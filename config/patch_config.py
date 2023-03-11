import ctypes
import ctypes.wintypes as wt
import logging
import os.path

import yaml
import pymem

import windows_apis
from keystone import KS_ARCH_X86, KS_MODE_32, KS_MODE_64, keystone
import pydantic.errors
import win32process

from config.models import GroupPatchModel, ProcessPatchConfig, ProcessSetPatchConfig, PatchType, HookType, Module

KS_ARCHITECTURE_MAP = {
    'x86': KS_ARCH_X86,
}

KS_MODE_MAP = {
    '32': KS_MODE_32,
    '64': KS_MODE_64
}

LOG_FORMAT = "[%(filename)s:%(lineno)d] %(asctime)s - %(name)s - %(levelname)s - %(message)s"

logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
logger = logging.getLogger()


class PatchConfig:
    def __init__(self, patch_manager: any, config_path: str):
        self._patch_manager = patch_manager
        self._config_path = config_path
        self._process_patch_group_map = None
        self._ks_architecture = None
        self._ks_mode = None

    @property
    def ks_architecture(self):
        return self._ks_architecture

    @property
    def ks_mode(self):
        return self._ks_mode

    def load_config(self):
        logger.info(f"Loading the configuration file '{self._config_path}'")

        self._process_patch_group_map = dict()

        try:
            with open(self._config_path, 'r') as f:
                config = yaml.safe_load(f.read())
            process_set_patch_config = ProcessSetPatchConfig(**config)
        except (OSError, yaml.YAMLError, pydantic.errors.PydanticErrorMixin) as e:
            logger.error(f"Failed to load the configuration file.\n{str(e)}")
            return False

        ks_architecture = KS_ARCHITECTURE_MAP.get(process_set_patch_config.architecture)
        ks_mode = KS_MODE_MAP.get(process_set_patch_config.mode)

        if ks_architecture is None or ks_mode is None:
            logger.error("Invalid architecture and/or mode specified")
            return False

        self._ks_architecture = ks_architecture
        self._ks_mode = ks_mode

        self._patch_manager.ks_assembler = keystone.Ks(self._ks_architecture, self._ks_mode)

        for process in process_set_patch_config.processes:
            process_name = process.get('name', "n/a")
            if process_name is None:
                continue

            try:
                process_patch_config = ProcessPatchConfig(**process, copy_map=dict())
            except Exception as e:
                logger.error(f"Failed to validate the patch configuration for the process '{process_name}'.\n{str(e)}")
                return False

            if process_name not in self._process_patch_group_map:
                self._process_patch_group_map[process_name] = process_patch_config

            try:
                pymem_instance = pymem.Pymem(process_name=process_name)
            except pymem.exception.PymemError as e:
                logger.error(f"Failed to get handle of the process '{process_name}'. {str(e)}")
                return False

            process_patch_config.pymem_instance = pymem_instance
            self.load_process_modules(process_patch_config)
            # logger.debug(f"Modules loaded for the process '{process_name}.\n"
            #              f"{yaml.safe_dump(list(process_patch_config.module_map.keys()))}")

            self._load_copies(process_patch_config)

            for group_config in process_patch_config.patch_groups:
                self._load_patch_group(process_patch_config, group_config)

    def _load_copies(self, process_patch_config: ProcessPatchConfig):
        logger.debug(f"Loading copies for the process '{process_patch_config.name}'")
        for copy_mem in process_patch_config.copies:
            if not copy_mem.src_address and copy_mem.module:
                if not process_patch_config.modules:
                    logger.error(f"Cannot retrieve the base address of the module '{process_patch_config.name}' "
                                 f"of the process '{copy_mem.module}'.")
                    return False
                if copy_mem.size is None:
                    logger.error(f"Invalid copy '{copy_mem.name}'. Size of memory region must be specified. ")
                    return False
                module_def = process_patch_config.module_map.get(copy_mem.module)
                if module_def is None:
                    logger.error(f"Invalid copy '{copy_mem.name}'. Module '{copy_mem.module}' not found.")
                    return False
                copy_mem.src_address = module_def.start_address
            elif copy_mem.pointer:
                if copy_mem.pointer.module is not None:
                    module_def = process_patch_config.module_map.get(copy_mem.pointer.module)
                    if module_def is None:
                        logger.error(f"Cannot create copy of the module '{copy_mem.pointer.module}'"
                                     f" of the process '{process_patch_config.name}'. The module cannot be found in the loaded "
                                     f"module map.")
                        return False

                    copy_mem.pointer.address = module_def.start_address

                if isinstance(copy_mem.pointer.address, str):
                    copy_mem.pointer.address = int(copy_mem.pointer.address)

                if isinstance(copy_mem.pointer.offset, str):
                    copy_mem.pointer.offset = int(copy_mem.pointer.offset)

                pointer_target_address = copy_mem.pointer.address + copy_mem.pointer.offset
                if self.ks_mode == KS_MODE_32:
                    read_byte_count = 4
                else:
                    read_byte_count = 8

                try:
                    pointer_address_bytes = process_patch_config.pymem_instance.read_bytes(pointer_target_address,
                                                                                           read_byte_count)
                except pymem.exception.MemoryReadError as e:
                    logger.error(f"Failed to read from pointer address from '{hex(pointer_target_address)}'. {str(e)}")
                    continue

                copy_mem.src_address = int.from_bytes(pointer_address_bytes, "little")

            if isinstance(copy_mem.size, str):
                copy_mem.size = int(copy_mem.size)

            if isinstance(copy_mem.src_address, str):
                copy_mem.src_address = int(copy_mem.src_address)

            logger.debug(f"Pointer address for the patch '{copy_mem.name}' has been resolved {hex(copy_mem.src_address)}")
            logger.info(f"Creating copy, reading {hex(copy_mem.size)} bytes from {hex(copy_mem.src_address)}")

            try:
                logger.debug(f"Setting permissions on {hex(copy_mem.src_address)} size {hex(copy_mem.size)}")
                old_protection = ctypes.pointer(wt.DWORD())
                success = windows_apis.VirtualProtectEx(process_patch_config.pymem_instance.process_handle, int(copy_mem.src_address),
                                                        copy_mem.size, pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
                                                        old_protection)
                if not success:
                    logger.error(f"Changing permissions the page of memory {hex(copy_mem.src_address)} - size: "
                                 f"{hex(copy_mem.size)} failed. kernel32.GetLastError - {windows_apis.GetLastError()}")
                copy_mem.data = process_patch_config.pymem_instance.read_bytes(copy_mem.src_address, copy_mem.size)
            except pymem.exception.MemoryReadError as e:
                logger.error(f"Cannot create the copy '{copy_mem.name}'. Failed to read data from the address "
                             f"'{hex(pointer_target_address)}'. {str(e)}")
                continue

            copy_mem.address = process_patch_config.pymem_instance.allocate(copy_mem.size)

            process_patch_config.copy_map[copy_mem.name] = copy_mem

    def _load_patch_group(self, process_patch_config: ProcessPatchConfig, patch_group: GroupPatchModel):
        logger.info(f"Loading patch list for the group '{patch_group.name}'")

        for idx in range(len(patch_group.patches)):
            patch_config = patch_group.patches[idx]
            full_patch_name = f"{patch_group.name}/{patch_config.name}"
            patch_config.pymem_instance = process_patch_config.pymem_instance
            logger.info(f"Loading the patch '{full_patch_name}'")

            if patch_config.patch_type is None:
                logger.error(f"Invalid patch '{full_patch_name}'. No patch type specified, skipping...")
                continue
            try:
                patch_config.patch_type = PatchType[patch_config.patch_type]
            except ValueError:
                logger.error(f"Invalid patch type specified for the patch '{full_patch_name}'.")
                return

            if not patch_config.address:
                if not patch_config.offset and not patch_config.module and not patch_config.pointer:
                    logger.error(f"The patch '{patch_config.name}' is invalid. "
                                 f"Unrecognized patch type specified for the patch .")
                    return
                elif patch_config.module:
                    module_def = process_patch_config.module_map.get(patch_config.module)
                    if module_def is None:
                        logger.error(f"Cannot create copy of the module '{patch_config.module}'"
                                     f" of the process '{process_patch_config.name}'")
                        return False
                    patch_config.address = int(module_def.start_address) + int(patch_config.offset)

            if patch_config.patch_type.name == PatchType.hook.name:
                try:
                    patch_config.hook_type = HookType[patch_config.hook_type]
                except ValueError:
                    logger.error(f"Invalid hook type specified for the patch '{patch_config.name}'.")
                    return

            if patch_config.vars is None:
                patch_config.vars = dict()

            patch_config.vars['process_patch_group_map'] = self._process_patch_group_map[process_patch_config.name]
            patch_config.vars['copy_map'] = self._process_patch_group_map[process_patch_config.name].copy_map
            patch_config.vars['module_map'] = self._process_patch_group_map[process_patch_config.name].module_map
            patch_config.vars['module'] = patch_config.module

            if patch_config.enable:
                logger.info(f"Enabling the patch/hook '{patch_group.name}/{patch_config.name}'")

                self._patch_manager.toggle_patch(patch_config, template_vars=patch_config.vars)

    def get_process_module(self, process_patch_config: ProcessPatchConfig, module_name: str):
        if process_patch_config.modules:
            for module in process_patch_config.modules:
                if module.name == module_name:
                    return module

    def load_process_modules(self, process_patch_config: ProcessPatchConfig):
        process_patch_config.modules = []
        process_patch_config.module_map = dict()
        for module_handle in windows_apis.EnumProcessModules(process_patch_config.pymem_instance.process_handle):
            module_path = win32process.GetModuleFileNameEx(process_patch_config.pymem_instance.process_handle, module_handle)
            module_name = os.path.basename(module_path)
            module = Module(name=module_name, start_address=module_handle, path=module_path)
            process_patch_config.modules.append(module)
            process_patch_config.module_map[module_name] = module
