import logging

import keystone
import pydantic.errors

import yaml
import pymem
from keystone import KS_ARCH_X86, KS_ARCH_ARM, KS_ARCH_ARM64, KS_MODE_16, KS_MODE_32, KS_MODE_64

from config.models import GroupCheatModel, ProcessCheatConfig, ProcessSetCheatConfig, PatchType, HookType

KS_ARCHITECTURE_MAP = {
    'x86': KS_ARCH_X86,
    'arm': KS_ARCH_ARM,
    'arm64': KS_ARCH_ARM64
}

KS_MODE_MAP = {
    '16': KS_MODE_16,
    '32': KS_MODE_32,
    '64': KS_MODE_64
}

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
logger = logging.getLogger()


class PatchConfig:
    def __init__(self, cheat_manager: any, config_path: str):
        self._cheat_manager = cheat_manager
        self._config_path = config_path
        self._process_cheat_group_map = None
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

        self._process_cheat_group_map = dict()

        try:
            with open(self._config_path, 'r') as f:
                config = yaml.safe_load(f.read())
            process_set_cheat_config = ProcessSetCheatConfig(**config)
        except (OSError, yaml.YAMLError, pydantic.errors.Any) as e:
            logger.error(f"Failed to load the configuration file.\n{str(e)}")
            return False

        ks_architecture = KS_ARCHITECTURE_MAP.get(process_set_cheat_config.architecture)
        ks_mode = KS_MODE_MAP.get(process_set_cheat_config.mode)

        if ks_architecture is None or ks_mode is None:
            logger.error("Invalid architecture and/or mode specified")
            return False

        self._ks_architecture = ks_architecture
        self._ks_mode = ks_mode

        self._cheat_manager.ks_assembler = keystone.Ks(self._ks_architecture, self._ks_mode)

        for process in process_set_cheat_config.processes:
            process_name = process.get('name', "n/a")
            if process_name is None:
                continue

            try:
                process_cheat_config = ProcessCheatConfig(**process, copy_map=dict())
            except Exception as e:
                logger.error(f"Failed to validate the patch configuration for the process '{process_name}'.\n{str(e)}")
                return False

            if process_name not in self._process_cheat_group_map:
                self._process_cheat_group_map[process_name] = process_cheat_config

            try:
                pymem_instance = pymem.Pymem(process_name=process_name)
            except pymem.exception.PymemError as e:
                logger.error(f"Failed to get handle of the process '{process_name}'. {str(e)}")
                return False

            process_cheat_config.pymem_instance = pymem_instance

            for copy_region in process_cheat_config.copies:
                copy_region.size = int(copy_region.size)
                copy_region.data = pymem_instance.read_bytes(int(copy_region.src_address), copy_region.size)
                copy_region.dst_address = pymem_instance.allocate(copy_region.size)

                process_cheat_config.copy_map[copy_region.name] = copy_region

            for group_config in process_cheat_config.patch_groups:
                self._load_patch_group(process_name, group_config, pymem_instance)

    def _load_patch_group(self, process_name: str, patch_group: GroupCheatModel, pymem_instance: pymem.Pymem):
        logger.info(f"Loading patch list for the group '{patch_group.name}'")

        for idx in range(len(patch_group.patches)):
            patch_config = patch_group.patches[idx]
            logger.info(f"Loading the patch '{patch_group.name}/{patch_config.name}'")

            if patch_config.patch_type == PatchType.hook.name:
                try:
                    hook_type = HookType[patch_config.hook_type]
                except ValueError:
                    logger.error(f"Invalid hook type specified for the patch '{patch_config.name}'.")
                    return

                if patch_config.vars is None:
                    patch_config.vars = dict()

                patch_config.vars['copy_map'] = self._process_cheat_group_map[process_name].copy_map
                if patch_config.enable:
                    logger.info(f"Enabling the patch/hook '{patch_group.name}/{patch_config.name}'")
                    self._cheat_manager.hook(pymem_instance, hook_type, patch_config, template_vars=patch_config.vars)

