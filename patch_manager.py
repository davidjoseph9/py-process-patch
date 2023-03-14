import enum
import jinja2
from keystone import *

from config.patch_config import *
from config.models import PatchModel, PatchPointer
from windows_apis import VirtualProtectEx


MAX_32_BIT_SIGNED_VALUE = 2147483647

logger = logging.getLogger()


class PatchError(Exception):
    def __init__(self, message, name="n/a"):
        # Call the base class constructor with the parameters it needs
        super().__init__(f"Patch '{name}' failed - {message}")


class PatchType(enum.Enum):
    write = 0
    hook = 1


class HookType(enum.Enum):
    jump = 0
    call = 1
    call_ptr = 2


class PatchManager:
    def __init__(self):
        self._template_env = jinja2.Environment(loader=jinja2.BaseLoader)
        self._template_env.globals.update(format_address=self.format_address)
        self._template_env.filters.update(hex=hex)
        self._config_path = None
        self._config = None
        self.ks_assembler = None
        self.kernel32 = ctypes.windll.kernel32

    @property
    def template_env(self):
        return self._template_env

    def load_config(self, path: str):
        self._config = PatchConfig(self, path)
        if not self._config.load_config():
            return False

    def toggle_patch(self, patch: PatchModel, enable: bool = True, template_vars: dict = None):
        """
        Toggle a patch

        Patch types:
        - hook
          Install/Uninstall the configured hook
        - write
          Write patch bytes or revert to original bytes

        :param pymem_instance: instance of pymem.Pymem (per process)
        :param patch: definition of the patch to apply
        :param template_vars: Variables to pass to the template for rendering
        :param template_name: Optional name of the template for logging if error occurs
        :return:
        """
        if enable:
            logger.debug(f"Toggle the patch '{patch.name}' ON")
            patch.address = int(patch.address)
            if patch.asm:
                if template_vars is None:
                    template_vars = dict()
                try:
                    asm_code = self.render_template(patch.asm, template_vars)
                except jinja2.exceptions.TemplateError as e:
                    raise PatchError(f"Cannot render the template\n{str(e)}", name=patch.name)

                asm_bytes = self.assemble(asm_code, patch.address)
                if asm_bytes is None:
                    raise PatchError("Cannot assemble the asm code", name=patch.name)
            else:
                asm_bytes = None

            patch_address = patch.address + patch.offset

            if patch.patch_type.name == PatchType.write.name:
                if patch.patch_bytes is not None:
                    patch.write_bytes = bytes.fromhex(patch.patch_bytes)
                elif asm_bytes is not None:
                    patch.write_bytes = asm_bytes
            elif patch.patch_type.name == PatchType.hook.name:
                patch.code_cave_address = patch.pymem_instance.allocate(len(asm_bytes))
                logger.debug(f"Allocating code cave at '{hex(patch.code_cave_address)}' size {len(asm_bytes)}")
                patch.pymem_instance.write_bytes(patch.code_cave_address, asm_bytes, len(asm_bytes))

                if patch.hook_type.name == HookType.jump.name:
                    if self._config.ks_mode == KS_MODE_64:
                        if abs(patch.address - patch.code_cave_address) > MAX_32_BIT_SIGNED_VALUE:
                            patch.write_bytes = self.get_absolute_jump_bytes(patch.code_cave_address)
                        else:
                            module_def = self._config._process_patch_group_map.get(patch.process).module_map.get(patch.module)
                            if module_def is None:
                                raise PatchError(f"Could not assemble the short jump for the patch '{patch.name}'")
                            patch.write_bytes = self.get_relative_jump_bytes(patch.code_cave_address, relative_address=patch_address)
                    else:
                        patch.write_bytes = self.get_relative_jump_bytes(patch.code_cave_address, relative_address=patch_address)
                elif patch.hook_type.name == HookType.call.name:
                    if self._config.ks_mode == KS_MODE_64:
                        if abs(patch.address - patch.code_cave_address) > MAX_32_BIT_SIGNED_VALUE:
                            patch.write_bytes = self.get_absolute_call_bytes(patch.code_cave_address)
                        else:
                            patch.write_bytes = self.get_relative_call_bytes(patch.code_cave_address)
                    else:
                        patch.write_bytes = self.get_relative_call_bytes(patch.code_cave_address)
                elif patch.hook_type.name == HookType.call_ptr.name:
                    patch.write_bytes = patch.code_cave_address.to_bytes(8, byteorder='little')

            if not patch.write_bytes:
                logger.error(f"Cannot proceed with the patch '{patch.name}'. no bytes to write")
                return

            logger.debug(f"Patching - type: {patch.patch_type.name} address: {hex(patch_address)}")
            old_protection = ctypes.pointer(wt.DWORD())
            success = VirtualProtectEx(patch.pymem_instance.process_handle, int(patch.address), len(patch.write_bytes),
                                            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE, old_protection)
            if not success:
                raise PatchError(f"Changing permissions the page of memory {hex(int(patch.address))} - "
                                 f"size: {len(patch.write_bytes)} failed. kernel32.GetLastError - "
                                 f"{self.kernel32.GetLastError()}", name=patch.name)

            patch.original_bytes = patch.pymem_instance.read_bytes(patch_address, len(patch.write_bytes))
            patch.pymem_instance.write_bytes(patch_address, bytes(patch.write_bytes), len(patch.write_bytes))
        else:
            logger.debug(f"Toggle the patch '{patch.name}' OFF")

            if not patch.original_bytes:
                raise PatchError("Cannot toggle patch off. The original bytes aren't available", name=patch.name)

            patch_address = patch.address + patch.offset
            patch.original_bytes = patch.pymem_instance.read_bytes(int(patch_address), len(patch.write_bytes))
            patch.pymem_instance.write_bytes(patch_address, bytes(patch.original_bytes), len(patch.original_bytes))
            if patch.patch_type.name == PatchType.hook.name and patch.code_cave_address is not None:
                patch.pymem_instance.free(patch.code_cave_address)

        return True

    def get_relative_jump_bytes(self, target_address: int, relative_address: int = None):
        return self.assemble(f"jmp {hex(target_address)}", address=relative_address)

    def get_relative_call_bytes(self, target_address: int, relative_address: int = None):
        return self.assemble(f"call {hex(target_address)}", address=relative_address)

    def get_absolute_jump_bytes(self, target_address: int, register: str = "rbx"):
        return self.assemble(f"push {register}; mov {register}, {hex(target_address)}; jmp {register}")

    def get_absolute_call_bytes(self, target_address: int, register: str = "rbx", relative_address: int = None):
        return self.assemble(f"push {register}; mov {register}, {hex(target_address)}; call {register}; pop {register};")

    def assemble(self, code: str, address: int = None):
        try:
            if address is not None:
                encoding, count = self.ks_assembler.asm(code, addr=address)
            else:
                encoding, count = self.ks_assembler.asm(code)
        except KsError as e:
            logger.error(f"Failed to assemble.\n{str(e)}")
            return None
        return bytes(encoding)

    def render_template(self, template: str, vars: dict):
        return self.template_env.from_string(template).render(**vars)

    def format_address(self, address: any, offset: any):
        if isinstance(address, str):
            address = int(address)
        elif isinstance(offset, str):
            offset = int(offset)
        return hex(address + offset)

    def load_pointer(self, process_patch_config: ProcessPatchConfig, pointer_config: PatchPointer):
        if pointer_config.module is not None:
            module_def = process_patch_config.module_map.get(pointer_config.module)
            if module_def is None:
                logger.error(f"Cannot create copy of the module '{pointer_config.module}'"
                             f" of the process '{process_patch_config.name}'. The module cannot be found in the loaded "
                             f"module map.")
                return None

            pointer_config.address = module_def.start_address

        if isinstance(pointer_config.address, str):
            pointer_config.address = int(pointer_config.address)

        if isinstance(pointer_config.offset, str):
            pointer_config.offset = int(pointer_config.offset)

        pointer_target_address = pointer_config.address + pointer_config.offset
        if self._config.ks_mode == KS_MODE_32:
            read_byte_count = 4
        else:
            read_byte_count = 8

        try:
            pointer_address_bytes = process_patch_config.pymem_instance.read_bytes(pointer_target_address, read_byte_count)
        except pymem.exception.MemoryReadError as e:
            logger.error(f"Failed to read from pointer address from '{hex(pointer_target_address)}'. {str(e)}")
            return None

        return int.from_bytes(pointer_address_bytes, "little")

