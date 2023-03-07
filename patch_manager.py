import ctypes
import ctypes.wintypes as wt
import enum

import jinja2
from keystone import *

from config.patch_config import *
from config.models import PatchModel

logger = logging.getLogger()


class HookType(enum.Enum):
    jump = 0
    call = 1
    call_ptr = 2


class PatchManager:
    def __init__(self):
        self._template_env = jinja2.Environment(loader=jinja2.BaseLoader)
        self._config_path = None
        self._config = None
        self.ks_assembler = None
        self.kernel32 = ctypes.windll.kernel32

        self.VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
        self.VirtualProtectEx.argtypes = [
            wt.HANDLE, wt.LPVOID, ctypes.c_size_t,
            wt.DWORD, wt.LPVOID
        ]
        self.VirtualProtectEx.restype = wt.BOOL

    @property
    def template_env(self):
        return self._template_env

    def load_config(self, path: str):
        self._config = PatchConfig(self, path)
        if not self._config.load_config():
            return False

    def hook(self, pymem_instance: pymem.Pymem, hook_type: HookType, patch: PatchModel,
             template_vars: dict = None, template_name="n/a"):

        if template_vars is None:
            template_vars = dict()

        asm_code = self.render_template(template_name, patch.asm, template_vars)
        asm_bytes = self.assemble(asm_code)
        if asm_bytes is None:
            return False

        patch.code_cave_address = pymem_instance.allocate(len(asm_bytes))
        pymem_instance.write_bytes(patch.code_cave_address, asm_bytes, len(asm_bytes))
        if hook_type.name == HookType.jump.name:
            hook_bytes = self.get_jump_bytes(patch.code_cave_address)
        elif hook_type.name == HookType.call.name:
            hook_bytes = self.get_call_bytes(patch.code_cave_address)
        elif hook_type.name == HookType.call_ptr.name:
            hook_bytes = patch.code_cave_address.to_bytes(8, byteorder='little')
        else:
            return False
        logger.debug(f"Hooking - type: {hook_type} address: {hex(int(patch.address))}")
        old_protection = ctypes.pointer(wt.DWORD())
        success = self.VirtualProtectEx(pymem_instance.process_handle, int(patch.address), len(hook_bytes),
                                        pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE, old_protection)
        if not success:
            logger.error(f"Changing permissions the page of memory {hex(int(patch.address))} - "
                         f"size: {len(hook_bytes)} failed. kernel32.GetLastError - {self.kernel32.GetLastError()}")
            return False
        pymem_instance.write_bytes(int(patch.address), bytes(hook_bytes), len(hook_bytes))
        return True

    def get_jump_bytes(self, target_address: any, register: str = "rbx"):
        return self.assemble(f"push {register}; mov {register}, {hex(target_address)}; jmp {register}")

    def get_call_bytes(self, target_address: any, register: str = "rax"):
        return self.assemble(f"push {register}; mov {register}, {hex(target_address)}; call {register}; pop {register};")

    def assemble(self, code: str):
        try:
            encoding, count = self.ks_assembler.asm(code)
        except KsError as e:
            logger.error(f"Failed to assemble.\n{str(e)}")
            return None
        return bytes(encoding)

    def render_template(self, template_name: str, template: str, vars: dict):
        template = self.template_env.from_string(template)
        try:
            rendered_content = template.render(**vars)
        except jinja2.exceptions.TemplateError as e:
            logger.error(f"Failed to render the template for the '{template_name}'")
            logger.error(str(e))
            return None
        return rendered_content
