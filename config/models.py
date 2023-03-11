import enum
from typing import List, Optional, Any

import pydantic
import pymem
from pymem.ressources.structure import MODULEINFO


class PatchType(enum.Enum):
    write = 0
    hook = 1


class HookType(enum.Enum):
    jump = 0
    call = 1
    call_ptr = 2


class PatchModel(pydantic.BaseModel):
    name: str

    enable: Optional[bool] = False          # enable at start
    enabled: Optional[bool] = False         # current status of enable

    patch_bytes: Optional[str] = None
    write_bytes: Optional[bytes] = None     # actual bytes to write parsed from write_bytes

    pymem_instance: Optional[pymem.Pymem] = None

    patch_type: Any
    hook_type: Optional[Any] = None

    vars: Optional[dict] = None

    asm: Optional[str] = None
    code_cave_address: Optional[int] = None

    address: Optional[str] = None
    offset: Optional[str] = None
    module: Optional[str] = None

    bytes: Optional[str] = None
    original_bytes: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


class GroupPatchModel(pydantic.BaseModel):
    name: str
    patches: List[PatchModel]
    pymem_instance: Optional[pymem.Pymem] = None

    class Config:
        arbitrary_types_allowed = True


class PatchPointer(pydantic.BaseModel):
    module: str
    offset: Any
    address: Optional[Any]


class CopyMemoryModel(pydantic.BaseModel):
    name: str
    src_address: Optional[str] = None # source address of memory region to copy
    address: Optional[str] = None  # address to the copy of the memory in allocated in the process
    pointer: Optional[PatchPointer]
    size: Optional[str]
    module: Optional[str]
    data: Optional[List[bytes]] = None
    module_info: Optional[MODULEINFO] = None

    class Config:
        arbitrary_types_allowed = True


class ProcessPatchConfig(pydantic.BaseModel):
    name: str
    patch_groups: List[GroupPatchModel]
    copies: List[CopyMemoryModel]
    copy_map: Optional[dict]
    pymem_instance: Optional[pymem.Pymem] = None
    modules: List[Any] = None
    module_map: Optional[dict] = None
    pointer: Optional[PatchPointer]

    class Config:
        arbitrary_types_allowed = True


class ProcessSetPatchConfig(pydantic.BaseModel):
    name: str
    architecture: str
    mode: str
    processes: List[dict]


class Module(pydantic.BaseModel):
    name: str
    path: str
    start_address: Any
    end_address: Optional[Any]