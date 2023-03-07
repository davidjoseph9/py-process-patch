import enum
from typing import List, Optional

import pydantic
import pymem


class PatchType(enum.Enum):
    write = 0
    hook = 1


class HookType(enum.Enum):
    jump = 0
    call = 1
    call_ptr = 2


class PatchModel(pydantic.BaseModel):
    name: str
    patch_type: str
    enable: Optional[bool] = False
    hook_type: str
    vars: Optional[dict] = None
    address: str
    bytes: Optional[str] = None
    asm: Optional[str] = None
    code_cave_address: Optional[int] = None


class GroupCheatModel(pydantic.BaseModel):
    name: str
    patches: List[PatchModel]


class ProcessCopyRegionModel(pydantic.BaseModel):
    name: str
    src_address: Optional[str]  # source address of memory region to copy
    dst_address: Optional[str] = None  # address to the copy of the memory in allocated in the process
    size: Optional[str]
    data: Optional[List[bytes]] = None


class ProcessCheatConfig(pydantic.BaseModel):
    name: str
    patch_groups: List[GroupCheatModel]
    copies: List[ProcessCopyRegionModel]
    copy_map: Optional[dict]
    pymem_instance: Optional[pymem.Pymem] = None

    class Config:
        arbitrary_types_allowed = True


class ProcessSetCheatConfig(pydantic.BaseModel):
    name: str
    architecture: str
    mode: str
    processes: List[dict]
