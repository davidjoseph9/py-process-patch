from _winapi import INVALID_HANDLE_VALUE
import win32process
import win32api
import ctypes
from ctypes import windll, WinError
import ctypes.wintypes as wt

VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [
    wt.HANDLE, wt.LPVOID, ctypes.c_size_t,
    wt.DWORD, wt.LPVOID
]
VirtualProtectEx.restype = wt.BOOL
OpenProcess = win32api.OpenProcess
EnumProcessModules = win32process.EnumProcessModules
GetLastError = windll.kernel32.GetLastError


TH32CS_SNAPALL = 0x00000000
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004


def CreateToolhelp32Snapshot(dwFlags=TH32CS_SNAPALL, th32ProcessID=0):
    """
    Create a snapshot of a process
    The snapshot will contain the information specified by the dwFlags
    This collects info on the heaps, modules, and more...

    # https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    """
    hSnapshot = windll.kernel32.CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if hSnapshot == INVALID_HANDLE_VALUE:
        raise WinError()
    return hSnapshot
