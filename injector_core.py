"""
DLL Injector Core — Windows API injection via ctypes.
"""

import ctypes
import ctypes.wintypes as wintypes
import os
from dataclasses import dataclass
from typing import Optional

import psutil

# ── Windows API Constants ──────────────────────────────────────────────
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

# ── Kernel32 Setup ─────────────────────────────────────────────────────
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = wintypes.LPVOID
VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.restype = wintypes.HANDLE
CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.restype = wintypes.BOOL
VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = wintypes.BOOL
CloseHandle.argtypes = [wintypes.HANDLE]

WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.restype = wintypes.DWORD
WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.restype = wintypes.HMODULE
GetModuleHandleA.argtypes = [wintypes.LPCSTR]

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.restype = wintypes.LPVOID
GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]


# ── Data Structures ───────────────────────────────────────────────────

@dataclass
class ProcessInfo:
    pid: int
    name: str
    memory_mb: float
    username: Optional[str] = None


@dataclass
class InjectionResult:
    success: bool
    message: str
    thread_id: Optional[int] = None
    error_code: Optional[int] = None


# ── Process Listing ───────────────────────────────────────────────────

def list_processes(filter_text: str = "") -> list[ProcessInfo]:
    """List running processes, optionally filtered by name."""
    processes = []
    for proc in psutil.process_iter(["pid", "name", "memory_info", "username"]):
        try:
            info = proc.info
            name = info["name"] or ""
            if filter_text and filter_text.lower() not in name.lower():
                continue
            mem = info["memory_info"]
            memory_mb = round(mem.rss / 1024 / 1024, 1) if mem else 0.0
            processes.append(ProcessInfo(
                pid=info["pid"],
                name=name,
                memory_mb=memory_mb,
                username=info.get("username"),
            ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    processes.sort(key=lambda p: p.name.lower())
    return processes


def get_process_by_pid(pid: int) -> Optional[ProcessInfo]:
    """Get process info by PID."""
    try:
        proc = psutil.Process(pid)
        mem = proc.memory_info()
        return ProcessInfo(
            pid=proc.pid,
            name=proc.name(),
            memory_mb=round(mem.rss / 1024 / 1024, 1),
            username=proc.username(),
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


# ── DLL Validation ────────────────────────────────────────────────────

def validate_dll(path: str) -> tuple[bool, str]:
    """Validate that the file exists and looks like a PE DLL."""
    if not os.path.isfile(path):
        return False, "File does not exist"

    if not path.lower().endswith(".dll"):
        return False, "File is not a .dll"

    try:
        with open(path, "rb") as f:
            magic = f.read(2)
            if magic != b"MZ":
                return False, "Invalid PE header (not MZ)"
    except PermissionError:
        return False, "Permission denied reading file"
    except Exception as e:
        return False, f"Error reading file: {e}"

    return True, "Valid DLL"


# ── DLL Injection ─────────────────────────────────────────────────────

def inject_dll(pid: int, dll_path: str) -> InjectionResult:
    """
    Inject a DLL into a target process using LoadLibraryA.

    Steps:
      1. OpenProcess
      2. VirtualAllocEx — allocate memory for DLL path
      3. WriteProcessMemory — write DLL path string
      4. GetProcAddress(kernel32, LoadLibraryA)
      5. CreateRemoteThread — call LoadLibraryA
      6. Cleanup
    """
    dll_path_abs = os.path.abspath(dll_path)

    # Validate DLL first
    valid, msg = validate_dll(dll_path_abs)
    if not valid:
        return InjectionResult(success=False, message=f"DLL validation failed: {msg}")

    dll_path_bytes = dll_path_abs.encode("ascii") + b"\x00"
    h_process = None
    alloc_addr = None

    try:
        # 1. Open the target process
        h_process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            err = ctypes.get_last_error()
            return InjectionResult(
                success=False,
                message=f"OpenProcess failed (is app running as admin?)",
                error_code=err,
            )

        # 2. Allocate memory in target process
        alloc_addr = VirtualAllocEx(
            h_process, None, len(dll_path_bytes),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        )
        if not alloc_addr:
            err = ctypes.get_last_error()
            return InjectionResult(
                success=False,
                message=f"VirtualAllocEx failed",
                error_code=err,
            )

        # 3. Write DLL path to allocated memory
        bytes_written = ctypes.c_size_t(0)
        success = WriteProcessMemory(
            h_process, alloc_addr, dll_path_bytes,
            len(dll_path_bytes), ctypes.byref(bytes_written),
        )
        if not success:
            err = ctypes.get_last_error()
            return InjectionResult(
                success=False,
                message=f"WriteProcessMemory failed",
                error_code=err,
            )

        # 4. Get address of LoadLibraryA
        h_kernel32 = GetModuleHandleA(b"kernel32.dll")
        if not h_kernel32:
            return InjectionResult(
                success=False,
                message="GetModuleHandleA(kernel32) failed",
            )

        load_library_addr = GetProcAddress(h_kernel32, b"LoadLibraryA")
        if not load_library_addr:
            return InjectionResult(
                success=False,
                message="GetProcAddress(LoadLibraryA) failed",
            )

        # 5. Create remote thread calling LoadLibraryA(dll_path)
        thread_id = wintypes.DWORD(0)
        h_thread = CreateRemoteThread(
            h_process, None, 0, load_library_addr, alloc_addr,
            0, ctypes.byref(thread_id),
        )
        if not h_thread:
            err = ctypes.get_last_error()
            return InjectionResult(
                success=False,
                message=f"CreateRemoteThread failed",
                error_code=err,
            )

        # Wait for the thread to finish (timeout 5 seconds)
        WaitForSingleObject(h_thread, 5000)
        CloseHandle(h_thread)

        return InjectionResult(
            success=True,
            message=f"DLL injected successfully into PID {pid}",
            thread_id=thread_id.value,
        )

    except Exception as e:
        return InjectionResult(
            success=False,
            message=f"Unexpected error: {e}",
        )

    finally:
        # Cleanup
        if alloc_addr and h_process:
            VirtualFreeEx(h_process, alloc_addr, 0, MEM_RELEASE)
        if h_process:
            CloseHandle(h_process)
