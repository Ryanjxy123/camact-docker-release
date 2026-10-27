"""Task-scoped hard termination and mock-service parent lifetime binding."""
from __future__ import annotations

import os
import signal
import subprocess
import threading
import time


def terminate_process_tree(process, *, owned_process_group: bool = False) -> None:
    # Only callers that created start_new_session may kill a POSIX group.
    # Do this even if the parent already exited: descendants can still hold
    # stdout/stderr open and prevent communicate() from completing.
    if os.name != "nt" and owned_process_group:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       creationflags=subprocess.CREATE_NO_WINDOW, check=False)
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)


def bind_service_to_parent(parent_pid: int) -> None:
    """A killed runner cannot run finally; its private service must exit itself.

    On Windows hold a process handle (immune to PID reuse); on POSIX reparenting
    identifies parent death. Only this service is terminated, never another task.
    """
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, parent_pid)  # SYNCHRONIZE
        if not handle:
            raise RuntimeError("service parent is no longer available")

        def watch():
            result = kernel.WaitForSingleObject(handle, 0xFFFFFFFF)
            kernel.CloseHandle(handle)
            os._exit(0 if result == 0 else 1)
    else:
        def watch():
            while os.getppid() == parent_pid:
                time.sleep(0.1)
            os._exit(0)
    threading.Thread(target=watch, name="service-parent-lifetime", daemon=True).start()
