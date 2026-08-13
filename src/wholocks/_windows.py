"""Windows backend: the Restart Manager API (rstrtmgr.dll).

This is the same API Windows itself uses for its "The file is open in
another program" dialog and during Windows Update. We register the target
files in a Restart Manager session and ask which processes are affected.
No subprocess, no external tools, works as a normal user.
"""

from __future__ import annotations

import ctypes
import datetime as _dt
import os
from ctypes import wintypes

from .core import BackendUnavailable, Holder, ScanResult

CCH_RM_SESSION_KEY = 32
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
ERROR_MORE_DATA = 234
_REGISTER_CHUNK = 512

_APP_TYPES = {
    0: "unknown",
    1: "main_window",
    2: "other_window",
    3: "service",
    4: "explorer",
    5: "console",
    1000: "critical",
}

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000
STILL_ACTIVE = 259
WAIT_OBJECT_0 = 0


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = (
        ("dwProcessId", wintypes.DWORD),
        ("ProcessStartTime", wintypes.FILETIME),
    )


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = (
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", ctypes.c_int),
        ("AppStatus", wintypes.ULONG),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    )


_rm = None
_k32 = None


def _load():
    global _rm, _k32
    if _rm is not None:
        return
    try:
        rm = ctypes.WinDLL("rstrtmgr", use_last_error=True)
    except OSError as e:  # pragma: no cover - rstrtmgr ships with Vista+
        raise BackendUnavailable("cannot load rstrtmgr.dll: %s" % e)
    rm.RmStartSession.argtypes = (
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.WCHAR),
    )
    rm.RmStartSession.restype = wintypes.DWORD
    rm.RmRegisterResources.argtypes = (
        wintypes.DWORD,
        wintypes.UINT,
        ctypes.POINTER(wintypes.LPCWSTR),
        wintypes.UINT,
        ctypes.c_void_p,
        wintypes.UINT,
        ctypes.c_void_p,
    )
    rm.RmRegisterResources.restype = wintypes.DWORD
    rm.RmGetList.argtypes = (
        wintypes.DWORD,
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(RM_PROCESS_INFO),
        ctypes.POINTER(wintypes.DWORD),
    )
    rm.RmGetList.restype = wintypes.DWORD
    rm.RmEndSession.argtypes = (wintypes.DWORD,)
    rm.RmEndSession.restype = wintypes.DWORD

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    k32.CloseHandle.restype = wintypes.BOOL
    k32.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    k32.TerminateProcess.restype = wintypes.BOOL
    k32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.GetExitCodeProcess.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    )
    k32.GetExitCodeProcess.restype = wintypes.BOOL

    _rm = rm
    _k32 = k32


def _expand_targets(files, dirs, recursive, max_files):
    """Restart Manager takes file paths, so directory targets are expanded."""
    paths = list(files)
    warnings = []
    truncated = False
    for d in dirs:
        if recursive:
            for root, _subdirs, names in os.walk(d):
                for n in names:
                    if len(paths) >= max_files:
                        truncated = True
                        break
                    paths.append(os.path.join(root, n))
                if truncated:
                    break
        else:
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        if len(paths) >= max_files:
                            truncated = True
                            break
                        if entry.is_file(follow_symlinks=False):
                            paths.append(entry.path)
            except OSError as e:
                warnings.append("cannot list %s: %s" % (d, e))
        if truncated:
            break
    if truncated:
        warnings.append(
            "directory contains more than %d files; only the first %d were "
            "checked (raise with --max-files)" % (max_files, max_files)
        )
    return paths, warnings


def _rm_query(paths):
    """Ask the Restart Manager which processes hold any of *paths*."""
    _load()
    handle = wintypes.DWORD()
    key = (wintypes.WCHAR * (CCH_RM_SESSION_KEY + 1))()
    res = _rm.RmStartSession(ctypes.byref(handle), 0, key)
    if res:
        raise BackendUnavailable("RmStartSession failed (error %d)" % res)
    try:
        for i in range(0, len(paths), _REGISTER_CHUNK):
            chunk = paths[i : i + _REGISTER_CHUNK]
            arr = (wintypes.LPCWSTR * len(chunk))(*chunk)
            res = _rm.RmRegisterResources(
                handle.value, len(chunk), arr, 0, None, 0, None
            )
            if res:
                raise BackendUnavailable(
                    "RmRegisterResources failed (error %d)" % res
                )
        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        res = _rm.RmGetList(
            handle.value,
            ctypes.byref(needed),
            ctypes.byref(count),
            None,
            ctypes.byref(reasons),
        )
        infos = []
        while res == ERROR_MORE_DATA:
            n = needed.value
            if n == 0:
                break
            buf = (RM_PROCESS_INFO * n)()
            count = wintypes.UINT(n)
            res = _rm.RmGetList(
                handle.value,
                ctypes.byref(needed),
                ctypes.byref(count),
                buf,
                ctypes.byref(reasons),
            )
            if res == 0:
                infos = list(buf)[: count.value]
        if res:
            raise BackendUnavailable("RmGetList failed (error %d)" % res)
        return infos
    finally:
        _rm.RmEndSession(handle.value)


def _exe_path(pid):
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        _k32.CloseHandle(h)


def _filetime_to_iso(ft):
    ticks = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    if not ticks:
        return None
    try:
        unix = ticks / 10_000_000 - 11_644_473_600
        return _dt.datetime.fromtimestamp(unix).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def scan(files, dirs, recursive=False, max_files=10000):
    paths, warnings = _expand_targets(files, dirs, recursive, max_files)
    holders = []
    if paths:
        for info in _rm_query(paths):
            pid = int(info.Process.dwProcessId)
            exe = _exe_path(pid)
            name = os.path.basename(exe) if exe else (info.strAppName or "")
            app_type = _APP_TYPES.get(info.ApplicationType, "unknown")
            desc = info.strAppName or None
            if app_type == "service" and info.strServiceShortName:
                desc = "service: %s" % info.strServiceShortName
            holders.append(
                Holder(
                    pid=pid,
                    name=name,
                    description=desc,
                    exe=exe,
                    access=["handle"],
                    app_type=app_type,
                    started=_filetime_to_iso(info.Process.ProcessStartTime),
                )
            )
    if dirs and not holders:
        warnings.append(
            "no file handles found. If you still cannot delete the folder, "
            "a console window may have its current directory inside it "
            "(cd elsewhere), or check hidden files with --recursive."
        )
    return ScanResult(
        targets=[],
        holders=holders,
        scanned_files=len(paths),
        warnings=warnings,
        backend="windows-restart-manager",
    )


def kill(pid, grace=5.0):
    """Forcefully terminate *pid*. Returns (ok, message)."""
    _load()
    h = _k32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
    if not h:
        err = ctypes.get_last_error()
        if not _pid_exists(pid):
            return True, "already gone"
        return False, (
            "cannot open process (error %d - try an elevated terminal)" % err
        )
    try:
        if not _k32.TerminateProcess(h, 1):
            err = ctypes.get_last_error()
            return False, "TerminateProcess failed (error %d)" % err
        waited = _k32.WaitForSingleObject(h, int(grace * 1000))
        if waited == WAIT_OBJECT_0:
            return True, "terminated"
        return True, "termination requested (still shutting down)"
    finally:
        _k32.CloseHandle(h)


def _pid_exists(pid):
    _load()
    h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = wintypes.DWORD()
        if _k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return code.value == STILL_ACTIVE
        return True
    finally:
        _k32.CloseHandle(h)
