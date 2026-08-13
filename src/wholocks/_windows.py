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

FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FileProcessIdsUsingFileInformation = 47
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = (
        ("Status", ctypes.c_void_p),
        ("Information", ctypes.c_void_p),
    )


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
_nt = None


def _load():
    global _rm, _k32, _nt
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
    k32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    k32.CreateFileW.restype = wintypes.HANDLE

    nt = ctypes.WinDLL("ntdll", use_last_error=True)
    nt.NtQueryInformationFile.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_int,
    )
    nt.NtQueryInformationFile.restype = ctypes.c_uint32

    _rm = rm
    _k32 = k32
    _nt = nt


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


def _pids_using_path(path):
    """Kernel-level answer: which PIDs hold an open handle to *path*?

    Uses NtQueryInformationFile(FileProcessIdsUsingFileInformation), which -
    unlike the Restart Manager - also works for directories. A console
    window whose current directory is inside a folder holds a directory
    handle, so this catches the classic "cmd is cd'd into the folder" case.
    """
    import struct as _struct

    _load()
    invalid = ctypes.c_void_p(-1).value
    h = _k32.CreateFileW(
        path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_ALL,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if not h or h == invalid:
        return []
    try:
        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        size = ptr_size * 512
        for _ in range(8):
            buf = ctypes.create_string_buffer(size)
            iosb = IO_STATUS_BLOCK()
            status = _nt.NtQueryInformationFile(
                h,
                ctypes.byref(iosb),
                buf,
                size,
                FileProcessIdsUsingFileInformation,
            )
            if status == STATUS_INFO_LENGTH_MISMATCH:
                size *= 4
                continue
            if status != 0:
                return []
            count = _struct.unpack_from("<L", buf, 0)[0]
            fmt = "<Q" if ptr_size == 8 else "<L"
            pids = []
            for i in range(count):
                offset = ptr_size + i * ptr_size
                if offset + ptr_size > size:
                    break
                pids.append(int(_struct.unpack_from(fmt, buf, offset)[0]))
            return pids
        return []
    finally:
        _k32.CloseHandle(h)


def _subdirs(d, recursive, cap):
    out = []
    try:
        if recursive:
            for root, subdir_names, _names in os.walk(d):
                for s in subdir_names:
                    out.append(os.path.join(root, s))
                    if len(out) >= cap:
                        return out
        else:
            with os.scandir(d) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=False):
                        out.append(entry.path)
                        if len(out) >= cap:
                            break
    except OSError:
        pass
    return out


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
    holder_map = {}

    # 1) Restart Manager over the file list: rich info (app name, type,
    #    start time), including processes that memory-map the files.
    if paths:
        try:
            infos = _rm_query(paths)
        except BackendUnavailable as e:
            warnings.append(
                "Restart Manager query failed (%s); falling back to the "
                "direct handle query, results may be less complete" % e
            )
            infos = []
        for info in infos:
            pid = int(info.Process.dwProcessId)
            exe = _exe_path(pid)
            name = os.path.basename(exe) if exe else (info.strAppName or "")
            app_type = _APP_TYPES.get(info.ApplicationType, "unknown")
            desc = info.strAppName or None
            if app_type == "service" and info.strServiceShortName:
                desc = "service: %s" % info.strServiceShortName
            holder_map[pid] = Holder(
                pid=pid,
                name=name,
                description=desc,
                exe=exe,
                access=["handle"],
                app_type=app_type,
                started=_filetime_to_iso(info.Process.ProcessStartTime),
            )

    # 2) Kernel-level handle query on the explicit targets and on the
    #    directories themselves. Unlike the Restart Manager this also sees
    #    directory handles - Explorer windows and shells cd'd into a folder.
    probe_targets = list(files) + list(dirs)
    for d in dirs:
        probe_targets.extend(_subdirs(d, recursive, cap=max_files))
    my_pid = os.getpid()
    probed = 0
    for target in probe_targets:
        if probed >= max_files:
            break
        probed += 1
        for pid in _pids_using_path(target):
            if pid == my_pid:
                continue
            h = holder_map.get(pid)
            if h is None:
                exe = _exe_path(pid)
                if exe:
                    name = os.path.basename(exe)
                elif pid == 4:
                    name = "System"
                else:
                    name = ""
                h = Holder(
                    pid=pid,
                    name=name,
                    exe=exe,
                    access=["handle"],
                )
                holder_map[pid] = h
            if target not in h.paths:
                h.paths.append(target)

    holders = list(holder_map.values())
    if dirs and not holders and not recursive:
        warnings.append(
            "nothing holds the folder or its immediate contents. If it "
            "still cannot be deleted, something may hold a deeper item - "
            "try --recursive."
        )
    return ScanResult(
        targets=[],
        holders=holders,
        scanned_files=len(paths),
        warnings=warnings,
        backend="windows-restart-manager+ntquery",
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
