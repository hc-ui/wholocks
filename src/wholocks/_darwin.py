"""macOS backend: parse `lsof -F` machine-readable output.

macOS has no /proc, and its file-handle APIs are private, so we drive the
preinstalled `lsof` (present on every macOS at /usr/sbin/lsof) with its
field-output mode, which is designed for programs to parse.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from .core import BackendUnavailable, Holder, ScanResult, make_matcher

_FD_ACCESS = {
    "cwd": "cwd",
    "twd": "cwd",
    "txt": "exe",
    "rtd": "root",
    "mem": "mmap",
    "DEL": "mmap (deleted)",
}


def _lsof_path():
    for candidate in ("lsof", "/usr/sbin/lsof", "/usr/bin/lsof"):
        found = shutil.which(candidate) if os.sep not in candidate else (
            candidate if os.path.exists(candidate) else None
        )
        if found:
            return found
    return None


def parse_lsof_field_output(text, match=None):
    """Parse `lsof -F pcufn` output into Holder objects.

    Records look like::

        p123
        cSome Command
        u501
        fcwd
        n/Users/me/held-dir
        f3
        n/Users/me/held-file.txt
    """
    holders = []
    current = None
    current_fd = None

    def flush():
        nonlocal current
        if current is not None and current.access:
            holders.append(current)
        current = None

    for line in text.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            flush()
            try:
                pid = int(value)
            except ValueError:
                current = None
                continue
            current = Holder(pid=pid)
            current_fd = None
        elif current is None:
            continue
        elif tag == "c":
            current.name = value
        elif tag == "u":
            current.user = value
        elif tag == "f":
            current_fd = value
        elif tag == "n":
            path = value
            if match is not None and not match(path):
                continue
            label = _FD_ACCESS.get(current_fd or "")
            if label is None:
                digits = (current_fd or "").rstrip("rwu ")
                label = "fd" if digits.isdigit() else (current_fd or "other")
            if label not in current.access:
                current.access.append(label)
            if path not in current.paths:
                current.paths.append(path)
    flush()
    return holders


def _resolve_users(holders):
    import pwd

    for h in holders:
        if h.user is not None and h.user.isdigit():
            try:
                h.user = pwd.getpwuid(int(h.user)).pw_name
            except (KeyError, ValueError):
                pass


def _fill_cmdlines(holders):
    if not holders:
        return
    pids = ",".join(str(h.pid) for h in holders)
    try:
        out = subprocess.run(
            ["ps", "-o", "pid=,args=", "-p", pids],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return
    table = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            table[int(parts[0])] = parts[1]
    for h in holders:
        h.cmdline = table.get(h.pid, h.cmdline)
        if h.cmdline and not h.exe:
            first = h.cmdline.split()[0]
            if first.startswith("/"):
                h.exe = first


def scan(files, dirs, recursive=False, max_files=10000):
    lsof = _lsof_path()
    if lsof is None:
        raise BackendUnavailable(
            "lsof not found - install it or run from a standard macOS shell"
        )
    # align with the kernel's view: /tmp and /var are symlinks into /private
    files = [os.path.realpath(f) for f in files]
    dirs = [os.path.realpath(d) for d in dirs]
    cmd = [lsof, "-n", "-P", "-F", "pcufn"]
    for d in dirs:
        cmd += ["+D" if recursive else "+d", d]
    if files:
        cmd += ["--"] + list(files)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise BackendUnavailable(
            "lsof timed out; for large folders try without --recursive"
        )
    except OSError as e:
        raise BackendUnavailable("cannot run lsof: %s" % e)

    match = make_matcher(files, dirs, recursive)
    holders = [h for h in parse_lsof_field_output(proc.stdout, match) if h.pid != os.getpid()]
    _resolve_users(holders)
    _fill_cmdlines(holders)

    warnings = []
    if not holders and hasattr(os, "geteuid") and os.geteuid() != 0:
        warnings.append(
            "processes of other users may be invisible without sudo"
        )
    return ScanResult(
        targets=[],
        holders=holders,
        scanned_files=len(files) + len(dirs),
        warnings=warnings,
        backend="darwin-lsof",
    )
