"""Linux backend: scan /proc directly. No subprocess, no lsof needed.

For every process we look at its open file descriptors (fd/), memory maps
(maps), current working directory (cwd), executable (exe) and root. This is
what lsof does under the hood, minus the binary.

Without root we can only inspect our own processes; the scan counts the
processes it could not look into and reports that honestly.
"""

from __future__ import annotations

import os

from .core import Holder, ScanResult, make_matcher

PROC_ROOT = "/proc"

_DELETED_SUFFIX = " (deleted)"


def _read_link(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def _strip_deleted(path):
    if path.endswith(_DELETED_SUFFIX):
        return path[: -len(_DELETED_SUFFIX)], True
    return path, False


def _boot_time():
    try:
        with open(os.path.join(PROC_ROOT, "stat"), "r") as fh:
            for line in fh:
                if line.startswith("btime "):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def _started_iso(pid_dir, btime, clk_tck):
    if btime is None or not clk_tck:
        return None
    try:
        with open(os.path.join(pid_dir, "stat"), "rb") as fh:
            data = fh.read().decode("ascii", "replace")
        rpar = data.rfind(")")
        fields = data[rpar + 2 :].split()
        start_jiffies = int(fields[19])  # field 22 of /proc/pid/stat
        import datetime as _dt

        unix = btime + start_jiffies / clk_tck
        return _dt.datetime.fromtimestamp(unix).isoformat(timespec="seconds")
    except (OSError, ValueError, IndexError):
        return None


def _proc_identity(pid_dir):
    name = cmdline = user = None
    try:
        with open(os.path.join(pid_dir, "comm"), "rb") as fh:
            name = fh.read().decode("utf-8", "replace").strip()
    except OSError:
        pass
    try:
        with open(os.path.join(pid_dir, "cmdline"), "rb") as fh:
            raw = fh.read()
        if raw:
            cmdline = " ".join(
                part.decode("utf-8", "replace")
                for part in raw.split(b"\0")
                if part
            )
    except OSError:
        pass
    try:
        uid = os.stat(pid_dir).st_uid
        try:
            import pwd

            user = pwd.getpwuid(uid).pw_name
        except (KeyError, ImportError):
            user = str(uid)
    except OSError:
        pass
    return name, cmdline, user


def _target_inodes(files):
    """(st_dev, st_ino) of the file targets - catches hardlinked names."""
    inodes = set()
    for f in files:
        try:
            st = os.stat(f)
            inodes.add((st.st_dev, st.st_ino))
        except OSError:
            pass
    return inodes


def scan(files, dirs, recursive=False, max_files=10000):
    match = make_matcher(files, dirs, recursive)
    target_inodes = _target_inodes(files)
    holders = []
    inaccessible = 0
    warnings = []
    btime = _boot_time()
    try:
        clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    except (ValueError, KeyError, AttributeError):
        clk_tck = None
    my_pid = os.getpid()

    for entry in os.listdir(PROC_ROOT):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == my_pid:
            continue
        pid_dir = os.path.join(PROC_ROOT, entry)
        access = []

        def add(label):
            if label not in access:
                access.append(label)

        readable = False
        try:
            for link, label in (("cwd", "cwd"), ("exe", "exe"), ("root", "root")):
                target = _read_link(os.path.join(pid_dir, link))
                if target is None:
                    continue
                readable = True
                target, deleted = _strip_deleted(target)
                if match(target):
                    add(label)
            fd_dir = os.path.join(pid_dir, "fd")
            try:
                fd_entries = os.listdir(fd_dir)
                readable = True
            except PermissionError:
                fd_entries = None
            except OSError:
                fd_entries = []
            if fd_entries is None:
                if not access:
                    inaccessible += 1
                    continue
            else:
                for fd in fd_entries:
                    fd_path = os.path.join(fd_dir, fd)
                    target = _read_link(fd_path)
                    if target is None:
                        continue
                    target, deleted = _strip_deleted(target)
                    if match(target):
                        add("fd (deleted)" if deleted else "fd")
                    elif target_inodes and target.startswith("/"):
                        # same file under another name (hardlink)?
                        try:
                            st = os.stat(fd_path)
                            if (st.st_dev, st.st_ino) in target_inodes:
                                add("fd (hardlink)")
                        except OSError:
                            pass
            try:
                with open(os.path.join(pid_dir, "maps"), "r") as fh:
                    for line in fh:
                        parts = line.rstrip("\n").split(maxsplit=5)
                        if len(parts) < 6:
                            continue
                        target, deleted = _strip_deleted(parts[5])
                        if not target.startswith("/"):
                            continue
                        if match(target):
                            add("mmap (deleted)" if deleted else "mmap")
            except OSError:
                pass
        except PermissionError:
            inaccessible += 1
            continue
        except (FileNotFoundError, ProcessLookupError):
            continue

        if not readable and not access:
            inaccessible += 1
            continue
        if not access:
            continue

        name, cmdline, user = _proc_identity(pid_dir)
        matched_paths = _matched_paths_for(pid_dir, match)
        holders.append(
            Holder(
                pid=pid,
                name=name or "",
                cmdline=cmdline,
                user=user,
                exe=_read_link(os.path.join(pid_dir, "exe")),
                access=access,
                paths=matched_paths,
                started=_started_iso(pid_dir, btime, clk_tck),
            )
        )

    if inaccessible and hasattr(os, "geteuid") and os.geteuid() != 0:
        warnings.append(
            "%d process(es) belonging to other users could not be inspected; "
            "run with sudo for a complete answer" % inaccessible
        )
    return ScanResult(
        targets=[],
        holders=holders,
        scanned_files=len(files) + len(dirs),
        inaccessible=inaccessible,
        warnings=warnings,
        backend="linux-proc",
    )


def _matched_paths_for(pid_dir, match):
    """Collect the concrete paths this process holds (for display)."""
    found = []

    def note(path):
        if path and path not in found:
            found.append(path)

    for link in ("cwd", "exe"):
        target = _read_link(os.path.join(pid_dir, link))
        if target is not None:
            target, _ = _strip_deleted(target)
            if match(target):
                note(target)
    fd_dir = os.path.join(pid_dir, "fd")
    try:
        entries = os.listdir(fd_dir)
    except OSError:
        entries = []
    for fd in entries:
        target = _read_link(os.path.join(fd_dir, fd))
        if target is None:
            continue
        target, _ = _strip_deleted(target)
        if match(target):
            note(target)
    return found
