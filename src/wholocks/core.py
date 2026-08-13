"""Platform dispatch, data model, advice engine, and kill/wait actions."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

DEFAULT_MAX_FILES = 10000


class UsageError(Exception):
    """Bad input from the user (missing path, conflicting flags). Exit code 2."""


class BackendUnavailable(Exception):
    """The platform backend cannot run (unsupported OS, lsof missing). Exit code 3."""


@dataclass
class Holder:
    """One process that holds at least one of the target paths."""

    pid: int
    name: str = ""
    description: Optional[str] = None
    exe: Optional[str] = None
    cmdline: Optional[str] = None
    user: Optional[str] = None
    access: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    app_type: Optional[str] = None
    started: Optional[str] = None

    def merge(self, other: "Holder") -> None:
        for a in other.access:
            if a not in self.access:
                self.access.append(a)
        for p in other.paths:
            if p not in self.paths:
                self.paths.append(p)
        self.name = self.name or other.name
        self.description = self.description or other.description
        self.exe = self.exe or other.exe
        self.cmdline = self.cmdline or other.cmdline
        self.user = self.user or other.user
        self.app_type = self.app_type or other.app_type
        self.started = self.started or other.started


@dataclass
class ScanResult:
    targets: List[str]
    holders: List[Holder]
    scanned_files: int = 0
    inaccessible: int = 0
    warnings: List[str] = field(default_factory=list)
    backend: str = ""

    @property
    def free(self) -> bool:
        return not self.holders


def dedupe_holders(holders: List[Holder]) -> List[Holder]:
    by_pid: dict = {}
    for h in holders:
        if h.pid in by_pid:
            by_pid[h.pid].merge(h)
        else:
            by_pid[h.pid] = h
    return sorted(by_pid.values(), key=lambda h: h.pid)


def split_targets(paths: List[str]) -> "tuple[list, list]":
    """Validate inputs and split into (files, dirs) of absolute paths."""
    files, dirs = [], []
    for raw in paths:
        p = os.path.abspath(raw)
        if os.path.isdir(p):
            dirs.append(p)
        elif os.path.exists(p):
            files.append(p)
        else:
            raise UsageError("path does not exist: %s" % raw)
    return files, dirs


def make_matcher(files: List[str], dirs: List[str], recursive: bool) -> Callable[[str], bool]:
    """Return match(path) used by the POSIX backends.

    A path matches when it is one of the target files, a target directory
    itself, an immediate child of a target directory, or (with recursive)
    anything under a target directory.
    """
    file_set = {os.path.realpath(f) for f in files}
    dir_list = [os.path.realpath(d).rstrip("/") or "/" for d in dirs]

    def match(path: str) -> bool:
        if path in file_set:
            return True
        for d in dir_list:
            if path == d:
                return True
            prefix = d if d.endswith("/") else d + "/"
            if path.startswith(prefix):
                if recursive:
                    return True
                # non-recursive: immediate children only
                if "/" not in path[len(prefix):]:
                    return True
        return False

    return match


def find_holders(
    paths: List[str],
    recursive: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
) -> ScanResult:
    """Find all processes currently holding any of *paths*.

    *paths* may contain files and directories.  Directories are checked
    together with their immediate children; pass recursive=True to check
    everything below them.
    """
    files, dirs = split_targets(paths)
    if sys.platform.startswith("win"):
        from . import _windows as backend
    elif sys.platform.startswith("linux"):
        from . import _linux as backend
    elif sys.platform == "darwin":
        from . import _darwin as backend
    else:
        raise BackendUnavailable("unsupported platform: %s" % sys.platform)

    result = backend.scan(files, dirs, recursive=recursive, max_files=max_files)
    result.targets = [os.path.abspath(p) for p in paths]
    result.holders = dedupe_holders(result.holders)
    for h in result.holders:
        h.access.sort()
        h.paths.sort()
    return result


# --------------------------------------------------------------------------
# Advice engine: targeted tips for well-known lockers.
# Keys are lower-case executable basenames without extension.
# --------------------------------------------------------------------------

_OFFICE = (
    "Close the document in {name}. If the app is already closed, look for a "
    "leftover '~$xxx' lock file next to the document and delete it too."
)
_SYNC = (
    "{name} is syncing this file. Pause syncing from the tray icon or wait "
    "for the sync to finish, then retry."
)
_AV = (
    "{name} looks like an antivirus / security scan. This is usually "
    "transient - retry in a few seconds, or add the folder to the scanner's "
    "exclusion list. Killing it is likely to fail or be blocked."
)
_INDEXER = (
    "Windows Search is indexing the file. This is transient - retry shortly, "
    "or exclude the folder under 'Windows Search settings'."
)
_DEVSERVER = (
    "Looks like a leftover dev-server worker (on Windows, Ctrl+C often does "
    "not reach grandchild processes). Killing it is usually safe."
)

ADVICE = {
    "winword": _OFFICE,
    "excel": _OFFICE,
    "powerpnt": _OFFICE,
    "wps": _OFFICE,
    "wpp": _OFFICE,
    "et": _OFFICE,
    "soffice": _OFFICE,
    "soffice.bin": _OFFICE,
    "onedrive": _SYNC,
    "dropbox": _SYNC,
    "googledrivefs": _SYNC,
    "kdrive": _SYNC,
    "msmpeng": _AV,
    "mpdefendercoreservice": _AV,
    "360tray": _AV,
    "360sd": _AV,
    "qqpcrtp": _AV,
    "kxetray": _AV,
    "kxescore": _AV,
    "searchindexer": _INDEXER,
    "searchprotocolhost": _INDEXER,
    "searchfilterhost": _INDEXER,
    "explorer": (
        "Windows Explorer holds it - usually an open folder window, the "
        "preview pane, or thumbnail generation. Close the folder window or "
        "press Esc in it, then retry. Killing explorer.exe restarts your "
        "desktop shell."
    ),
    "node": _DEVSERVER,
    "esbuild": _DEVSERVER,
    "vite": _DEVSERVER,
    "deno": _DEVSERVER,
    "bun": _DEVSERVER,
    "java": (
        "Often a Gradle/Maven daemon or a language server holding build "
        "output. 'gradlew --stop' shuts Gradle daemons down cleanly."
    ),
    "acrord32": "Close the PDF in Adobe Reader.",
    "acrobat": "Close the PDF in Adobe Acrobat.",
    "vmware-vmx": "A running virtual machine holds it. Shut the VM down first.",
    "vmmem": "WSL or a VM holds it. 'wsl --shutdown' releases WSL-held files.",
    "sqlservr": (
        "A database server holds its data files. Stop the service properly "
        "instead of killing it, or you risk corrupting the database."
    ),
    "mysqld": (
        "A database server holds its data files. Stop the service properly "
        "instead of killing it, or you risk corrupting the database."
    ),
    "postgres": (
        "A database server holds its data files. Stop the service properly "
        "instead of killing it, or you risk corrupting the database."
    ),
    "system": (
        "Held by the Windows kernel itself (PID 4) - typically an SMB "
        "network share, a filter driver, or kernel-level indexing. It "
        "cannot be killed; retry in a moment."
    ),
}


def advice_for(holder: Holder) -> Optional[str]:
    base = (holder.name or "").lower()
    for ext in (".exe", ".bin"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    tip = ADVICE.get(base)
    if tip:
        return tip.format(name=holder.name or "the app")
    return None


# --------------------------------------------------------------------------
# Kill / wait actions
# --------------------------------------------------------------------------

def kill_block_reason(holder: Holder, force: bool = False) -> Optional[str]:
    """Return a reason string when we refuse to kill this holder."""
    if holder.app_type == "critical":
        return "critical system process - killing it would destabilize Windows"
    if sys.platform.startswith("win"):
        if holder.pid <= 4:
            return "core system process"
    else:
        if holder.pid == 1:
            return "PID 1 (init/systemd)"
    if holder.pid == os.getpid():
        return "this is wholocks itself"
    if holder.app_type == "service" and not force:
        svc = holder.description or holder.name
        return (
            "it is a Windows service (%s) - stop it with "
            "'net stop <service>' or pass --force" % svc
        )
    return None


def kill_holder(holder: Holder, force: bool = False, grace: float = 5.0) -> "tuple[bool, str]":
    """Terminate one holder. Returns (ok, message)."""
    if sys.platform.startswith("win"):
        from . import _windows

        return _windows.kill(holder.pid, grace=grace)

    import signal

    try:
        os.kill(holder.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True, "already gone"
    except PermissionError:
        return False, "permission denied (try sudo)"
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not _pid_alive(holder.pid):
            return True, "terminated (SIGTERM)"
        time.sleep(0.1)
    if force:
        try:
            os.kill(holder.pid, signal.SIGKILL)
        except ProcessLookupError:
            return True, "terminated (SIGTERM)"
        except PermissionError:
            return False, "permission denied (try sudo)"
        time.sleep(0.2)
        return True, "killed (SIGKILL)"
    return False, "still running after SIGTERM (use --force to SIGKILL)"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_until_free(
    paths: List[str],
    recursive: bool = False,
    timeout: Optional[float] = None,
    max_files: int = DEFAULT_MAX_FILES,
    on_poll: Optional[Callable[[ScanResult, float], None]] = None,
) -> "tuple[bool, float]":
    """Poll until no process holds *paths*. Returns (became_free, waited_seconds)."""
    start = time.monotonic()
    interval = 0.5
    while True:
        result = find_holders(paths, recursive=recursive, max_files=max_files)
        waited = time.monotonic() - start
        if result.free:
            return True, waited
        if timeout is not None and waited >= timeout:
            return False, waited
        if on_poll is not None:
            on_poll(result, waited)
        remaining = None if timeout is None else max(0.0, timeout - waited)
        sleep_for = interval if remaining is None else min(interval, remaining + 0.01)
        time.sleep(sleep_for)
        interval = min(interval * 1.5, 2.0)
