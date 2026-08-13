"""Command-line interface for wholocks."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .core import (
    DEFAULT_MAX_FILES,
    BackendUnavailable,
    Holder,
    ScanResult,
    UsageError,
    advice_for,
    find_holders,
    kill_block_reason,
    kill_holder,
    wait_until_free,
)

EXIT_FREE = 0
EXIT_HELD = 1
EXIT_USAGE = 2
EXIT_BACKEND = 3


# ---------------------------------------------------------------- colors ---

class _Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def _wrap(self, code, text):
        if not self.enabled:
            return text
        return "\033[%sm%s\033[0m" % (code, text)

    def bold(self, t):
        return self._wrap("1", t)

    def red(self, t):
        return self._wrap("31", t)

    def green(self, t):
        return self._wrap("32", t)

    def yellow(self, t):
        return self._wrap("33", t)

    def dim(self, t):
        return self._wrap("2", t)


def _make_style(no_color_flag):
    if no_color_flag or os.environ.get("NO_COLOR"):
        return _Style(False)
    if not sys.stdout.isatty():
        return _Style(False)
    if sys.platform.startswith("win"):
        if not _enable_windows_ansi():
            return _Style(False)
    return _Style(True)


def _enable_windows_ansi():
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetStdHandle.argtypes = (ctypes.c_uint32,)
        kernel32.GetConsoleMode.restype = ctypes.c_int
        kernel32.GetConsoleMode.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        )
        kernel32.SetConsoleMode.restype = ctypes.c_int
        kernel32.SetConsoleMode.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        handle = kernel32.GetStdHandle(0xFFFFFFF5)  # STD_OUTPUT_HANDLE (-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, new_mode))
    except Exception:
        return False


# ---------------------------------------------------------------- output ---

def _fmt_started(iso):
    if not iso:
        return None
    # show just the time part when it's today-ish; keep it simple: strip date T
    return iso.replace("T", " ")


def _print_holder(h: Holder, style: _Style, out):
    title = "  PID %-7d %s" % (h.pid, style.bold(h.name or "?"))
    if h.description and h.description != h.name:
        title += "   " + style.dim(h.description)
    print(title, file=out)
    detail_rows = []
    if h.exe and h.exe != h.name:
        detail_rows.append(("exe", h.exe))
    if h.cmdline and h.cmdline != h.exe:
        cmd = h.cmdline if len(h.cmdline) <= 120 else h.cmdline[:117] + "..."
        detail_rows.append(("cmd", cmd))
    meta = []
    if h.user:
        meta.append("user: %s" % h.user)
    if h.app_type:
        meta.append("type: %s" % h.app_type.replace("_", " "))
    started = _fmt_started(h.started)
    if started:
        meta.append("started: %s" % started)
    if h.access:
        meta.append("via: %s" % ", ".join(h.access))
    if meta:
        detail_rows.append((None, "   ".join(meta)))
    for label, value in detail_rows:
        prefix = "%s: " % label if label else ""
        print("             %s%s" % (prefix, style.dim(value)), file=out)
    if h.paths:
        shown = h.paths[:3]
        extra = len(h.paths) - len(shown)
        for p in shown:
            print("             holds: %s" % style.dim(p), file=out)
        if extra > 0:
            print("             holds: %s" % style.dim("... and %d more" % extra), file=out)
    tip = advice_for(h)
    if tip:
        print("             %s %s" % (style.yellow("tip:"), tip), file=out)


def _print_report(result: ScanResult, args, style: _Style, out=None):
    out = out if out is not None else sys.stdout
    label = ", ".join(result.targets)
    if result.free:
        print("%s\n  %s" % (label, style.green("not held by any process.")), file=out)
    else:
        n = len(result.holders)
        print(
            "%s\n  %s"
            % (
                label,
                style.red("held by %d process%s:" % (n, "" if n == 1 else "es")),
            ),
            file=out,
        )
        print("", file=out)
        for h in result.holders:
            _print_holder(h, style, out)
        print("", file=out)
        if not args.kill:
            quoted = " ".join(_quote(t) for t in result.targets)
            print("  free it:   wholocks --kill %s" % quoted, file=out)
            print("  wait:      wholocks --wait %s" % quoted, file=out)
    for w in result.warnings:
        print("  %s %s" % (style.yellow("note:"), w), file=out)


def _quote(path):
    return '"%s"' % path if " " in path else path


def _holder_dict(h: Holder):
    return {
        "pid": h.pid,
        "name": h.name,
        "description": h.description,
        "exe": h.exe,
        "cmdline": h.cmdline,
        "user": h.user,
        "access": h.access,
        "paths": h.paths,
        "app_type": h.app_type,
        "started": h.started,
        "advice": advice_for(h),
    }


def _result_dict(result: ScanResult):
    return {
        "wholocks": __version__,
        "backend": result.backend,
        "targets": result.targets,
        "free": result.free,
        "holders": [_holder_dict(h) for h in result.holders],
        "scanned_files": result.scanned_files,
        "inaccessible_processes": result.inaccessible,
        "warnings": result.warnings,
    }


# ---------------------------------------------------------------- parser ---

def build_parser():
    p = argparse.ArgumentParser(
        prog="wholocks",
        description=(
            "Find which process is locking a file or folder - then kill it "
            "or wait for it. Zero dependencies."
        ),
        epilog=(
            "examples:\n"
            "  wholocks report.docx              show who holds the file\n"
            "  wholocks --kill report.docx       terminate the holders (asks first)\n"
            "  wholocks --wait -t 60 build.log   block until the file is free\n"
            "  wholocks -r node_modules          check everything inside a folder\n"
            "  wholocks --json app.db            machine-readable output\n"
            "\n"
            "exit codes: 0 = free / action succeeded, 1 = held / failed / "
            "timed out, 2 = usage error, 3 = backend unavailable"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="+", metavar="PATH", help="file(s) or folder(s) to check")
    p.add_argument(
        "-k", "--kill", action="store_true",
        help="terminate the holding processes (asks for confirmation)",
    )
    p.add_argument(
        "-y", "--yes", action="store_true",
        help="do not ask for confirmation before killing",
    )
    p.add_argument(
        "-f", "--force", action="store_true",
        help="escalate: SIGKILL on POSIX after grace period; also required to kill Windows services",
    )
    p.add_argument(
        "-w", "--wait", action="store_true",
        help="wait until the path is no longer held",
    )
    p.add_argument(
        "-t", "--timeout", type=float, metavar="SEC",
        help="give up waiting after SEC seconds (default: wait forever)",
    )
    p.add_argument(
        "-r", "--recursive", action="store_true",
        help="for folders: check everything below, not just immediate children",
    )
    p.add_argument("--json", action="store_true", help="output JSON")
    p.add_argument(
        "-q", "--quiet", action="store_true",
        help="no output, exit code only",
    )
    p.add_argument(
        "--max-files", type=int, default=DEFAULT_MAX_FILES, metavar="N",
        help="cap on files checked inside folders (default %d)" % DEFAULT_MAX_FILES,
    )
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument(
        "-V", "--version", action="version", version="wholocks %s" % __version__
    )
    return p


def _validate_args(args):
    if args.kill and args.wait:
        raise UsageError("--kill and --wait cannot be combined")
    if args.timeout is not None and not args.wait:
        raise UsageError("--timeout only makes sense together with --wait")
    if args.timeout is not None and args.timeout < 0:
        raise UsageError("--timeout must be >= 0")
    if args.yes and not args.kill:
        raise UsageError("--yes only makes sense together with --kill")
    if args.kill and args.quiet and not args.yes:
        raise UsageError("--kill --quiet requires --yes (there is no interactive prompt in quiet mode)")
    if args.max_files < 1:
        raise UsageError("--max-files must be >= 1")
    if args.json and args.quiet:
        raise UsageError("--json and --quiet cannot be combined")


# ---------------------------------------------------------------- modes ----

def _mode_report(args, style):
    result = find_holders(args.paths, recursive=args.recursive, max_files=args.max_files)
    if args.json:
        print(json.dumps(_result_dict(result), ensure_ascii=False, indent=2))
    elif not args.quiet:
        _print_report(result, args, style)
    return EXIT_FREE if result.free else EXIT_HELD


def _mode_kill(args, style):
    result = find_holders(args.paths, recursive=args.recursive, max_files=args.max_files)
    if result.free:
        if args.json:
            payload = _result_dict(result)
            payload["kill_results"] = []
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        elif not args.quiet:
            _print_report(result, args, style)
        return EXIT_FREE

    if not args.quiet and not args.json:
        _print_report(result, args, style)

    parent_pid = os.getppid()
    if not args.yes:
        if args.json:
            raise UsageError("--kill with --json requires --yes (no interactive prompt)")
        try:
            n = len(result.holders)
            answer = input(
                "Terminate %d process%s? [y/N] " % (n, "" if n == 1 else "es")
            )
        except (EOFError, KeyboardInterrupt):
            print("\naborted. Use --yes to skip the prompt in scripts.")
            return EXIT_HELD
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted.")
            return EXIT_HELD

    kill_results = []
    for h in result.holders:
        reason = kill_block_reason(h, force=args.force)
        if reason:
            kill_results.append({"pid": h.pid, "name": h.name, "ok": False, "detail": "refused: " + reason})
            continue
        if h.pid == parent_pid and not args.force:
            kill_results.append({
                "pid": h.pid, "name": h.name, "ok": False,
                "detail": "refused: this is the shell/process that started wholocks (pass --force if you mean it)",
            })
            continue
        ok, detail = kill_holder(h, force=args.force)
        kill_results.append({"pid": h.pid, "name": h.name, "ok": ok, "detail": detail})

    # the truthful success metric: is the file free now?
    after = find_holders(args.paths, recursive=args.recursive, max_files=args.max_files)

    if args.json:
        payload = _result_dict(after)
        payload["kill_results"] = kill_results
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif not args.quiet:
        for r in kill_results:
            mark = style.green("ok") if r["ok"] else style.red("failed")
            print("  %s  PID %-7d %s - %s" % (mark, r["pid"], r["name"], r["detail"]))
        print("")
        if after.free:
            print("  %s" % style.green("the path is now free."))
        else:
            print("  %s" % style.red("still held by:"))
            for h in after.holders:
                _print_holder(h, style, sys.stdout)
    return EXIT_FREE if after.free else EXIT_HELD


def _mode_wait(args, style):
    last_seen = {"sig": None, "t": 0.0}

    def on_poll(result, waited):
        if args.quiet or args.json:
            return
        sig = tuple(h.pid for h in result.holders)
        if sig != last_seen["sig"] or waited - last_seen["t"] >= 5.0:
            last_seen["sig"] = sig
            last_seen["t"] = waited
            names = ", ".join(
                "%s (PID %d)" % (h.name or "?", h.pid) for h in result.holders[:4]
            )
            more = len(result.holders) - 4
            if more > 0:
                names += " and %d more" % more
            print(
                "  still held by %s - %.0fs elapsed" % (names, waited),
                flush=True,
            )

    became_free, waited = wait_until_free(
        args.paths,
        recursive=args.recursive,
        timeout=args.timeout,
        max_files=args.max_files,
        on_poll=on_poll,
    )
    if args.json:
        result = find_holders(args.paths, recursive=args.recursive, max_files=args.max_files)
        payload = _result_dict(result)
        payload["waited_seconds"] = round(waited, 2)
        payload["timed_out"] = not became_free
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif not args.quiet:
        if became_free:
            print("  %s (waited %.1fs)" % (style.green("the path is now free."), waited))
        else:
            print("  %s (waited %.1fs)" % (style.red("timed out; still held."), waited))
    return EXIT_FREE if became_free else EXIT_HELD


def main(argv=None):
    # never crash on paths the console encoding cannot represent
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    style = _make_style(args.no_color)
    try:
        _validate_args(args)
        if args.wait:
            return _mode_wait(args, style)
        if args.kill:
            return _mode_kill(args, style)
        return _mode_report(args, style)
    except UsageError as e:
        print("wholocks: error: %s" % e, file=sys.stderr)
        return EXIT_USAGE
    except BackendUnavailable as e:
        print("wholocks: %s" % e, file=sys.stderr)
        return EXIT_BACKEND
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
