# Changelog

## 0.1.0 - 2026-08-13

Initial release.

- Find which processes hold a file or folder open:
  - Windows: Restart Manager API via ctypes (no subprocess, no admin needed)
  - Linux: direct /proc scan (fd, maps, cwd, exe, root)
  - macOS: lsof field-output mode
- `--kill` with confirmation, safety guardrails (refuses critical/system
  processes, PID 1, itself; Windows services need `--force`), and post-kill
  verification that the path is actually free
- `--wait [--timeout N]` to block until a path is released
- `--recursive` folder scanning, `--json` output, `--quiet`, scripting-friendly
  exit codes (0 free / 1 held / 2 usage / 3 backend unavailable)
- Targeted tips for well-known lockers (Office `~$` lock files, OneDrive,
  antivirus, Explorer preview pane, orphaned dev servers, databases)
- Zero runtime dependencies, Python 3.9+
