# Changelog

## 0.2.0 - 2026-08-13

The classic hidden locker - a console window merely `cd`'d into a folder, or
an Explorer window showing it - is now detected on Windows.

- Windows: added a kernel-level `NtQueryInformationFile`
  (`FileProcessIdsUsingFileInformation`) probe alongside the Restart
  Manager. Unlike the Restart Manager it also reports *directory* handles,
  so Explorer windows and shells sitting inside a folder are found. It also
  attributes which explicit target each process holds.
- Windows: a Restart Manager failure no longer aborts the scan; it degrades
  to the direct handle query with a warning.
- Windows: holders now show the owning account name (process token query),
  matching the POSIX output.
- Shells (cmd, PowerShell, bash, zsh, ...) get a targeted tip - they usually
  hold a folder via their current directory; the kernel PID 4 "System"
  holder is explained too.
- Output streams no longer crash on file names the console encoding cannot
  represent (`errors="replace"`).
- Fixed 64-bit handle truncation risk in the ANSI-color console setup.
- Tests: fixed `/proc` fixture paths on macOS (`/tmp` symlink realpath);
  added cross-platform cwd-holder integration tests.

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
