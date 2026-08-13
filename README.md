# wholocks

[![CI](https://github.com/hc-ui/wholocks/actions/workflows/ci.yml/badge.svg)](https://github.com/hc-ui/wholocks/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

**"The file is open in another program." Okay — *which one?***

`wholocks` answers that in one command, then frees the file for you or waits until it's free. Windows, macOS, Linux. **Zero dependencies** — pure Python standard library.

[中文说明](#wholocks-中文) below.

```text
$ wholocks report.docx
C:\work\report.docx
  held by 1 process:

  PID 4184    WINWORD.EXE   Microsoft Word
              exe: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
              type: main window   started: 2026-08-13 10:32:06   via: handle
              tip: Close the document in Word. If the app is already closed, look
                   for a leftover '~$xxx' lock file next to the document.

  free it:   wholocks --kill report.docx
  wait:      wholocks --wait report.docx
```

## The problem

Sooner or later you hit one of these:

- Windows: *"The action can't be completed because the file is open in another program"*
- Windows: `rmdir` / `rm -rf node_modules` fails with *"Access is denied"* or *"The process cannot access the file"*
- Linux: `umount: /mnt/usb: target is busy`
- Any OS: a build fails because a stale dev server still holds `app.log` or `dist/`

The classic answers are painful: on Windows you download Sysinternals `handle.exe` or a 2010-era GUI unlocker and read raw handle dumps; on Linux/macOS you try to remember whether it was `lsof -- file`, `fuser -v`, or `lsof +D dir`, and none of it works on your teammate's Windows machine.

`wholocks` is one memorable command that works the same everywhere, tells you *who* holds the path, *how* (open handle, working directory, memory-mapped, executable), gives a targeted tip for well-known lockers (Office, OneDrive, antivirus, Explorer preview, orphaned dev servers...), and can kill the holder or block until the path is free.

## Install

```bash
pip install git+https://github.com/hc-ui/wholocks
```

Or try it once without installing anything (needs [uv](https://docs.astral.sh/uv/)):

```bash
uvx --from git+https://github.com/hc-ui/wholocks wholocks stubborn-folder
```

PyPI release is being set up — `pip install wholocks` will work once it's live. Either way there are no dependencies; it's a single pure-stdlib package.

## Usage

```bash
wholocks PATH [PATH...]         # who holds this file/folder?
wholocks --kill PATH            # terminate the holders (asks first)
wholocks --kill --yes PATH      # ...without asking (scripts)
wholocks --wait -t 60 PATH      # block until free, give up after 60 s
wholocks -r FOLDER              # check everything inside a folder
wholocks --json PATH            # machine-readable output
wholocks -q PATH                # exit code only
```

### Real-world recipes

**Delete a stubborn `node_modules` on Windows** (orphaned `esbuild.exe` / `node.exe` workers are the usual culprits — Ctrl+C doesn't reach grandchild processes):

```bash
wholocks -r node_modules          # see the orphans
wholocks -r --kill node_modules   # free them, then delete normally
```

**Wait for Excel to release a report before your script copies it:**

```bash
wholocks --wait --timeout 300 monthly.xlsx && cp monthly.xlsx archive/
```

**Find what blocks a USB drive from unmounting (Linux):**

```bash
wholocks -r /mnt/usb
```

**In CI / scripts** — exit codes make it composable:

| code | meaning |
|------|---------|
| 0    | path is free (or was successfully freed / became free) |
| 1    | path is held (or kill failed / wait timed out) |
| 2    | usage error (bad flags, path does not exist) |
| 3    | platform backend unavailable |

```bash
wholocks -q app.db || echo "db is busy, skipping backup"
```

### As a library

```python
from wholocks import find_holders

result = find_holders(["C:/work/report.docx"])
for h in result.holders:
    print(h.pid, h.name, h.access, h.started)
```

## How it works

| Platform | Mechanism | Subprocesses spawned |
|----------|-----------|----------------------|
| Windows  | **Restart Manager API** (the same API behind Windows' own *"file is open in another program"* dialog) **plus a kernel-level `NtQueryInformationFile` handle query** that also sees *directory* handles — Explorer windows and shells `cd`'d into a folder. Both via `ctypes`. | none |
| Linux    | Scans `/proc/*/fd`, `maps`, `cwd`, `exe`, `root` directly | none |
| macOS    | Drives the preinstalled `lsof` in its machine-readable `-F` mode | `lsof`, `ps` |

No drivers, no elevated service, no kernel tricks. Killing uses `TerminateProcess` on Windows and `SIGTERM` (then `SIGKILL` with `--force`) on POSIX, always with a confirmation prompt unless `--yes`.

## vs. the alternatives

| | wholocks | Sysinternals `handle.exe` | Process Explorer / LockHunter | `lsof` / `fuser` | `lockhound` (npm) |
|---|---|---|---|---|---|
| Windows | yes | yes | yes | no | yes |
| macOS / Linux | yes | no | no | yes | no |
| Install | one `pip install` | manual download + EULA | manual download, GUI | preinstalled | needs Node |
| Readable answer | yes | raw handle dump | GUI browsing | terse columns | yes |
| Kill with guardrails | yes (confirm, refuses system/critical) | no | yes | `fuser -k` (no confirm) | yes |
| Wait-until-free mode | **yes** | no | no | no | no |
| Sees folder/cwd lockers (Explorer, `cd`'d shells) | **yes** | needs admin | partial | `fuser` only | heuristic |
| JSON + exit codes | yes | no | no | partial | no |
| Targeted tips (Office/OneDrive/AV...) | **yes** | no | no | no | partial |
| Dependencies | **zero** | – | – | – | zero (but Node) |

## Safety

- Killing always shows *what* will die and asks first (`--yes` to skip).
- Refuses to touch critical system processes, PID 0–4 / PID 1, and itself.
- Windows services are refused unless `--force` (stop them properly with `net stop`).
- Databases get a "stop the service instead" warning in the tip line.
- `--kill` verifies afterwards: success is reported only if the path is actually free.

## Limitations (honest ones)

- **Windows, folder held via a deep subfolder:** a shell `cd`'d into the folder itself (or any probed subfolder) *is* detected — but in non-recursive mode only the folder and its immediate children are probed. If deletion still fails, run again with `--recursive`.
- **POSIX, other users' processes:** without `sudo`, `/proc` and `lsof` only reveal your own processes. `wholocks` counts what it couldn't inspect and says so instead of pretending the file is free.
- **Windows, multiple targets:** the Restart Manager reports holders for the whole set of registered files, so per-file attribution isn't shown (Linux/macOS output lists the exact paths each process holds).
- **PID reuse:** between scan and kill a PID could in theory be recycled; the window is milliseconds, but it exists — the confirmation prompt shows names precisely for this reason.

## FAQ

**Do I need admin/root?** No for the common cases (your own processes). Root/admin widens visibility to other users' processes.

**Why not use `psutil`?** `psutil` is great, but it's a compiled dependency. `wholocks` is pure stdlib — it installs instantly anywhere Python runs, including locked-down corporate machines, and it uses the *official* Windows API for this exact question.

**Does it close file handles without killing?** No. Force-closing a handle inside another process (what some GUI unlockers do) can corrupt that process's state. `wholocks` prefers honest process termination with confirmation.

---

# wholocks (中文)

**「操作无法完成,因为文件已在另一个程序中打开」——到底是哪个程序?**

`wholocks` 一条命令告诉你是谁锁住了文件(或整个文件夹),还能帮你结束占用进程、或阻塞等待文件释放。Windows / macOS / Linux 全平台,**零依赖**,纯 Python 标准库。

## 你一定遇到过

- Windows:删除文件提示 **「文件已在另一个程序中打开」**、删除文件夹提示 **「操作无法完成」**
- `node_modules` 删不掉,提示被某个进程占用(Ctrl+C 杀不干净 esbuild/node 孤儿进程)
- Linux:`umount: target is busy`,U 盘弹不出来
- 脚本要处理的文件还被 Excel/WPS 开着,复制就失败

传统解法都很折磨:Windows 上要去下载 Sysinternals 的 `handle.exe` 或十几年前的 Unlocker 图形工具,对着一堆十六进制句柄猜;Linux/macOS 上要回忆 `lsof` 和 `fuser` 的参数;而且这些方法互不通用。

## 安装

```bash
pip install git+https://github.com/hc-ui/wholocks
```

PyPI 上架流程进行中,届时 `pip install wholocks` 即可。

## 用法

```bash
wholocks 路径              # 谁在占用这个文件/文件夹?
wholocks --kill 路径       # 结束占用进程(先确认)
wholocks --kill --yes 路径 # 不确认,直接结束(适合脚本)
wholocks --wait -t 60 路径 # 阻塞等待释放,最多等 60 秒
wholocks -r 文件夹         # 检查文件夹内所有文件(递归)
wholocks --json 路径       # JSON 输出
```

### 典型场景

**Windows 删除顽固的 `node_modules`:**

```bash
wholocks -r node_modules          # 看看是哪些孤儿进程
wholocks -r --kill node_modules   # 清掉它们,然后正常删除
```

**等 Excel/WPS 关闭文件后再处理:**

```bash
wholocks --wait --timeout 300 月报.xlsx && copy 月报.xlsx 存档\
```

**Linux 查 U 盘为什么弹不出:**

```bash
wholocks -r /mnt/usb
```

退出码:`0` 空闲/操作成功,`1` 被占用/失败/超时,`2` 参数错误,`3` 平台不支持——方便写脚本判断。

## 原理

| 平台 | 机制 | 是否调用外部命令 |
|------|------|------------------|
| Windows | **Restart Manager API**(Windows 自家「文件已在另一个程序中打开」对话框背后的官方 API)**加内核级 `NtQueryInformationFile` 句柄查询**——后者连**目录句柄**都能查到:资源管理器开着文件夹窗口、某个终端 `cd` 在文件夹里,这类"隐形占用"也能揪出来 | 否 |
| Linux | 直接扫描 `/proc/*/fd`、`maps`、`cwd`、`exe` | 否 |
| macOS | 调用系统自带 `lsof` 的机器可读模式 | `lsof`、`ps` |

对常见占用者(Word/Excel/WPS、OneDrive、杀毒软件、资源管理器预览、开发服务器孤儿进程、数据库等)会给出针对性提示,比如 Office 文档关了还占用时提醒你删掉旁边的 `~$` 锁文件。

## 安全设计

- 结束进程前必先列出并确认(脚本用 `--yes` 跳过)
- 拒绝结束系统关键进程、PID 0–4 / PID 1、以及 wholocks 自己
- Windows 服务需要 `--force` 才会动手(并提示用 `net stop` 更妥当)
- 数据库进程会警告「请正常停止服务,强杀可能损坏数据」
- `--kill` 结束后会重新扫描验证,文件真正释放了才报成功

## 已知局限

- **Windows 深层子目录占用**:终端 `cd` 在目标文件夹本身或已探测的子目录里都能查到;非递归模式只探测文件夹本身和第一层内容,删不掉时加 `--recursive` 再查一次
- **POSIX 非 root**:只能看到自己的进程;查不到的进程数会如实报告,不会假装文件空闲
- **Windows 多目标**:Restart Manager 返回的是整批文件的占用者,不区分单个文件(Linux/macOS 会列出每个进程具体占用的路径)

## License

MIT
