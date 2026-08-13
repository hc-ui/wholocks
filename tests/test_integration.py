"""End-to-end tests that exercise the real platform backend."""

import json
import os
import sys
import time

import pytest

from conftest import run_cli, wait_deletable


def test_detects_holder(hold_file):
    path, proc = hold_file()
    code, out, err = run_cli(path)
    assert code == 1, "stdout=%s stderr=%s" % (out, err)
    assert str(proc.pid) in out
    assert "held by" in out


def test_free_file_exits_zero(tmp_path):
    path = tmp_path / "free.txt"
    path.write_bytes(b"nobody holds me")
    code = None
    for _ in range(3):  # tolerate transient scanners (antivirus, indexers)
        code, out, err = run_cli(path)
        if code == 0:
            break
        time.sleep(1.0)
    assert code == 0, "stdout=%s stderr=%s" % (out, err)
    assert "not held" in out


def test_missing_path_is_usage_error(tmp_path):
    code, out, err = run_cli(tmp_path / "does-not-exist.txt")
    assert code == 2
    assert "does not exist" in err


def test_json_output(hold_file):
    path, proc = hold_file()
    code, out, err = run_cli("--json", path)
    assert code == 1, "stdout=%s stderr=%s" % (out, err)
    payload = json.loads(out)
    assert payload["free"] is False
    pids = [h["pid"] for h in payload["holders"]]
    assert proc.pid in pids
    holder = next(h for h in payload["holders"] if h["pid"] == proc.pid)
    assert holder["access"]
    assert "python" in (holder["name"] or "").lower() or holder["exe"]
    assert holder["user"], "user field should be resolved for our own child"
    for key in ("targets", "backend", "warnings", "scanned_files"):
        assert key in payload


def test_json_free(tmp_path):
    path = tmp_path / "free.json.txt"
    path.write_bytes(b"x")
    for _ in range(3):
        code, out, err = run_cli("--json", path)
        payload = json.loads(out)
        if payload["free"]:
            break
        time.sleep(1.0)
    assert payload["free"] is True
    assert payload["holders"] == []
    assert code == 0


def test_kill_frees_file(hold_file):
    path, proc = hold_file()
    code, out, err = run_cli("--kill", "--yes", path)
    assert code == 0, "stdout=%s stderr=%s" % (out, err)
    assert proc.wait(timeout=15) is not None
    wait_deletable(path)


def test_kill_prompt_abort(hold_file):
    path, proc = hold_file()
    code, out, err = run_cli("--kill", path, input_text="n\n")
    assert code == 1
    assert proc.poll() is None, "child must survive an aborted kill"


def test_kill_json_requires_yes(hold_file):
    path, proc = hold_file()
    code, out, err = run_cli("--kill", "--json", path)
    assert code == 2
    assert "--yes" in err


def test_wait_until_released(hold_file):
    path, proc = hold_file(seconds=2.5)
    start = time.monotonic()
    code, out, err = run_cli("--wait", "--timeout", "60", path)
    elapsed = time.monotonic() - start
    assert code == 0, "stdout=%s stderr=%s" % (out, err)
    assert elapsed < 55
    assert "free" in out


def test_wait_timeout(hold_file):
    path, proc = hold_file(seconds=120)
    code, out, err = run_cli("--wait", "--timeout", "2", path)
    assert code == 1
    assert "timed out" in out


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX allows unlinking a held file")
def test_wait_succeeds_when_holder_deletes_file(hold_file, tmp_path):
    script = (
        "import os, sys, time\n"
        "f = open(sys.argv[1], 'r+b')\n"
        "print('READY', flush=True)\n"
        "time.sleep(1.0)\n"
        "os.unlink(sys.argv[1])\n"
        "time.sleep(float(sys.argv[2]))\n"
    )
    path, proc = hold_file(path=tmp_path / "doomed.txt", seconds=60, script=script)
    code, out, err = run_cli("--wait", "--timeout", "30", path)
    assert code == 0, "stdout=%s stderr=%s" % (out, err)


def test_recursive_directory(hold_file, tmp_path):
    sub = tmp_path / "outer" / "inner"
    sub.mkdir(parents=True)
    held = sub / "held.bin"
    held.write_bytes(b"x" * 32)
    path, proc = hold_file(path=held)

    code, out, err = run_cli("--recursive", tmp_path / "outer")
    assert code == 1, "stdout=%s stderr=%s" % (out, err)
    assert str(proc.pid) in out

    code2, out2, err2 = run_cli(tmp_path / "outer")  # non-recursive: 2 levels deep
    assert code2 == 0, "stdout=%s stderr=%s" % (out2, err2)


def test_multiple_paths(hold_file, tmp_path):
    held_path, proc = hold_file()
    free_path = tmp_path / "free2.txt"
    free_path.write_bytes(b"y")
    code, out, err = run_cli(held_path, free_path)
    assert code == 1
    assert str(proc.pid) in out


def test_detects_cwd_holder(hold_cwd, tmp_path):
    """A process merely cd'd into a folder blocks its deletion on Windows -
    the classic hidden locker. All three backends must find it."""
    d = tmp_path / "busy-dir"
    d.mkdir()
    proc = hold_cwd(d)
    code, out, err = run_cli(d)
    assert code == 1, "stdout=%s stderr=%s" % (out, err)
    assert str(proc.pid) in out


def test_recursive_detects_deep_cwd(hold_cwd, tmp_path):
    deep = tmp_path / "project" / "node_modules" / ".vite"
    deep.mkdir(parents=True)
    proc = hold_cwd(deep)
    code, out, err = run_cli("--recursive", tmp_path / "project")
    assert code == 1, "stdout=%s stderr=%s" % (out, err)
    assert str(proc.pid) in out


@pytest.mark.skipif(sys.platform.startswith("win") or sys.platform == "darwin",
                    reason="hardlink-inode matching is implemented in the /proc backend")
def test_hardlink_detection(hold_file, tmp_path):
    original = tmp_path / "app.log"
    original.write_bytes(b"log data")
    link = tmp_path / "rotated.log"
    os.link(original, link)

    # the process holds the file via ONE name...
    path, proc = hold_file(path=link)
    # ...but we ask about the OTHER name
    code, out, err = run_cli("--json", original)
    assert code == 1, "stdout=%s stderr=%s" % (out, err)
    payload = json.loads(out)
    holder = next(h for h in payload["holders"] if h["pid"] == proc.pid)
    assert any("hardlink" in a or a == "fd" for a in holder["access"])


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="mmap access labels are Linux-specific")
def test_mmap_detection_linux(hold_file):
    from conftest import MMAP_FILE_SCRIPT

    path, proc = hold_file(script=MMAP_FILE_SCRIPT)
    code, out, err = run_cli("--json", path)
    assert code == 1
    payload = json.loads(out)
    holder = next(h for h in payload["holders"] if h["pid"] == proc.pid)
    assert any(a.startswith(("fd", "mmap")) for a in holder["access"])


def test_version():
    code, out, err = run_cli("--version")
    assert code == 0
    assert "wholocks" in out


def test_quiet_mode(hold_file):
    path, proc = hold_file()
    code, out, err = run_cli("--quiet", path)
    assert code == 1
    assert out.strip() == ""
