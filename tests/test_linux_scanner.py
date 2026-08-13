"""Test the /proc scanner against a synthetic /proc tree (POSIX only)."""

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform.startswith("win"), reason="requires POSIX symlinks and paths"
)


@pytest.fixture
def fake_proc(tmp_path, monkeypatch):
    import wholocks._linux as _linux

    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "stat").write_text("cpu 1 2 3\nbtime 1700000000\n")
    monkeypatch.setattr(_linux, "PROC_ROOT", str(proc))
    return proc


def _make_pid(proc_dir, pid, comm="testproc", cmdline=("testproc", "--flag")):
    d = proc_dir / str(pid)
    d.mkdir()
    (d / "comm").write_text(comm + "\n")
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in cmdline) + b"\0")
    stat_fields = "S 1 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 777 100"
    (d / "stat").write_text("%d (%s) %s\n" % (pid, comm, stat_fields))
    (d / "maps").write_text("")
    (d / "fd").mkdir()
    return d


def test_finds_fd_holder(fake_proc, tmp_path):
    import wholocks._linux as _linux

    target = tmp_path / "held.txt"
    target.write_text("data")
    real_target = os.path.realpath(str(target))  # /proc links hold real paths

    pid_dir = _make_pid(fake_proc, 4321)
    os.symlink(real_target, pid_dir / "fd" / "3")
    os.symlink("/", pid_dir / "cwd")
    os.symlink("/usr/bin/testproc", pid_dir / "exe")

    result = _linux.scan([str(target)], [], recursive=False)
    assert len(result.holders) == 1
    h = result.holders[0]
    assert h.pid == 4321
    assert h.name == "testproc"
    assert h.cmdline == "testproc --flag"
    assert h.access == ["fd"]
    assert real_target in h.paths[0]
    assert h.started is not None


def test_finds_cwd_holder_for_directory(fake_proc, tmp_path):
    import wholocks._linux as _linux

    held_dir = tmp_path / "busy-dir"
    held_dir.mkdir()

    pid_dir = _make_pid(fake_proc, 5000, comm="bash")
    os.symlink(os.path.realpath(str(held_dir)), pid_dir / "cwd")

    result = _linux.scan([], [str(held_dir)], recursive=False)
    assert [h.pid for h in result.holders] == [5000]
    assert result.holders[0].access == ["cwd"]


def test_deleted_fd_labelled(fake_proc, tmp_path):
    import wholocks._linux as _linux

    target = tmp_path / "gone.log"
    target.write_text("x")

    pid_dir = _make_pid(fake_proc, 6000, comm="logger")
    # /proc shows deleted-but-open files as "path (deleted)"
    os.symlink(os.path.realpath(str(target)) + " (deleted)", pid_dir / "fd" / "7")

    result = _linux.scan([str(target)], [], recursive=False)
    assert result.holders
    assert result.holders[0].access == ["fd (deleted)"]


def test_mmap_holder_via_maps(fake_proc, tmp_path):
    import wholocks._linux as _linux

    target = tmp_path / "lib.so"
    target.write_text("elf!")

    pid_dir = _make_pid(fake_proc, 7000, comm="loader")
    real = os.path.realpath(str(target))
    (pid_dir / "maps").write_text(
        "7f0000000000-7f0000001000 r-xp 00000000 08:01 12345 %s\n" % real
    )

    result = _linux.scan([str(target)], [], recursive=False)
    assert result.holders
    assert result.holders[0].access == ["mmap"]


def test_unrelated_process_not_reported(fake_proc, tmp_path):
    import wholocks._linux as _linux

    target = tmp_path / "held.txt"
    target.write_text("data")
    other = tmp_path / "other.txt"
    other.write_text("nope")

    pid_dir = _make_pid(fake_proc, 8000)
    os.symlink(os.path.realpath(str(other)), pid_dir / "fd" / "3")

    result = _linux.scan([str(target)], [], recursive=False)
    assert result.holders == []


def test_recursive_dir_match(fake_proc, tmp_path):
    import wholocks._linux as _linux

    deep = tmp_path / "root-dir" / "a" / "b"
    deep.mkdir(parents=True)
    target = deep / "deep.txt"
    target.write_text("x")

    pid_dir = _make_pid(fake_proc, 9000)
    os.symlink(os.path.realpath(str(target)), pid_dir / "fd" / "4")

    non_rec = _linux.scan([], [str(tmp_path / "root-dir")], recursive=False)
    assert non_rec.holders == []

    rec = _linux.scan([], [str(tmp_path / "root-dir")], recursive=True)
    assert [h.pid for h in rec.holders] == [9000]
