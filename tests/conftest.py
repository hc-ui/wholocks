import os
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


HOLD_FILE_SCRIPT = r"""
import sys, time
f = open(sys.argv[1], "r+b")
print("READY", flush=True)
time.sleep(float(sys.argv[2]))
f.close()
"""

MMAP_FILE_SCRIPT = r"""
import mmap, sys, time
f = open(sys.argv[1], "r+b")
m = mmap.mmap(f.fileno(), 0)
print("READY", flush=True)
time.sleep(float(sys.argv[2]))
"""

CWD_SCRIPT = r"""
import sys, time
print("READY", flush=True)
time.sleep(float(sys.argv[1]))
"""


def _spawn(script, path, seconds):
    proc = subprocess.Popen(
        [sys.executable, "-c", script, str(path), str(seconds)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline()
    if "READY" not in line:
        err = proc.stderr.read()
        proc.kill()
        raise RuntimeError("holder child failed to start: %r / %s" % (line, err))
    return proc


@pytest.fixture
def hold_file(tmp_path):
    """Factory: spawn a child process that keeps a file open."""
    children = []

    def _hold(path=None, seconds=120.0, script=HOLD_FILE_SCRIPT):
        if path is None:
            path = tmp_path / "held.txt"
        path = str(path)
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(b"payload")
        proc = _spawn(script, path, seconds)
        children.append(proc)
        return path, proc

    yield _hold
    for proc in children:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


@pytest.fixture
def hold_cwd():
    """Factory: spawn a child whose current working directory is *dirpath*."""
    children = []

    def _hold(dirpath, seconds=120.0):
        proc = subprocess.Popen(
            [sys.executable, "-c", CWD_SCRIPT, str(seconds)],
            cwd=str(dirpath),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = proc.stdout.readline()
        if "READY" not in line:
            err = proc.stderr.read()
            proc.kill()
            raise RuntimeError("cwd child failed to start: %r / %s" % (line, err))
        children.append(proc)
        return proc

    yield _hold
    for proc in children:
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


def run_cli(*argv, input_text=None, timeout=90):
    """Run the wholocks CLI in a subprocess, returns (exit_code, stdout, stderr)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["NO_COLOR"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "wholocks", *[str(a) for a in argv]],
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
        env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def wait_deletable(path, timeout=10.0):
    """Try to delete *path*, retrying while the OS still holds it."""
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            os.remove(path)
            return True
        except OSError as e:
            last_err = e
            time.sleep(0.3)
    raise AssertionError("file still locked after %.0fs: %s" % (timeout, last_err))
