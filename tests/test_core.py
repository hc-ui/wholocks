"""Unit tests for the platform-independent core."""

import os
import sys

import pytest

from wholocks.core import (
    Holder,
    UsageError,
    advice_for,
    dedupe_holders,
    kill_block_reason,
    make_matcher,
    split_targets,
)


class TestSplitTargets:
    def test_missing_path_raises(self, tmp_path):
        with pytest.raises(UsageError):
            split_targets([str(tmp_path / "nope.txt")])

    def test_split(self, tmp_path):
        f = tmp_path / "a.txt"
        f.write_text("x")
        files, dirs = split_targets([str(f), str(tmp_path)])
        assert files == [str(f)]
        assert dirs == [str(tmp_path)]


class TestDedupe:
    def test_merges_by_pid(self):
        a = Holder(pid=7, name="x", access=["fd"], paths=["/a"])
        b = Holder(pid=7, name="", access=["cwd"], paths=["/b"], user="u")
        merged = dedupe_holders([a, b])
        assert len(merged) == 1
        h = merged[0]
        assert h.name == "x"
        assert h.user == "u"
        assert set(h.access) == {"fd", "cwd"}
        assert set(h.paths) == {"/a", "/b"}

    def test_sorted_by_pid(self):
        out = dedupe_holders([Holder(pid=9), Holder(pid=2)])
        assert [h.pid for h in out] == [2, 9]


@pytest.mark.skipif(sys.platform.startswith("win"), reason="matcher is used by the POSIX backends")
class TestMatcher:
    def test_exact_file(self, tmp_path):
        f = tmp_path / "t.txt"
        f.write_text("x")
        match = make_matcher([str(f)], [], recursive=False)
        assert match(os.path.realpath(str(f)))
        assert not match(str(tmp_path / "other.txt"))

    def test_dir_immediate_children(self, tmp_path):
        d = tmp_path / "d"
        (d / "sub").mkdir(parents=True)
        match = make_matcher([], [str(d)], recursive=False)
        real = os.path.realpath(str(d))
        assert match(real)
        assert match(real + "/child.txt")
        assert not match(real + "/sub/deeper.txt")

    def test_dir_recursive(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        match = make_matcher([], [str(d)], recursive=True)
        real = os.path.realpath(str(d))
        assert match(real + "/sub/deeper.txt")
        assert not match(real + "-sibling/file.txt")


class TestAdvice:
    def test_office_tip_mentions_lock_file(self):
        h = Holder(pid=1, name="WINWORD.EXE")
        assert "~$" in advice_for(h)

    def test_onedrive(self):
        h = Holder(pid=1, name="OneDrive.exe")
        assert "sync" in advice_for(h).lower()

    def test_node_orphan(self):
        h = Holder(pid=1, name="node")
        assert "dev-server" in advice_for(h)

    def test_unknown_gets_none(self):
        assert advice_for(Holder(pid=1, name="myrandomapp.exe")) is None

    def test_database_warns_against_kill(self):
        h = Holder(pid=1, name="postgres")
        assert "corrupt" in advice_for(h)

    def test_shells_get_cwd_tip(self):
        for shell in ("cmd.exe", "powershell.exe", "bash", "zsh"):
            tip = advice_for(Holder(pid=1, name=shell))
            assert tip and "terminal" in tip

    def test_kernel_system_process(self):
        h = Holder(pid=4, name="System")
        assert "kernel" in advice_for(h)


class TestKillSafety:
    def test_refuses_critical(self):
        h = Holder(pid=1234, name="csrss.exe", app_type="critical")
        assert kill_block_reason(h) is not None

    def test_refuses_low_pid(self):
        h = Holder(pid=1, name="init")
        assert kill_block_reason(h) is not None

    def test_refuses_self(self):
        h = Holder(pid=os.getpid(), name="python")
        assert kill_block_reason(h) is not None

    def test_service_requires_force(self):
        h = Holder(pid=5555, name="svc.exe", app_type="service")
        assert kill_block_reason(h, force=False) is not None
        assert kill_block_reason(h, force=True) is None

    def test_normal_process_allowed(self):
        h = Holder(pid=44444, name="node.exe", app_type="console")
        assert kill_block_reason(h) is None
