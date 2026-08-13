"""CLI argument validation and output formatting (in-process, backend mocked)."""

import json

import pytest

import wholocks.cli as cli
from wholocks.core import Holder, ScanResult


@pytest.fixture
def existing_file(tmp_path):
    f = tmp_path / "target.txt"
    f.write_text("x")
    return str(f)


def _fake_find(holders):
    def fake(paths, recursive=False, max_files=10000):
        return ScanResult(
            targets=[str(p) for p in paths],
            holders=list(holders),
            scanned_files=len(paths),
            backend="fake",
        )

    return fake


class TestValidation:
    def test_kill_and_wait_conflict(self, existing_file):
        assert cli.main(["--kill", "--wait", existing_file]) == 2

    def test_timeout_without_wait(self, existing_file):
        assert cli.main(["--timeout", "5", existing_file]) == 2

    def test_negative_timeout(self, existing_file):
        assert cli.main(["--wait", "--timeout", "-1", existing_file]) == 2

    def test_yes_without_kill(self, existing_file):
        assert cli.main(["--yes", existing_file]) == 2

    def test_quiet_kill_without_yes(self, existing_file):
        assert cli.main(["--kill", "--quiet", existing_file]) == 2

    def test_json_quiet_conflict(self, existing_file):
        assert cli.main(["--json", "--quiet", existing_file]) == 2

    def test_bad_max_files(self, existing_file):
        assert cli.main(["--max-files", "0", existing_file]) == 2

    def test_no_paths_is_argparse_error(self):
        with pytest.raises(SystemExit) as exc:
            cli.main([])
        assert exc.value.code == 2


class TestReportOutput:
    def test_free(self, existing_file, monkeypatch, capsys):
        monkeypatch.setattr(cli, "find_holders", _fake_find([]))
        assert cli.main(["--no-color", existing_file]) == 0
        out = capsys.readouterr().out
        assert "not held" in out

    def test_held_shows_pid_and_tip(self, existing_file, monkeypatch, capsys):
        holder = Holder(
            pid=4242,
            name="WINWORD.EXE",
            description="Microsoft Word",
            exe=r"C:\Office\WINWORD.EXE",
            access=["handle"],
            app_type="main_window",
        )
        monkeypatch.setattr(cli, "find_holders", _fake_find([holder]))
        assert cli.main(["--no-color", existing_file]) == 1
        out = capsys.readouterr().out
        assert "4242" in out
        assert "WINWORD.EXE" in out
        assert "~$" in out  # office advice
        assert "--kill" in out  # next-step suggestion

    def test_warnings_shown(self, existing_file, monkeypatch, capsys):
        def fake(paths, recursive=False, max_files=10000):
            return ScanResult(
                targets=list(paths),
                holders=[],
                warnings=["some processes could not be inspected"],
                backend="fake",
            )

        monkeypatch.setattr(cli, "find_holders", fake)
        assert cli.main(["--no-color", existing_file]) == 0
        out = capsys.readouterr().out
        assert "note:" in out

    def test_json_shape(self, existing_file, monkeypatch, capsys):
        holder = Holder(pid=7, name="node", access=["fd"], paths=["/x"])
        monkeypatch.setattr(cli, "find_holders", _fake_find([holder]))
        assert cli.main(["--json", existing_file]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["free"] is False
        assert payload["holders"][0]["pid"] == 7
        assert payload["holders"][0]["advice"]  # node has a tip
        assert "wholocks" in payload


class TestVanishingPaths:
    """A path disappearing mid-action means it is free, not an error."""

    def test_kill_succeeds_when_path_vanishes(self, existing_file, monkeypatch, capsys):
        from wholocks.core import UsageError

        holder = Holder(pid=99999999, name="ghost.exe", access=["handle"])
        calls = {"n": 0}

        def fake(paths, recursive=False, max_files=10000):
            calls["n"] += 1
            if calls["n"] == 1:
                return ScanResult(targets=list(paths), holders=[holder], backend="fake")
            raise UsageError("path does not exist: %s" % paths[0])

        monkeypatch.setattr(cli, "find_holders", fake)
        monkeypatch.setattr(cli, "kill_holder", lambda h, force=False: (True, "terminated"))
        assert cli.main(["--kill", "--yes", "--no-color", existing_file]) == 0
        out = capsys.readouterr().out
        assert "now free" in out

    def test_wait_succeeds_when_path_vanishes(self, existing_file, monkeypatch):
        import wholocks.core as core
        from wholocks.core import UsageError

        holder = Holder(pid=99999999, name="ghost.exe", access=["handle"])
        calls = {"n": 0}

        def fake(paths, recursive=False, max_files=10000):
            calls["n"] += 1
            if calls["n"] == 1:
                return ScanResult(targets=list(paths), holders=[holder], backend="fake")
            raise UsageError("path does not exist: %s" % paths[0])

        monkeypatch.setattr(core, "find_holders", fake)
        became_free, waited = core.wait_until_free([existing_file], timeout=10)
        assert became_free is True

    def test_wait_typo_still_fails_loudly(self, tmp_path):
        import wholocks.core as core
        from wholocks.core import UsageError

        with pytest.raises(UsageError):
            core.wait_until_free([str(tmp_path / "never-existed.txt")], timeout=1)
