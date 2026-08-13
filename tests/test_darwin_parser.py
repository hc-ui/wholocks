"""The lsof field-output parser is pure text processing - test it everywhere."""

from wholocks._darwin import parse_lsof_field_output

SAMPLE = """\
p123
cVim
u501
f3
n/Users/me/notes/todo.txt
p456
cFinder
u501
fcwd
n/Users/me/held-dir
ftxt
n/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
p789
cmdworker
u0
fmem
n/Users/me/held-dir/data.bin
"""


def test_parses_processes_and_access():
    holders = parse_lsof_field_output(SAMPLE)
    assert [h.pid for h in holders] == [123, 456, 789]

    vim = holders[0]
    assert vim.name == "Vim"
    assert vim.user == "501"
    assert vim.access == ["fd"]
    assert vim.paths == ["/Users/me/notes/todo.txt"]

    finder = holders[1]
    assert set(finder.access) == {"cwd", "exe"}

    worker = holders[2]
    assert worker.access == ["mmap"]


def test_match_filter_drops_unrelated_paths():
    match = lambda p: p.startswith("/Users/me/held-dir")  # noqa: E731
    holders = parse_lsof_field_output(SAMPLE, match)
    assert [h.pid for h in holders] == [456, 789]
    finder = holders[0]
    assert finder.access == ["cwd"]  # the txt path was filtered out
    assert finder.paths == ["/Users/me/held-dir"]


def test_tolerates_garbage_and_empty_lines():
    text = "p12\ncX\n\nzunknown-tag\nf7\nn/tmp/a\npNOTANUMBER\nf3\nn/tmp/b\n"
    holders = parse_lsof_field_output(text)
    assert len(holders) == 1
    assert holders[0].pid == 12
    assert holders[0].paths == ["/tmp/a"]


def test_numeric_fd_with_mode_suffix():
    text = "p5\ncY\nf10u\nn/tmp/c\n"
    holders = parse_lsof_field_output(text)
    assert holders[0].access == ["fd"]


def test_deleted_mmap_label():
    text = "p6\ncZ\nfDEL\nn/tmp/gone.so\n"
    holders = parse_lsof_field_output(text)
    assert holders[0].access == ["mmap (deleted)"]
