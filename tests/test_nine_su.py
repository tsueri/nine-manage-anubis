"""Tests for nine_su.py — the heredoc wrapper and its quoting.

Two shells parse a ``nine-su`` command: the local one, which sees
``sudo nine-su <user>`` and a quoted heredoc delimiter, and the far-side one,
which re-parses the script body. Both layers are asserted here — the local one
via :func:`su_argv`, the far side via :func:`script_argv`.
"""

import posixpath

import pytest
from conftest import HOSTILE_PATHS
from shellparse import script_argv, sh_words, sh_words_after, su_argv, su_script

from nine_manage_anubis.nine_su import (
    nine_su,
    nine_su_backup,
    nine_su_file_exists,
    nine_su_glob_prefix,
    nine_su_read_file,
    nine_su_systemd,
    nine_su_unlink,
    nine_su_write_file,
)
from nine_manage_anubis.runner import FakeRunner


def test_nine_su_runs_the_script_under_the_user():
    r = FakeRunner()
    nine_su("www-example", "echo hi", r)
    assert su_argv(r.calls[0]) == ["sudo", "nine-su", "www-example"]
    assert su_script(r.calls[0]) == "echo hi"


def test_nine_su_quotes_the_user():
    r = FakeRunner()
    nine_su("www example`id`", "echo hi", r)
    assert su_argv(r.calls[0]) == ["sudo", "nine-su", "www example`id`"]


def test_nine_su_script_cannot_terminate_the_heredoc():
    # A script line equal to the delimiter would end the heredoc early and
    # hand the rest of the script to the *local* root shell.
    r = FakeRunner()
    nine_su("www-example", "echo hi\nNINE_SU_EOF\nid", r)
    assert su_script(r.calls[0]) == "echo hi\nNINE_SU_EOF\nid"


def test_nine_su_systemd_sets_the_runtime_dir():
    r = FakeRunner()
    nine_su_systemd("www-anubis", "systemctl --user daemon-reload", r)
    script = su_script(r.calls[0])
    assert script.startswith("export XDG_RUNTIME_DIR=/run/user/$(id -u)")
    assert "systemctl --user daemon-reload" in script


# --- File operations ----------------------------------------------------------


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_read_file_quotes_the_path(path):
    r = FakeRunner()
    nine_su_read_file("www-example", path, r)
    assert path in script_argv(r.calls[0])


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_write_file_quotes_the_path(path):
    r = FakeRunner()
    nine_su_write_file("www-example", path, "content\n", r)
    # Once to grant write permission, once as the redirect target.
    assert script_argv(r.calls[0]).count(path) == 2


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_write_file_creates_the_parent_directory(path):
    r = FakeRunner()
    nine_su_write_file("www-example", path, "x\n", r)
    words = script_argv(r.calls[0])
    assert words[:3] == ["mkdir", "-p", "--"]
    assert words[3] == posixpath.dirname(path)


def test_write_file_delivers_the_content_verbatim():
    r = FakeRunner()
    nine_su_write_file("www-example", "/home/www-example/f.txt", "a 'b' `c`\n$(d)", r)
    assert "a 'b' `c`\n$(d)" in su_script(r.calls[0])


def test_write_file_content_cannot_terminate_its_heredoc():
    # Webroot files are attacker-controlled: restoring one whose content holds
    # a line equal to the delimiter would run the rest as the website user.
    r = FakeRunner()
    nine_su_write_file("www-example", "/home/www-example/.user.ini", "FILE_EOF\nid", r)
    assert "FILE_EOF\nid" in su_script(r.calls[0])
    assert script_argv(r.calls[0]).count("id") == 0


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_file_exists_quotes_the_path(path):
    r = FakeRunner()
    nine_su_file_exists("www-example", path, r)
    assert path in script_argv(r.calls[0])


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_unlink_quotes_the_path(path):
    r = FakeRunner()
    nine_su_unlink("www-example", path, r)
    assert script_argv(r.calls[0]) == ["rm", "-f", "--", path]


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_unlink_hands_a_real_shell_one_path_argument(path):
    # The far side is a real shell, so a real shell decides whether the `$( )`
    # and backtick payloads stayed inert.
    r = FakeRunner()
    nine_su_unlink("www-example", path, r)
    assert sh_words_after(su_script(r.calls[0]), "rm -f -- ") == [path]


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_glob_prefix_hands_a_real_shell_one_pattern_argument(path, tmp_path):
    r = FakeRunner()
    nine_su_glob_prefix("www-example", f"{path}.anubis-bak.", r)
    script = su_script(r.calls[0])
    pattern = script[len("ls -1d -- "):].split(" 2>/dev/null")[0]
    # Nothing matches the prefix on this machine, so the shell leaves the
    # pattern as the single word it was given.
    assert sh_words(pattern) == [f"{path}.anubis-bak.*"]


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_backup_quotes_both_paths(path):
    r = FakeRunner()
    nine_su_backup("www-example", path, r)
    words = script_argv(r.calls[0])
    assert path in words
    backups = [w for w in words if w.startswith(f"{path}.anubis-bak.")]
    assert len(backups) == 2  # the cp destination, and the name echoed back


def test_backup_returns_the_backup_path():
    r = FakeRunner({"sudo nine-su": "/home/www-example/f.anubis-bak.123\n"})
    assert nine_su_backup("www-example", "/home/www-example/f", r) == (
        "/home/www-example/f.anubis-bak.123"
    )


def test_backup_returns_none_when_nothing_was_copied():
    r = FakeRunner({"sudo nine-su": "\n"})
    assert nine_su_backup("www-example", "/home/www-example/f", r) is None


# --- Globbing -----------------------------------------------------------------


def test_glob_prefix_leaves_only_the_trailing_star_live():
    r = FakeRunner()
    nine_su_glob_prefix("www-example", "/home/www example/.user.ini.anubis-bak.", r)
    script = su_script(r.calls[0])
    assert "'/home/www example/.user.ini.anubis-bak.'*" in script


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_glob_prefix_quotes_the_prefix(path):
    r = FakeRunner()
    nine_su_glob_prefix("www-example", f"{path}.anubis-bak.", r)
    words = script_argv(r.calls[0])
    assert f"{path}.anubis-bak.*" in words


def test_glob_prefix_returns_one_path_per_line():
    r = FakeRunner({"sudo nine-su": "/home/x/f.anubis-bak.1\n/home/x/f.anubis-bak.2\n"})
    assert nine_su_glob_prefix("www-example", "/home/x/f.anubis-bak.", r) == [
        "/home/x/f.anubis-bak.1",
        "/home/x/f.anubis-bak.2",
    ]


def test_glob_prefix_tolerates_no_matches():
    r = FakeRunner({"sudo nine-su": ""})
    assert nine_su_glob_prefix("www-example", "/home/x/f.anubis-bak.", r) == []
