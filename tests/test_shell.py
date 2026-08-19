"""Tests for shell.py — quoting of values interpolated into commands.

These tests use a real ``/bin/sh`` as the oracle rather than asserting on
the quoted text: the property that matters is what the shell does with the
result, not which quoting style produced it.
"""

import shlex
import subprocess

import pytest
from conftest import HOSTILE_PATHS
from shellparse import sh_words

from nine_manage_anubis.shell import heredoc, quote, quote_glob_prefix


# The shared payloads, plus the shapes only this module needs: quote() is the
# one function every command builder funnels through, so it is where the
# separators and the empty string are worth pinning.
HOSTILE = HOSTILE_PATHS + [
    "/home/www-example/x && id",   # and-list
    "/home/www-example/x | id",    # pipe
    "",                         # empty — must not vanish
]


# --- quote --------------------------------------------------------------------


@pytest.mark.parametrize("value", HOSTILE)
def test_quote_survives_a_real_shell_as_one_word(value):
    assert sh_words(quote(value)) == [value]


@pytest.mark.parametrize("value", HOSTILE)
def test_quote_survives_shlex_as_one_word(value):
    # shlex is the oracle the other test modules use — keep the two agreeing.
    assert shlex.split(f"cmd {quote(value)}") == ["cmd", value]


def test_quote_leaves_a_plain_value_readable():
    assert quote("/home/www-example/example.com") == "/home/www-example/example.com"


def test_quote_accepts_an_int():
    assert sh_words(f"--port={quote(7010)}") == ["--port=7010"]


def test_quote_inside_a_flag_keeps_the_flag_and_value_together():
    assert sh_words(f"--webroot={quote('/home/w w/`id`')}") == [
        "--webroot=/home/w w/`id`"
    ]


# --- quote_glob_prefix --------------------------------------------------------


def test_quote_glob_prefix_keeps_the_trailing_star_live(tmp_path):
    (tmp_path / "f.bak.1").write_text("a")
    (tmp_path / "f.bak.2").write_text("b")
    (tmp_path / "other").write_text("c")
    prefix = f"{tmp_path}/f.bak."
    assert sorted(sh_words(quote_glob_prefix(prefix))) == [
        f"{tmp_path}/f.bak.1",
        f"{tmp_path}/f.bak.2",
    ]


def test_quote_glob_prefix_disarms_metacharacters_in_the_prefix(tmp_path):
    weird = tmp_path / "a b`id`"
    weird.mkdir()
    (weird / "f.bak.1").write_text("a")
    assert sh_words(quote_glob_prefix(f"{weird}/f.bak.")) == [
        f"{weird}/f.bak.1"
    ]


def test_quote_glob_prefix_disarms_a_star_inside_the_prefix(tmp_path):
    (tmp_path / "star*name.bak.1").write_text("a")
    (tmp_path / "decoy.bak.1").write_text("b")
    assert sh_words(quote_glob_prefix(f"{tmp_path}/star*name.bak.")) == [
        f"{tmp_path}/star*name.bak.1"
    ]


# --- heredoc ------------------------------------------------------------------


def sh_stdin(command: str) -> str:
    proc = subprocess.run(
        ["/bin/sh", "-c", command], capture_output=True, text=True, check=True
    )
    return proc.stdout


def test_heredoc_delivers_the_body_verbatim():
    body = "line one\n$(id) `id` 'quoted' \"double\"\nline three"
    assert sh_stdin(heredoc("cat", body, "BODY_EOF")) == body + "\n"


def test_heredoc_body_cannot_terminate_the_heredoc():
    # A body line equal to the marker would end the heredoc early and hand
    # everything after it to the shell as commands.
    body = "harmless\nBODY_EOF\nid > /dev/stderr\nmore"
    cmd = heredoc("cat", body, "BODY_EOF")
    proc = subprocess.run(
        ["/bin/sh", "-c", cmd], capture_output=True, text=True, check=True
    )
    assert proc.stdout == body + "\n"
    assert proc.stderr == ""


def test_heredoc_marker_is_stable_when_the_body_is_harmless():
    assert heredoc("cat", "hello", "BODY_EOF") == "cat <<'BODY_EOF'\nhello\nBODY_EOF"


def test_heredoc_body_is_not_expanded_by_the_shell():
    body = "HOME is $HOME"
    assert sh_stdin(heredoc("cat", body, "BODY_EOF")) == "HOME is $HOME\n"
