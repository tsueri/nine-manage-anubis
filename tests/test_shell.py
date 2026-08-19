"""Tests for shell.py — quoting of values interpolated into commands.

These tests use a real ``/bin/sh`` as the oracle rather than asserting on
the quoted text: the property that matters is what the shell does with the
result, not which quoting style produced it.
"""

import re
import shlex
import subprocess

import pytest
from conftest import HOSTILE_PATHS
from shellparse import sh_words

from nine_manage_anubis import shell
from nine_manage_anubis.shell import (
    HeredocCollision,
    heredoc,
    quote,
    quote_glob_prefix,
    strip_delimiter_nonces,
)


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


def delimiter_of(command: str) -> str:
    match = re.search(r"<<'([^']+)'", command)
    assert match, f"not a heredoc command: {command!r}"
    return match.group(1)


def test_heredoc_delivers_the_body_verbatim():
    body = "line one\n$(id) `id` 'quoted' \"double\"\nline three"
    assert sh_stdin(heredoc("cat", body, "BODY_EOF")) == body + "\n"


def test_heredoc_body_is_not_expanded_by_the_shell():
    body = "HOME is $HOME"
    assert sh_stdin(heredoc("cat", body, "BODY_EOF")) == "HOME is $HOME\n"


def test_heredoc_does_not_add_a_line_to_a_body_that_ends_in_a_newline():
    # File content almost always ends in a newline, and a heredoc always ends
    # its last line — so appending one unconditionally left every file this
    # tool writes with a blank line the caller never asked for.
    assert sh_stdin(heredoc("cat", "one\ntwo\n", "BODY_EOF")) == "one\ntwo\n"


def test_heredoc_terminates_a_body_that_does_not_end_in_a_newline():
    # The delimiter has to start a line, so a body without a trailing newline
    # gets one. That is the heredoc's own limit, not a choice.
    assert sh_stdin(heredoc("cat", "one\ntwo", "BODY_EOF")) == "one\ntwo\n"


def test_heredoc_delivers_an_empty_body_as_nothing():
    assert sh_stdin(heredoc("cat", "", "BODY_EOF")) == ""


@pytest.mark.parametrize("body", ["hello", "harmless\nBODY_EOF\nid > /dev/stderr"])
def test_heredoc_delimiter_is_fresh_on_every_invocation(body):
    # Not derived from the body, and not reused: the same body twice gets two
    # different delimiters, so no content can be written to match one.
    first = delimiter_of(heredoc("cat", body, "BODY_EOF"))
    second = delimiter_of(heredoc("cat", body, "BODY_EOF"))
    assert first != second


def test_heredoc_delimiter_keeps_the_prefix_readable():
    # The nonce is what makes it unguessable; the prefix is what makes a
    # command in a log or an error message legible.
    assert delimiter_of(heredoc("cat", "hello", "BODY_EOF")).startswith("BODY_EOF")


def test_heredoc_delimiter_is_unguessable():
    # 128 bits of it, so guessing beats content-dependent escaping.
    nonce = delimiter_of(heredoc("cat", "hello", "BODY_EOF"))[len("BODY_EOF"):]
    assert re.fullmatch(r"_[0-9a-f]{32}", nonce)


def test_heredoc_body_cannot_terminate_the_heredoc():
    # A body line equal to the delimiter would end the heredoc early and hand
    # everything after it to the shell as commands. The old fixed delimiters
    # were guessable, so a body line naming one is the attack.
    body = "harmless\nBODY_EOF\nid > /dev/stderr\nmore"
    cmd = heredoc("cat", body, "BODY_EOF")
    proc = subprocess.run(
        ["/bin/sh", "-c", cmd], capture_output=True, text=True, check=True
    )
    assert proc.stdout == body + "\n"
    assert proc.stderr == ""


def test_heredoc_refuses_a_body_that_holds_its_delimiter(monkeypatch):
    # Unreachable in practice — it needs the nonce to be guessed — but if the
    # body ever does contain the delimiter, refusing is the only safe answer:
    # writing it would run the rest of the body as commands.
    monkeypatch.setattr(shell, "fresh_delimiter", lambda prefix: f"{prefix}_known")
    with pytest.raises(HeredocCollision) as excinfo:
        heredoc("cat", "harmless\nBODY_EOF_known\nid", "BODY_EOF")
    assert "BODY_EOF_known" in str(excinfo.value)


def test_heredoc_refuses_rather_than_retrying_with_another_delimiter(monkeypatch):
    # Retrying would make the delimiter a function of the body again.
    monkeypatch.setattr(shell, "fresh_delimiter", lambda prefix: f"{prefix}_known")
    with pytest.raises(HeredocCollision):
        heredoc("cat", "BODY_EOF_known", "BODY_EOF")


# --- strip_delimiter_nonces ---------------------------------------------------


def test_strip_delimiter_nonces_leaves_the_bare_prefix():
    cmd = heredoc("cat", "hello", "BODY_EOF")
    assert strip_delimiter_nonces(cmd) == "cat <<'BODY_EOF'\nhello\nBODY_EOF"


def test_strip_delimiter_nonces_folds_both_layers_of_a_nested_heredoc():
    inner = heredoc("cat > /tmp/f", "content", "FILE_EOF")
    outer = heredoc("sudo nine-su www-example", inner, "NINE_SU_EOF")
    assert strip_delimiter_nonces(outer) == (
        "sudo nine-su www-example <<'NINE_SU_EOF'\n"
        "cat > /tmp/f <<'FILE_EOF'\n"
        "content\n"
        "FILE_EOF\n"
        "NINE_SU_EOF"
    )


def test_strip_delimiter_nonces_leaves_a_body_that_mentions_the_delimiter_alone(
    monkeypatch,
):
    # Content is content, even when it names the delimiter carrying it: only
    # the `<<'...'` and the line that closes it are syntax. A fixed nonce, so
    # the body can mention the very delimiter it travels under.
    nonce = "ab" * 16
    monkeypatch.setattr(shell, "fresh_delimiter", lambda prefix: f"{prefix}_{nonce}")
    body = f"echo BODY_EOF_{nonce}\nRewriteEngine On"
    folded = strip_delimiter_nonces(heredoc("cat", body, "BODY_EOF"))
    assert folded == f"cat <<'BODY_EOF'\n{body}\nBODY_EOF"


def test_strip_delimiter_nonces_survives_a_body_that_looks_like_a_heredoc():
    # A webroot file may contain anything, including a line that opens a
    # heredoc of its own. Taking that for one of ours would lose track of the
    # delimiter actually in force, and leave the real one unfolded.
    body = "RewriteRule x <<'FOO'\nRewriteEngine On"
    folded = strip_delimiter_nonces(heredoc("cat", body, "BODY_EOF"))
    assert folded == f"cat <<'BODY_EOF'\n{body}\nBODY_EOF"


def test_strip_delimiter_nonces_leaves_a_command_without_a_heredoc_alone():
    assert strip_delimiter_nonces("openssl rand -hex 32") == "openssl rand -hex 32"
