"""Every remote write, executed for real, with content that used to break out.

Heredoc terminators used to be fixed strings — ``FILE_EOF``, ``KEY_EOF``,
``NINE_SU_EOF`` — so a file whose content held one of them on a line ended the
heredoc early and had the rest of itself parsed by the shell as commands, as
the website user. The reachable path is the fixup installer: it reads a
customer's ``.htaccess`` or ``.user.ini`` and writes it back with our block on
top, so the content is the site owner's, not ours.

These tests run the generated commands through a real ``/bin/sh`` (see
:mod:`shellrunner`) rather than asserting on command text. The question is what
a shell does, so a shell answers it: the file must hold what we asked for, and
the payload must not have run.
"""

import os
import stat
from pathlib import Path

import pytest
from conftest import TERMINATORS
from shellrunner import ShellRunner

from nine_manage_anubis import config
from nine_manage_anubis.fileops import RemoteFileOps
from nine_manage_anubis.fixups import HTACCESS_BLOCK, HTACCESS_BLOCK_START, apply
from nine_manage_anubis.nine_su import nine_su_read_file, nine_su_write_file
from nine_manage_anubis.systemd import (
    write_env_file,
    write_key_file,
    write_systemd_template,
)

USER = "www-example"


def payload(tmp_path: Path, terminator: str) -> tuple[str, Path]:
    """Content that would run ``touch <probe>`` if it escaped its heredoc."""
    probe = tmp_path / "escaped"
    content = (
        "# harmless first line\n"
        f"{terminator}\n"
        f"touch {probe}\n"
        "# harmless last line\n"
    )
    return content, probe


def assert_nothing_escaped(runner: ShellRunner, probe: Path) -> None:
    assert not probe.exists(), "the payload ran: content escaped its heredoc"
    assert runner.ran_nothing_unexpected(), f"shell complained: {runner.stderr}"


# --- File writes --------------------------------------------------------------


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_write_file_delivers_content_holding_a_terminator(tmp_path, terminator):
    content, probe = payload(tmp_path, terminator)
    target = tmp_path / "webroot" / ".htaccess"
    r = ShellRunner()

    nine_su_write_file(USER, str(target), content, r)

    assert target.read_text() == content
    assert_nothing_escaped(r, probe)


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_read_file_returns_content_holding_a_terminator(tmp_path, terminator):
    content, _ = payload(tmp_path, terminator)
    target = tmp_path / ".user.ini"
    target.write_text(content)
    r = ShellRunner()

    assert nine_su_read_file(USER, str(target), r) == content


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_write_file_round_trips_content_holding_a_terminator(tmp_path, terminator):
    content, probe = payload(tmp_path, terminator)
    target = tmp_path / ".user.ini"
    r = ShellRunner()

    nine_su_write_file(USER, str(target), content, r)

    assert nine_su_read_file(USER, str(target), r) == content
    assert_nothing_escaped(r, probe)


def test_write_file_overwrites_a_read_only_file(tmp_path):
    # .htaccess at 444 is the case the chmod u+w in the script exists for, and
    # a real shell is the only thing that can confirm it.
    target = tmp_path / ".htaccess"
    target.write_text("old\n")
    target.chmod(0o444)
    r = ShellRunner()

    nine_su_write_file(USER, str(target), "new\n", r)

    assert target.read_text() == "new\n"


# --- Key writes ---------------------------------------------------------------


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_key_write_delivers_content_holding_a_terminator(tmp_path, terminator):
    content, probe = payload(tmp_path, terminator)
    target = tmp_path / "anubis-key"
    r = ShellRunner()

    write_key_file(USER, str(target), content, runner=r)

    assert target.read_text() == content
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    assert_nothing_escaped(r, probe)


# --- Env writes ---------------------------------------------------------------


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_env_write_delivers_content_holding_a_terminator(tmp_path, terminator):
    content, probe = payload(tmp_path, terminator)
    target = tmp_path / "anubis" / "example.com.env"
    r = ShellRunner()

    write_env_file(USER, str(target), content, runner=r)

    assert target.read_text() == content
    assert_nothing_escaped(r, probe)


def test_env_write_delivers_a_generated_env_file_verbatim(tmp_path):
    # The generated content is ours, but its values are not: the target host
    # and policy path come from a vhost record and the config file.
    target = tmp_path / "example.com.env"
    content = config.generate_env_file(
        config.AnubisConfig(
            domain="example.com",
            app_port=7010,
            metrics_port=7011,
            anubis_user="www-anubis",
            key_path="/home/www-anubis/.config/anubis/key.hex",
        ),
        policy_file="/home/www-anubis/.config/anubis/botPolicies.yaml",
    )
    r = ShellRunner()

    write_env_file(USER, str(target), content, runner=r)

    assert target.read_text() == content


# --- The systemd unit template ------------------------------------------------


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_systemd_template_write_delivers_content_holding_a_terminator(
    tmp_path, terminator, monkeypatch
):
    content, probe = payload(tmp_path, terminator)
    target = tmp_path / ".config" / "systemd" / "user" / "anubis@.service"
    monkeypatch.setattr(config, "systemd_template_path", lambda user: str(target))
    r = ShellRunner()

    write_systemd_template(USER, content, runner=r)

    assert target.read_text() == content
    assert_nothing_escaped(r, probe)


def test_systemd_template_write_delivers_the_real_unit_verbatim(tmp_path, monkeypatch):
    target = tmp_path / "anubis@.service"
    monkeypatch.setattr(config, "systemd_template_path", lambda user: str(target))
    r = ShellRunner()

    write_systemd_template(USER, config.SYSTEMD_TEMPLATE, runner=r)

    assert target.read_text() == config.SYSTEMD_TEMPLATE


# --- The reachable path: fixups on a customer's own .htaccess -----------------


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_fixups_round_trip_an_htaccess_holding_a_terminator(tmp_path, terminator):
    webroot = tmp_path / "webroot"
    webroot.mkdir()
    original, probe = payload(tmp_path, terminator)
    (webroot / ".htaccess").write_text(original)
    r = ShellRunner()
    ops = RemoteFileOps(USER, r)

    apply(str(webroot), ops)

    text = ops.read(str(webroot / ".htaccess"))
    assert text is not None
    assert text.startswith(HTACCESS_BLOCK_START)
    assert HTACCESS_BLOCK in text
    assert original in text
    assert_nothing_escaped(r, probe)


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_fixups_round_trip_a_user_ini_holding_a_terminator(tmp_path, terminator):
    webroot = tmp_path / "webroot"
    webroot.mkdir()
    original, probe = payload(tmp_path, terminator)
    (webroot / ".user.ini").write_text(original)
    r = ShellRunner()
    ops = RemoteFileOps(USER, r)

    apply(str(webroot), ops)

    text = ops.read(str(webroot / ".user.ini"))
    assert text is not None
    assert original in text
    assert "auto_prepend_file" in text
    assert_nothing_escaped(r, probe)


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_fixups_back_up_the_original_htaccess_intact(tmp_path, terminator):
    webroot = tmp_path / "webroot"
    webroot.mkdir()
    original, probe = payload(tmp_path, terminator)
    (webroot / ".htaccess").write_text(original)
    r = ShellRunner()
    ops = RemoteFileOps(USER, r)

    apply(str(webroot), ops)

    backups = ops.glob_backups(str(webroot / ".htaccess"))
    assert len(backups) == 1
    assert ops.read(backups[0]) == original
    assert_nothing_escaped(r, probe)
