"""Tests for systemd.py — service management via nine-su heredoc."""

import posixpath

import pytest
from conftest import HOSTILE_PATHS, TERMINATORS
from shellparse import script_argv, sh_words_after, su_argv, su_script

from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.systemd import (
    daemon_reload,
    enable_service,
    disable_service,
    restart_service,
    is_active,
    write_systemd_template,
    template_exists,
    remove_systemd_template,
    write_env_file,
    write_key_file,
    remove_file,
    file_exists,
    generate_key,
    binary_exists,
    binary_version,
    download_binary,
    extract_policy,
    get_latest_version,
    DOWNLOAD_TIMEOUT,
    RELEASE_QUERY_TIMEOUT,
    SERVICE_TIMEOUT,
)
from nine_manage_anubis.config import SYSTEMD_TEMPLATE

_SU = "sudo nine-su www-anubis <<'NINE_SU_EOF'"


def _su_calls(r: FakeRunner) -> list[str]:
    # The delimiter carries a per-invocation nonce, so match the part of the
    # command that does not: the nine-su call itself.
    return [c for c in r.calls if c.startswith("sudo nine-su www-anubis <<")]


# --- Service operations -------------------------------------------------------


def test_daemon_reload():
    r = FakeRunner()
    daemon_reload("www-anubis", runner=r)
    assert len(_su_calls(r)) == 1
    assert "XDG_RUNTIME_DIR" in r.calls[0]
    assert "daemon-reload" in r.calls[0]


def test_enable_service():
    r = FakeRunner()
    enable_service("www-anubis", "example.com", runner=r)
    cmd = r.calls[0]
    assert "enable --now anubis@example.com.service" in cmd
    assert "XDG_RUNTIME_DIR" in cmd


def test_disable_service():
    r = FakeRunner()
    disable_service("www-anubis", "example.com", runner=r)
    assert "disable --now anubis@example.com.service" in r.calls[0]


def test_restart_service():
    r = FakeRunner()
    restart_service("www-anubis", "example.com", runner=r)
    assert "restart anubis@example.com.service" in r.calls[0]


def test_is_active():
    r = FakeRunner()
    # is_active calls nine_su_systemd which returns the runner output
    r.responses[_SU + "\nexport XDG_RUNTIME_DIR"] = "active\n"
    result = is_active("www-anubis", "example.com", runner=r)
    assert result == "active"


def test_is_active_inactive():
    r = FakeRunner()
    r.responses[_SU + "\nexport XDG_RUNTIME_DIR"] = "inactive\n"
    result = is_active("www-anubis", "example.com", runner=r)
    assert result == "inactive"


def test_is_active_tolerates_nonzero_exit():
    """`systemctl is-active` exits 3 for any non-active unit.

    Without failure tolerance the Runner raises RuntimeError instead of
    reporting the state, which breaks every health check.
    """
    r = FakeRunner()
    is_active("www-anubis", "example.com", runner=r)
    assert "is-active anubis@example.com.service || true" in r.calls[0]


def test_is_active_failed():
    r = FakeRunner()
    r.responses[_SU + "\nexport XDG_RUNTIME_DIR"] = "failed\n"
    assert is_active("www-anubis", "example.com", runner=r) == "failed"


# --- Template operations ------------------------------------------------------


def test_write_systemd_template():
    r = FakeRunner()
    write_systemd_template("www-anubis", SYSTEMD_TEMPLATE, runner=r)
    cmd = r.calls[0]
    assert "anubis@.service" in cmd
    assert "cat >" in cmd
    assert "Anubis bot protection" in cmd


def test_template_exists_true():
    r = FakeRunner()
    r.responses[_SU] = "yes\n"
    assert template_exists("www-anubis", runner=r)


def test_template_exists_false():
    r = FakeRunner()
    r.responses[_SU] = "no\n"
    assert not template_exists("www-anubis", runner=r)


def test_remove_systemd_template():
    r = FakeRunner()
    remove_systemd_template("www-anubis", runner=r)
    assert "rm -f" in r.calls[0]
    assert "anubis@.service" in r.calls[0]


# --- File operations ----------------------------------------------------------


def test_write_env_file():
    r = FakeRunner()
    write_env_file("www-anubis", "/home/www-anubis/.config/anubis/test.env", "BIND=:7010\n", runner=r)
    cmd = r.calls[0]
    assert "cat >" in cmd
    assert "/home/www-anubis/.config/anubis/test.env" in cmd
    assert "BIND=:7010" in cmd


def test_write_key_file():
    r = FakeRunner()
    write_key_file("www-anubis", "/home/www-anubis/.config/anubis/test.key", "abc123", runner=r)
    cmd = r.calls[0]
    assert "umask 177" in cmd
    assert "abc123" in cmd


def test_remove_file():
    r = FakeRunner()
    remove_file("www-anubis", "/path/to/file", runner=r)
    assert "rm -f" in r.calls[0]
    assert "/path/to/file" in r.calls[0]


def test_file_exists_true():
    r = FakeRunner()
    r.responses[_SU] = "yes\n"
    assert file_exists("www-anubis", "/some/path", runner=r)


def test_file_exists_false():
    r = FakeRunner()
    r.responses[_SU] = "no\n"
    assert not file_exists("www-anubis", "/some/path", runner=r)


def test_generate_key():
    r = FakeRunner({"openssl rand -hex 32": "deadbeef\n"})
    key = generate_key(r)
    assert key == "deadbeef"


# --- Binary operations --------------------------------------------------------


def test_binary_exists_true():
    r = FakeRunner()
    r.responses[_SU] = "yes\n"
    assert binary_exists("www-anubis", runner=r)


def test_binary_exists_false():
    r = FakeRunner()
    r.responses[_SU] = "no\n"
    assert not binary_exists("www-anubis", runner=r)


def test_binary_version():
    r = FakeRunner()
    r.responses[_SU] = "Anubis version 1.27.0\n"
    v = binary_version("www-anubis", runner=r)
    assert "1.27.0" in v


def test_download_binary():
    r = FakeRunner()
    r.responses[_SU] = "Anubis version 1.27.0\n"
    download_binary("www-anubis", "1.27.0", runner=r)
    cmd = r.calls[0]
    assert "curl -sLO" in cmd
    assert "anubis-1.27.0-linux-amd64.tar.gz" in cmd
    assert "tar xzf" in cmd
    assert "cp anubis-1.27.0-linux-amd64/bin/anubis ~/bin/" in cmd
    assert "chmod +x" in cmd


def test_get_latest_version():
    r = FakeRunner({
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest":
            '{"tag_name": "v1.27.0", "name": "v1.27.0"}',
    })
    assert get_latest_version(r) == "1.27.0"


def test_get_latest_version_asks_one_program_so_a_failure_names_it():
    # A pipeline exits with its last command's status, so `curl | grep` reported
    # curl as the program that failed whenever grep was the one that found
    # nothing.
    r = FakeRunner({
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest":
            '{"tag_name": "v1.27.0"}',
    })
    get_latest_version(r)
    assert "|" not in r.calls[0]


# --- Quoting -------------------------------------------------------------------
#
# Instance names and paths are interpolated into a script the far-side shell
# re-parses. Paths are outside any whitelist, so quoting is what keeps them
# from ending the command they sit in.


HOSTILE_USER = "www example`id`"
HOSTILE_INSTANCE = "example.com; id"


# Service operations


@pytest.mark.parametrize(
    "call",
    [enable_service, disable_service, restart_service, is_active],
)
def test_service_functions_quote_the_user_and_instance(call):
    r = FakeRunner()
    call(HOSTILE_USER, HOSTILE_INSTANCE, runner=r)
    assert su_argv(r.calls[0]) == ["sudo", "nine-su", HOSTILE_USER]
    assert f"anubis@{HOSTILE_INSTANCE}.service" in script_argv(r.calls[0])


# File operations


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_write_env_file_quotes_the_path(path):
    r = FakeRunner()
    write_env_file("www-anubis", path, "BIND=:7010\n", runner=r)
    words = script_argv(r.calls[0])
    assert posixpath.dirname(path) in words
    assert path in words
    assert "BIND=:7010" in su_script(r.calls[0])


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_write_env_file_content_cannot_terminate_its_heredoc(terminator):
    r = FakeRunner()
    write_env_file(
        "www-anubis", "/home/www-anubis/e.env", f"BIND=:7010\n{terminator}\nid", runner=r
    )
    assert f"{terminator}\nid" in su_script(r.calls[0])
    assert "id" not in script_argv(r.calls[0])


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_write_key_file_quotes_the_path(path):
    r = FakeRunner()
    write_key_file("www-anubis", path, "deadbeef", runner=r)
    words = script_argv(r.calls[0])
    assert posixpath.dirname(path) in words
    # Any leftover removed, then written — the same single argument each time.
    assert words.count(path) == 2


@pytest.mark.parametrize("write", [write_env_file, write_key_file])
def test_the_instances_own_files_are_restricted_in_one_round_trip(write):
    # One round trip, because a second one is a window: between two nine-su
    # calls the file sits on disk at whatever the host's umask allowed. Where
    # inside the script the mode is settled is test_nine_su's business; that
    # there is only one script is this one's.
    r = FakeRunner()
    write("www-anubis", "/home/www-anubis/.config/anubis/example.com", "x\n", runner=r)
    assert len(r.calls) == 1
    assert "umask 177" in su_script(r.calls[0]).splitlines()


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_write_key_file_content_cannot_terminate_its_heredoc(terminator):
    r = FakeRunner()
    write_key_file(
        "www-anubis", "/home/www-anubis/k", f"{terminator}\nid", runner=r
    )
    assert f"{terminator}\nid" in su_script(r.calls[0])
    assert "id" not in script_argv(r.calls[0])


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_remove_file_quotes_the_path(path):
    r = FakeRunner()
    remove_file("www-anubis", path, runner=r)
    assert script_argv(r.calls[0]) == ["rm", "-f", "--", path]


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_remove_file_hands_a_real_shell_one_path_argument(path):
    r = FakeRunner()
    remove_file("www-anubis", path, runner=r)
    assert sh_words_after(su_script(r.calls[0]), "rm -f -- ") == [path]


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_file_exists_quotes_the_path(path):
    r = FakeRunner()
    file_exists("www-anubis", path, runner=r)
    assert path in script_argv(r.calls[0])


# Template operations


def test_write_systemd_template_quotes_the_user_derived_path():
    r = FakeRunner()
    write_systemd_template(HOSTILE_USER, "[Unit]\n", runner=r)
    path = f"/home/{HOSTILE_USER}/.config/systemd/user/anubis@.service"
    assert su_argv(r.calls[0]) == ["sudo", "nine-su", HOSTILE_USER]
    assert path in script_argv(r.calls[0])


@pytest.mark.parametrize("terminator", TERMINATORS)
def test_systemd_template_content_cannot_terminate_its_heredoc(terminator):
    r = FakeRunner()
    write_systemd_template("www-anubis", f"[Unit]\n{terminator}\nid", runner=r)
    assert f"{terminator}\nid" in su_script(r.calls[0])
    assert "id" not in script_argv(r.calls[0])


@pytest.mark.parametrize("call", [template_exists, remove_systemd_template])
def test_template_functions_quote_the_user_derived_path(call):
    r = FakeRunner()
    call(HOSTILE_USER, runner=r)
    path = f"/home/{HOSTILE_USER}/.config/systemd/user/anubis@.service"
    assert path in script_argv(r.calls[0])


# Binary operations


@pytest.mark.parametrize("call", [binary_exists, binary_version])
def test_binary_functions_quote_the_user_derived_path(call):
    r = FakeRunner()
    call(HOSTILE_USER, runner=r)
    assert f"/home/{HOSTILE_USER}/bin/anubis" in script_argv(r.calls[0])


def test_download_binary_quotes_the_version():
    # The version reaches here from the config file or the GitHub API, both
    # of which are validated — quoting is the second line of defence.
    r = FakeRunner()
    download_binary("www-anubis", "1.27.0; id", runner=r)
    words = script_argv(r.calls[0])
    assert "anubis-1.27.0; id-linux-amd64.tar.gz" in words
    assert (
        "https://github.com/TecharoHQ/anubis/releases/download/"
        "v1.27.0; id/anubis-1.27.0; id-linux-amd64.tar.gz" in words
    )
    assert "anubis-1.27.0; id-linux-amd64/bin/anubis" in words
    assert "anubis-1.27.0; id-linux-amd64" in words


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_extract_policy_quotes_the_destination(path):
    r = FakeRunner()
    extract_policy("www-anubis", path, runner=r)
    words = script_argv(r.calls[0])
    assert posixpath.dirname(path) in words
    assert path in words


def test_extract_policy_quotes_the_scratch_directory():
    r = FakeRunner()
    extract_policy(HOSTILE_USER, "/home/www-anubis/policy.yaml", runner=r)
    words = script_argv(r.calls[0])
    assert f"/tmp/anubis-extract-{HOSTILE_USER}" in words
    assert f"/tmp/anubis-extract-{HOSTILE_USER}/data/botPolicies.yaml" in words


# --- Timeouts -----------------------------------------------------------------
#
# Every command here runs under one. The two that reach the network get their
# own, because a release download is legitimately slower than anything else
# this tool does — and a stalled one used to block the run for good.


@pytest.mark.parametrize("call", [enable_service, disable_service, restart_service])
def test_a_service_change_runs_under_the_service_timeout(call):
    r = FakeRunner()
    call("www-anubis", "example.com", runner=r)
    assert r.invocations[0].timeout == SERVICE_TIMEOUT
    assert "anubis@example.com.service" in r.invocations[0].what


def test_a_binary_download_runs_under_the_download_timeout():
    r = FakeRunner()
    download_binary("www-anubis", "1.27.0", runner=r)
    assert r.invocations[0].timeout == DOWNLOAD_TIMEOUT
    assert "1.27.0" in r.invocations[0].what


def test_a_binary_download_also_limits_curl_on_the_far_side():
    # This curl runs as another user through nine-su, so it is the one place
    # our own kill can be refused — curl's clock cannot be.
    r = FakeRunner()
    download_binary("www-anubis", "1.27.0", runner=r)
    words = script_argv(r.calls[0])
    assert "--max-time" in words
    assert int(words[words.index("--max-time") + 1]) < DOWNLOAD_TIMEOUT


def test_a_release_query_runs_under_the_release_query_timeout():
    r = FakeRunner({"curl -sL https://api.github.com": '"tag_name": "v1.27.0"'})
    get_latest_version(runner=r)
    assert r.invocations[0].timeout == RELEASE_QUERY_TIMEOUT
    assert r.invocations[0].what


def test_generating_a_key_names_the_operation_and_not_the_key():
    r = FakeRunner({"openssl rand -hex 32": "deadbeef\n"})
    generate_key(runner=r)
    what = r.invocations[0].what
    assert what
    assert "deadbeef" not in what


def test_a_file_write_names_the_path_it_was_writing():
    r = FakeRunner()
    write_env_file("www-anubis", "/home/www-anubis/.config/anubis/e.env", "BIND=:7010\n", runner=r)
    assert "/home/www-anubis/.config/anubis/e.env" in r.invocations[0].what
