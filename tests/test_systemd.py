"""Tests for systemd.py — service management via nine-su heredoc."""

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
    get_latest_version,
)
from nine_manage_anubis.config import SYSTEMD_TEMPLATE

_SU = "sudo nine-su www-anubis <<'NINE_SU_EOF'"


def _su_calls(r: FakeRunner) -> list[str]:
    return [c for c in r.calls if c.startswith(_SU)]


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
    assert "chmod 600" in cmd
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
    result = download_binary("www-anubis", "1.27.0", runner=r)
    cmd = r.calls[0]
    assert "curl -sLO" in cmd
    assert "anubis-1.27.0-linux-amd64.tar.gz" in cmd
    assert "tar xzf" in cmd
    assert "cp anubis-1.27.0-linux-amd64/bin/anubis ~/bin/" in cmd
    assert "chmod +x" in cmd


def test_get_latest_version():
    r = FakeRunner({
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest": '',
    })
    # The actual command pipes to grep, so we need to match the full command
    r.responses["curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest "
                "| grep -m1 '\"tag_name\"'"] = '"tag_name": "v1.27.0"'
    v = get_latest_version(r)
    assert v == "1.27.0"
