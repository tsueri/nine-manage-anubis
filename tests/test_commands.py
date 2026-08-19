"""Tests for commands.py — command implementations."""

import pytest

from conftest import hostile
from shellparse import argv
from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.validate import ValidationError
from nine_manage_anubis.commands import (
    _http_probe,
    cmd_install,
    cmd_uninstall,
    cmd_enable,
    cmd_disable,
    cmd_upgrade,
    cmd_restart,
    cmd_status,
    cmd_selftest,
    DEFAULT_ANUBIS_USER,
)

_SU = "sudo nine-su www-anubis <<'NINE_SU_EOF'\n"

# Sample vhost data — one proxy (already enabled), one default (not yet enabled)
VHOSTS_WITH_PROXY = """[
  {"domain": "test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []},
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/example.com", "template": "default_letsencrypt_https", "template_variables": {"TIMEOUT": "300", "PHP_VERSION": "8.2", "MODSEC": "Off"}, "aliases": [], "jobs": []},
  {"domain": "origin-test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "default_snakeoil_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
]"""

VHOSTS_EMPTY = "[]"

USERS_JSON = """[{"name": "www-data"}, {"name": "www-anubis"}]"""

CERT_LIST = """test.example.ch
================
       DOMAIN: test.example.ch
  VALID UNTIL: 2026-12-01
"""


def _base_runner(**overrides) -> FakeRunner:
    """Runner with common responses for command tests."""
    responses = {
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_WITH_PROXY,
        "sudo nine-manage-vhosts user list --json": USERS_JSON,
        "sudo nine-manage-vhosts certificate list": CERT_LIST,
        "ss -tlnp": "LISTEN 0 4096 0.0.0.0:7010 0.0.0.0:* users:((\"anubis\",pid=1,fd=3))\n",
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        _SU + "ls ~/.config/anubis/*.env 2>/dev/null": "/home/www-anubis/.config/anubis/test.example.ch.env\n",
        _SU + "cat -- /home/www-anubis/.config/anubis/test.example.ch.env": "BIND=:7010\nMETRICS_BIND=:7011\nTARGET_HOST=origin-test.example.ch\n",
        _SU + "export XDG_RUNTIME_DIR": "active",
        _SU + "/home/www-anubis/bin/anubis --version": "Anubis version 1.27.0\n",
        _SU + "test -f": "yes\n",
        _SU + "cat >": "",
        _SU + "rm -f": "",
        _SU + "mkdir -p": "",
        _SU + "cp -p": "",
        _SU + "ls -1": "",
        "openssl rand -hex 32": "abc123def456\n",
        "sudo nine-manage-vhosts virtual-host create": "",
        "sudo nine-manage-vhosts virtual-host update": "",
        "sudo nine-manage-vhosts virtual-host remove": "",
        "sudo nine-manage-vhosts certificate create": "",
        "sudo nine-manage-vhosts user create": "",
        "sudo nine-manage-vhosts user remove": "",
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest "
        "| grep -m1 '\"tag_name\"'": '"tag_name": "v1.27.0"',
        "curl -s -o /dev/null -w '%{http_code}'": "200",
    }
    responses.update(overrides)
    return FakeRunner(responses)


# --- install ------------------------------------------------------------------


def test_install_dry_run():
    r = _base_runner()
    result = cmd_install(runner=r, dry_run=True)
    assert result.success
    assert any("user" in s.lower() for s in result.steps)
    assert any("binary" in s.lower() for s in result.steps)
    assert any("template" in s.lower() for s in result.steps)


def test_install_real():
    r = _base_runner()
    result = cmd_install(runner=r)
    assert result.success
    assert any("Created" in s or "already exists" in s for s in result.steps)


def test_install_user_exists():
    r = _base_runner()
    result = cmd_install(runner=r)
    assert result.success
    assert any("already exists" in s for s in result.steps)


def test_install_init_policy():
    r = _base_runner()
    result = cmd_install(
        runner=r,
        policy_file="/home/www-anubis/.config/anubis/shared-policy.yaml",
        init_policy=True,
    )
    assert result.success
    assert any("Extracted default bot policy" in s for s in result.steps)


def test_install_init_policy_no_policy_file_warns():
    r = _base_runner()
    result = cmd_install(
        runner=r,
        init_policy=True,
    )
    assert result.success
    assert any("no policy_file" in w for w in result.warnings)


def test_install_init_policy_dry_run():
    r = _base_runner()
    result = cmd_install(
        runner=r,
        dry_run=True,
        policy_file="/home/www-anubis/.config/anubis/shared-policy.yaml",
        init_policy=True,
    )
    assert result.success
    assert any("Would extract" in s for s in result.steps)


# --- uninstall ----------------------------------------------------------------


def test_uninstall_refuses_with_instances():
    r = _base_runner()
    result = cmd_uninstall(runner=r)
    assert not result.success
    assert "instance" in result.error.lower()


def test_uninstall_dry_run_no_instances():
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_EMPTY,
        "ss -tlnp": "",
        "ls -d /home/www-*/ 2>/dev/null": "",
    })
    result = cmd_uninstall(runner=r, dry_run=True)
    assert result.success
    assert any("remove" in s.lower() for s in result.steps)


def test_uninstall_real_no_instances():
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_EMPTY,
        "ss -tlnp": "",
        "ls -d /home/www-*/ 2>/dev/null": "",
    })
    result = cmd_uninstall(runner=r)
    assert result.success
    assert any("Removed" in s for s in result.steps)


# --- enable -------------------------------------------------------------------


def test_enable_dry_run_new_domain():
    r = _base_runner()
    result = cmd_enable("example.com", runner=r, dry_run=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "JWT" in steps_text or "key" in steps_text.lower()
    assert "env" in steps_text.lower()
    assert "origin" in steps_text.lower()
    assert "proxy" in steps_text.lower() or "PROXYPORT" in steps_text


def test_enable_vhost_not_found():
    r = _base_runner()
    result = cmd_enable("nonexistent.com", runner=r, dry_run=True)
    assert not result.success
    assert "not found" in result.error


def test_enable_already_behind_anubis():
    r = _base_runner()
    result = cmd_enable("test.example.ch", runner=r, dry_run=True)
    assert not result.success
    assert "already behind" in result.error


def test_enable_real_new_domain():
    r = _base_runner()
    result = cmd_enable("example.com", runner=r)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "Switched" in steps_text or "proxy" in steps_text.lower()


def test_enable_prepare_only():
    r = _base_runner()
    result = cmd_enable("example.com", runner=r, prepare_only=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "Cut over" not in steps_text
    assert "proxy template" not in steps_text.lower() or "PROXYPORT" not in steps_text


def test_enable_cutover_only():
    r = _base_runner()
    result = cmd_enable("example.com", runner=r, cutover_only=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "proxy" in steps_text.lower() or "PROXYPORT" in steps_text


# --- disable ------------------------------------------------------------------


def test_disable_dry_run_last_vhost():
    r = _base_runner()
    result = cmd_disable("test.example.ch", runner=r, dry_run=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "tear down" in steps_text.lower() or "last vhost" in steps_text.lower()


def test_disable_not_behind_anubis():
    r = _base_runner()
    result = cmd_disable("example.com", runner=r)
    assert not result.success
    assert "not behind" in result.error


def test_disable_vhost_not_found():
    r = _base_runner()
    result = cmd_disable("nonexistent.com", runner=r)
    assert not result.success
    assert "not found" in result.error


def test_disable_real_last_vhost():
    r = _base_runner()
    result = cmd_disable("test.example.ch", runner=r)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "Switched" in steps_text
    assert "Stopped" in steps_text or "disabled" in steps_text.lower()
    assert "Removed" in steps_text


def test_disable_not_last_vhost():
    # Two vhosts on the same port
    vhosts = """[
      {"domain": "example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7014"}, "aliases": [], "jobs": []},
      {"domain": "blog.example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7014"}, "aliases": [], "jobs": []}
    ]"""
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
        "ss -tlnp": "LISTEN 0 4096 0.0.0.0:7014 0.0.0.0:* users:((\"anubis\",pid=1,fd=3))\n",
        _SU + "ls ~/.config/anubis/*.env 2>/dev/null": "/home/www-anubis/.config/anubis/example.ch.env\n",
        _SU + "cat -- /home/www-anubis/.config/anubis/example.ch.env": "BIND=:7014\nMETRICS_BIND=:7015\nTARGET_HOST=origin-example.ch\n",
    })
    result = cmd_disable("example.ch", runner=r)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "still serving" in steps_text
    assert "blog.example.ch" in steps_text


# --- upgrade ------------------------------------------------------------------


def test_upgrade_dry_run():
    r = _base_runner()
    result = cmd_upgrade(runner=r, dry_run=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "1.27.0" in steps_text
    assert "rolling" in steps_text.lower()


def test_upgrade_dry_run_specific_version():
    r = _base_runner()
    result = cmd_upgrade(version="1.26.0", runner=r, dry_run=True)
    assert result.success
    assert any("1.26.0" in s for s in result.steps)


def test_upgrade_dry_run_no_rolling():
    r = _base_runner()
    result = cmd_upgrade(runner=r, dry_run=True, no_rolling=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "at once" in steps_text


def test_upgrade_real():
    r = _base_runner()
    result = cmd_upgrade(runner=r)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "Downloaded" in steps_text
    assert "Restarted" in steps_text


# --- restart ------------------------------------------------------------------


def test_restart_dry_run():
    r = _base_runner()
    result = cmd_restart(runner=r, dry_run=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "rolling" in steps_text.lower()


def test_restart_dry_run_no_rolling():
    r = _base_runner()
    result = cmd_restart(runner=r, dry_run=True, no_rolling=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "at once" in steps_text


def test_restart_dry_run_no_instances():
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_EMPTY,
        "ss -tlnp": "",
        "ls -d /home/www-*/ 2>/dev/null": "",
    })
    result = cmd_restart(runner=r, dry_run=True)
    assert result.success
    assert any("no instances" in s.lower() for s in result.steps)


def test_restart_real():
    r = _base_runner()
    result = cmd_restart(runner=r)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "Restarted" in steps_text
    assert "Health check" in steps_text


def test_restart_real_no_rolling():
    r = _base_runner()
    result = cmd_restart(runner=r, no_rolling=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "Restarted" in steps_text
    assert "Health check" not in steps_text


def test_restart_no_instances():
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_EMPTY,
        "ss -tlnp": "",
        "ls -d /home/www-*/ 2>/dev/null": "",
    })
    result = cmd_restart(runner=r)
    assert result.success
    assert any("no instances" in s.lower() for s in result.steps)


# --- status -------------------------------------------------------------------


def test_status_basic():
    r = _base_runner()
    instances, health_map = cmd_status(runner=r)
    assert len(instances) == 1
    assert instances[0].domain == "test.example.ch"
    assert health_map is None


def test_status_with_domain():
    r = _base_runner()
    instances, _ = cmd_status(domain="test.example.ch", runner=r)
    assert len(instances) == 1


def test_status_with_domain_no_match():
    r = _base_runner()
    instances, _ = cmd_status(domain="nonexistent.com", runner=r)
    assert len(instances) == 0


def test_status_with_health():
    r = _base_runner(**{
        "curl -s -o /dev/null -w '%{http_code}'": "200",
    })
    instances, health_map = cmd_status(health=True, runner=r)
    assert health_map is not None
    assert "test.example.ch" in health_map


# --- self-test ----------------------------------------------------------------


def test_selftest_all_pass():
    r = _base_runner()
    result = cmd_selftest(runner=r)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "user" in steps_text.lower()
    assert "binary" in steps_text.lower()
    assert "template" in steps_text.lower()
    assert "test.example.ch" in steps_text


def test_selftest_no_instances():
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_EMPTY,
        "ss -tlnp": "",
        "ls -d /home/www-*/ 2>/dev/null": "",
    })
    result = cmd_selftest(runner=r)
    assert result.success
    assert any("no instances" in s.lower() for s in result.steps)


def test_selftest_instance_not_active():
    r = _base_runner(**{
        _SU + "export XDG_RUNTIME_DIR": "failed",
        _SU + "/home/www-anubis/bin/anubis --version": "Anubis version 1.27.0\n",
    })
    result = cmd_selftest(runner=r)
    assert not result.success
    assert any("not active" in s.lower() or "failed" in s.lower() for s in result.warnings)


def test_selftest_http_probe_any_response_is_ok():
    """Any HTTP response means Anubis is running and listening."""
    r = _base_runner(**{
        "curl -s -o /dev/null -w '%{http_code}'": "502",
    })
    result = cmd_selftest(runner=r)
    assert result.success
    assert any("502" in s for s in result.steps)


def test_selftest_dry_run():
    r = _base_runner()
    result = cmd_selftest(runner=r, dry_run=True)
    assert result.success
    steps_text = " ".join(result.steps)
    assert "Would" in steps_text


# --- enable rollback ----------------------------------------------------------


def test_enable_rollback_on_service_enable_failure():
    """If enable_service raises, rollback undoes fixups + origin vhost + env/key."""
    call_count = {"enable": 0}

    def failing_runner(cmd: str) -> str:
        r = _base_runner()
        if "systemctl --user enable" in cmd:
            call_count["enable"] += 1
            raise RuntimeError("systemctl enable failed")
        return r(cmd)

    result = cmd_enable("example.com", runner=failing_runner)
    assert not result.success
    assert "rollback" in result.error.lower() or "rolled back" in result.error.lower()
    assert any("rollback" in s.lower() or "rolled back" in s.lower() for s in result.steps)
    assert call_count["enable"] == 1


def test_enable_rollback_on_cutover_failure():
    """If switch_to_proxy raises, rollback undoes service + fixups + origin vhost + env/key."""
    def failing_runner(cmd: str) -> str:
        r = _base_runner()
        if "virtual-host update example.com" in cmd and "--template=proxy_letsencrypt_https_redirect" in cmd:
            raise RuntimeError("cutover failed")
        return r(cmd)

    result = cmd_enable("example.com", runner=failing_runner)
    assert not result.success
    assert "rollback" in result.error.lower() or "rolled back" in result.error.lower()


def test_enable_no_rollback_on_validation_error():
    """If vhost not found, no rollback needed — nothing was done."""
    r = _base_runner()
    result = cmd_enable("nonexistent.com", runner=r)
    assert not result.success
    assert "not found" in result.error
    assert not any("rollback" in s.lower() for s in result.steps)


def test_enable_reused_webroot_rollback_on_cutover_failure():
    """Reused webroot path: only cutover needs rollback (switch back to default)."""
    vhosts = """[
      {"domain": "example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7014"}, "aliases": [], "jobs": []},
      {"domain": "blog.example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "default_letsencrypt_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
    ]"""
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
        "ss -tlnp": "LISTEN 0 4096 0.0.0.0:7014 0.0.0.0:* users:((\"anubis\",pid=1,fd=3))\n",
        _SU + "ls ~/.config/anubis/*.env 2>/dev/null": "/home/www-anubis/.config/anubis/example.ch.env\n",
        _SU + "cat -- /home/www-anubis/.config/anubis/example.ch.env": "BIND=:7014\nMETRICS_BIND=:7015\nTARGET_HOST=origin-example.ch\n",
    })

    def failing_runner(cmd: str) -> str:
        if "virtual-host update blog.example.ch" in cmd and "--template=proxy_letsencrypt_https_redirect" in cmd:
            raise RuntimeError("cutover failed")
        return r(cmd)

    result = cmd_enable("blog.example.ch", runner=failing_runner)
    assert not result.success
    assert "rollback" in result.error.lower() or "rolled back" in result.error.lower()


def test_enable_reuse_creates_certificate_if_missing():
    """Reused webroot path must check/create cert before switch_to_proxy.

    A domain sharing a webroot with an already-Anubis-protected site still
    needs its own Let's Encrypt certificate for the proxy template.
    """
    vhosts = """[
      {"domain": "example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7014"}, "aliases": [], "jobs": []},
      {"domain": "blog.example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "default_letsencrypt_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
    ]"""
    cert_list_without_sp_studen = """test.example.ch
================
       DOMAIN: test.example.ch
  VALID UNTIL: 2026-12-01
"""
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
        "sudo nine-manage-vhosts certificate list": cert_list_without_sp_studen,
        "ss -tlnp": "LISTEN 0 4096 0.0.0.0:7014 0.0.0.0:* users:((\"anubis\",pid=1,fd=3))\n",
        _SU + "ls ~/.config/anubis/*.env 2>/dev/null": "/home/www-anubis/.config/anubis/example.ch.env\n",
        _SU + "cat -- /home/www-anubis/.config/anubis/example.ch.env": "BIND=:7014\nMETRICS_BIND=:7015\nTARGET_HOST=origin-example.ch\n",
    })

    cert_commands = []
    original_run = r

    def tracking_runner(cmd: str) -> str:
        if "certificate create" in cmd:
            cert_commands.append(cmd)
        return original_run(cmd)

    result = cmd_enable("blog.example.ch", runner=tracking_runner)
    assert result.success
    assert any("certificate" in s.lower() and "created" in s.lower() for s in result.steps)
    assert len(cert_commands) == 1
    assert "blog.example.ch" in cert_commands[0]


# --- Input validation at the command entry points -----------------------------
#
# The library must be safe when driven directly, not just through the CLI.
# Every command function rejects malformed input before it builds a single
# sudo command.

HOSTILE_DOMAINS = hostile("example.com")
HOSTILE_USERS = hostile("www-anubis")
HOSTILE_VERSIONS = hostile("1.27.0")


@pytest.mark.parametrize("domain", HOSTILE_DOMAINS)
def test_cmd_enable_rejects_malformed_domain(domain):
    r = _base_runner()
    with pytest.raises(ValidationError) as exc:
        cmd_enable(domain, runner=r)
    assert repr(domain) in str(exc.value)
    assert r.calls == []


@pytest.mark.parametrize("domain", HOSTILE_DOMAINS)
def test_cmd_disable_rejects_malformed_domain(domain):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_disable(domain, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("user", HOSTILE_USERS)
def test_cmd_enable_rejects_malformed_anubis_user(user):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_enable("example.com", runner=r, anubis_user=user)
    assert r.calls == []


@pytest.mark.parametrize("user", HOSTILE_USERS)
def test_cmd_disable_rejects_malformed_anubis_user(user):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_disable("test.example.ch", runner=r, anubis_user=user)
    assert r.calls == []


@pytest.mark.parametrize("user", HOSTILE_USERS)
def test_cmd_install_rejects_malformed_anubis_user(user):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_install(anubis_user=user, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("version", HOSTILE_VERSIONS)
def test_cmd_install_rejects_malformed_version(version):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_install(anubis_user="www-anubis", version=version, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("user", HOSTILE_USERS)
def test_cmd_uninstall_rejects_malformed_anubis_user(user):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_uninstall(anubis_user=user, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("version", HOSTILE_VERSIONS)
def test_cmd_upgrade_rejects_malformed_version(version):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_upgrade(version=version, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("user", HOSTILE_USERS)
def test_cmd_upgrade_rejects_malformed_anubis_user(user):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_upgrade(anubis_user=user, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("user", HOSTILE_USERS)
def test_cmd_restart_rejects_malformed_anubis_user(user):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_restart(anubis_user=user, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("user", HOSTILE_USERS)
def test_cmd_selftest_rejects_malformed_anubis_user(user):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_selftest(anubis_user=user, runner=r)
    assert r.calls == []


@pytest.mark.parametrize("domain", HOSTILE_DOMAINS)
def test_cmd_status_rejects_malformed_domain_filter(domain):
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_status(domain=domain, runner=r)
    assert r.calls == []


def test_dry_run_also_rejects_malformed_input():
    """Dry run must not be a way to smuggle a value past validation."""
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_enable("example.com; id", runner=r, dry_run=True)
    assert r.calls == []


def test_cmd_install_rejects_malformed_policy_file():
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_install(runner=r, policy_file="/tmp/policy.yaml; id", init_policy=True)
    assert r.calls == []


def test_cmd_enable_rejects_malformed_policy_file():
    r = _base_runner()
    with pytest.raises(ValidationError):
        cmd_enable("example.com", runner=r, policy_file="/tmp/p.yaml`id`")
    assert r.calls == []


def test_cmd_upgrade_rejects_malformed_version_from_github():
    """get_latest_version parses an HTTP response — untrusted."""
    r = _base_runner(**{
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest "
        "| grep -m1 '\"tag_name\"'": '"tag_name": "v1.27.0; id"',
    })
    with pytest.raises(ValidationError) as exc:
        cmd_upgrade(runner=r)
    assert "1.27.0; id" in str(exc.value)
    assert not any("curl -sLO" in c for c in r.calls)


def test_valid_input_still_works():
    """The whitelist must not reject the ordinary case."""
    r = _base_runner()
    result = cmd_enable("example.com", runner=r, dry_run=True)
    assert result.success


# --- HTTP probe ---------------------------------------------------------------
#
# Every health check probes the instance with the same curl command. It is
# built once, so the Host header and the URL are quoted once.


def test_http_probe_returns_the_status_code():
    r = FakeRunner({"curl -s -o /dev/null -w '%{http_code}'": "200"})
    assert _http_probe("example.com", 7010, r) == "200"


def test_http_probe_quotes_the_host_header_and_url():
    r = FakeRunner()
    _http_probe("example.com; id", 7010, r)
    words = argv(r.calls[0])
    assert "Host: example.com; id" in words
    assert "http://localhost:7010/" in words
    assert "id" not in words


def test_http_probe_asks_for_the_status_code_only():
    r = FakeRunner()
    _http_probe("example.com", 7010, r)
    words = argv(r.calls[0])
    assert words[:2] == ["curl", "-s"]
    assert "%{http_code}" in words
    assert "X-Real-Ip: 127.0.0.1" in words


def test_every_health_check_uses_the_same_probe():
    for command in (cmd_status, cmd_selftest, cmd_restart, cmd_upgrade):
        r = _base_runner()
        kwargs = {"health": True} if command is cmd_status else {}
        command(runner=r, **kwargs)
        probes = [c for c in r.calls if c.startswith("curl -s -o /dev/null")]
        assert probes, f"{command.__name__} did not probe"
        assert all(p == probes[0] for p in probes)
        assert "'Host: test.example.ch'" in probes[0]
