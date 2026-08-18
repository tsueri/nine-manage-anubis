"""Tests for commands.py — command implementations."""

from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.commands import (
    cmd_install,
    cmd_uninstall,
    cmd_enable,
    cmd_disable,
    cmd_upgrade,
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
        _SU + "cat '/home/www-anubis/.config/anubis/test.example.ch.env'": "BIND=:7010\nMETRICS_BIND=:7011\nTARGET_HOST=origin-test.example.ch\n",
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
        _SU + "cat '/home/www-anubis/.config/anubis/example.ch.env'": "BIND=:7014\nMETRICS_BIND=:7015\nTARGET_HOST=origin-example.ch\n",
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


def test_selftest_http_probe_fails():
    r = _base_runner(**{
        "curl -s -o /dev/null -w '%{http_code}'": "502",
    })
    result = cmd_selftest(runner=r)
    assert not result.success
    assert any("502" in s for s in result.warnings)


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
        _SU + "cat '/home/www-anubis/.config/anubis/example.ch.env'": "BIND=:7014\nMETRICS_BIND=:7015\nTARGET_HOST=origin-example.ch\n",
    })

    def failing_runner(cmd: str) -> str:
        if "virtual-host update blog.example.ch" in cmd and "--template=proxy_letsencrypt_https_redirect" in cmd:
            raise RuntimeError("cutover failed")
        return r(cmd)

    result = cmd_enable("blog.example.ch", runner=failing_runner)
    assert not result.success
    assert "rollback" in result.error.lower() or "rolled back" in result.error.lower()
