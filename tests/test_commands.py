"""Tests for commands.py — command implementations."""

import json
import posixpath
import re

import pytest

from conftest import hostile
from shellparse import argv, script_argv
from nine_manage_anubis import ports
from nine_manage_anubis.locking import ExclusiveLock, LockUnavailable
from nine_manage_anubis.runner import CommandFailed, CommandTimeout, FakeRunner
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
    ANUBIS_VERSION,
    DEFAULT_ANUBIS_USER,
    PROBE_FAILED,
    PROBE_TIMEOUT,
    STARTUP_ATTEMPTS,
)

_SU = "sudo nine-su www-anubis <<'NINE_SU_EOF'\n"

# Sample vhost data — one proxy (already enabled), one default (not yet enabled)
VHOSTS_WITH_PROXY = """[
  {"domain": "test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []},
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/example.com", "template": "default_letsencrypt_https", "template_variables": {"TIMEOUT": "300", "PHP_VERSION": "8.2", "MODSEC": "Off"}, "aliases": [], "jobs": []},
  {"domain": "origin-test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "default_snakeoil_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
]"""

VHOSTS_EMPTY = "[]"

# Two instances on two webroots — for the rolling restart, which must stop at
# the first unhealthy one rather than carry on to the next.
VHOSTS_TWO_INSTANCES = """[
  {"domain": "test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []},
  {"domain": "second.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/second.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7012"}, "aliases": [], "jobs": []}
]"""

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
        _SU + "cat -- /home/www-anubis/.config/anubis/test.example.ch.key": "0123456789abcdef\n",
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
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest": '"tag_name": "v1.27.0"',
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


def test_every_file_an_enable_writes_brings_its_own_directory():
    # On a host that has never run this tool, ~/.config/anubis does not exist,
    # and the env file the systemd unit reads has to arrive with it. The failure
    # this guards against needs no hostile input and no unusual host: it is the
    # first install on any clean machine.
    r = _base_runner()
    cmd_enable("example.com", runner=r)

    targets = []
    for call in [c for c in r.calls if "cat > " in c]:
        words = script_argv(call)
        target = words[words.index(">") + 1]
        assert words[:4] == ["mkdir", "-p", "--", posixpath.dirname(target)], (
            f"nothing created the parent directory of {target}"
        )
        targets.append(target)

    assert "/home/www-anubis/.config/anubis/example.com.env" in targets
    assert "/home/www-anubis/.config/anubis/example.com.key" in targets


def test_the_env_and_key_files_an_enable_writes_are_the_owners_alone():
    # Asserted here as well as at the write helpers, because this is the path an
    # operator actually runs: it is `enable` that decides which files an instance
    # gets, and which of them carry a signing key.
    r = _base_runner()
    cmd_enable("example.com", runner=r)

    for name in ("example.com.env", "example.com.key"):
        write = [
            c for c in r.calls
            if f"cat > /home/www-anubis/.config/anubis/{name}" in c
        ]
        assert len(write) == 1, f"{name} was not written exactly once"
        assert "umask 177" in write[0].splitlines()


def _allocation_lock_is_free() -> bool:
    """Whether a second run could take the port lock at this instant."""
    try:
        with ExclusiveLock(
            ports.PORT_LOCK_PATH, what="probe", runner=FakeRunner(), timeout=0.0
        ):
            return True
    except LockUnavailable:
        return False


class _LockWatchingRunner(FakeRunner):
    """Records whether the port lock is free at chosen moments of a command.

    Keyed by a phrase from the command that marks the moment — a run is only
    observable from the outside through the commands it issues."""

    def __init__(self, responses: dict[str, str], marks: dict[str, str]):
        super().__init__(responses)
        self._marks = marks
        self.free_at: dict[str, bool] = {}

    def __call__(self, cmd, **kwargs):
        for label, needle in self._marks.items():
            if needle in cmd and label not in self.free_at:
                self.free_at[label] = _allocation_lock_is_free()
        return super().__call__(cmd, **kwargs)


def test_enable_holds_the_port_pair_until_the_env_file_records_it():
    """The claim covers the gap between deciding on a pair and writing it down.

    Before the env file exists, nothing on the host says the port is taken, so
    a concurrent run would pick the same one — hence the hold. After it, the
    scan every run does finds it, so the hold ends: what is left of an enable
    is a certificate request and a service start, and a host-wide lock has no
    business spanning those."""
    r = _LockWatchingRunner(
        _base_runner().responses,
        {
            "before the env file": (
                "cat > /home/www-anubis/.config/anubis/example.com.key"
            ),
            "after the env file": "virtual-host create",
        },
    )
    result = cmd_enable("example.com", runner=r)
    assert result.success
    assert r.free_at["before the env file"] is False
    assert r.free_at["after the env file"] is True
    assert _allocation_lock_is_free()


def test_enable_does_not_hold_the_port_lock_through_a_dry_run():
    """A dry run promises nothing, so it has nothing to hold anyone up over."""
    r = _LockWatchingRunner(
        _base_runner().responses, {"during the dry run": "openssl rand -hex 32"}
    )
    result = cmd_enable("example.com", runner=r, dry_run=True)
    assert result.success
    assert r.free_at["during the dry run"] is True


def test_enable_does_not_hold_the_port_lock_through_a_cutover():
    """--cutover-only writes no env file, so it records no claim — and it may
    request a certificate, which is no place to be holding a host-wide lock."""
    r = _LockWatchingRunner(
        _base_runner().responses, {"during the cutover": "certificate list"}
    )
    result = cmd_enable("example.com", runner=r, cutover_only=True)
    assert result.success
    assert r.free_at["during the cutover"] is True


def test_enable_lets_the_port_lock_go_when_it_fails():
    """A failed enable must not leave the next one unable to allocate."""

    def failing_runner(cmd: str, **kwargs) -> str:
        if "systemctl --user enable" in cmd:
            raise RuntimeError("systemctl enable failed")
        return _base_runner()(cmd, **kwargs)

    result = cmd_enable("example.com", runner=failing_runner)
    assert not result.success
    assert _allocation_lock_is_free()


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
    # blog.example.ch is still proxying to this instance, so nothing about it may
    # be touched — that is the whole difference between the two branches.
    assert not any("systemctl --user disable --now" in c for c in r.calls)
    assert not any("virtual-host remove" in c for c in r.calls)
    assert not any("rm -f -- /home/www-anubis/.config/anubis/" in c for c in r.calls)


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

    def failing_runner(cmd: str, **kwargs) -> str:
        r = _base_runner()
        if "systemctl --user enable" in cmd:
            call_count["enable"] += 1
            raise RuntimeError("systemctl enable failed")
        return r(cmd, **kwargs)

    result = cmd_enable("example.com", runner=failing_runner)
    assert not result.success
    assert "rollback" in result.error.lower() or "rolled back" in result.error.lower()
    assert any("rollback" in s.lower() or "rolled back" in s.lower() for s in result.steps)
    assert call_count["enable"] == 1


def test_enable_rollback_on_cutover_failure():
    """If switch_to_proxy raises, rollback undoes service + fixups + origin vhost + env/key."""
    def failing_runner(cmd: str, **kwargs) -> str:
        r = _base_runner()
        if "virtual-host update example.com" in cmd and "--template=proxy_letsencrypt_https_redirect" in cmd:
            raise RuntimeError("cutover failed")
        return r(cmd, **kwargs)

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

    def failing_runner(cmd: str, **kwargs) -> str:
        if "virtual-host update blog.example.ch" in cmd and "--template=proxy_letsencrypt_https_redirect" in cmd:
            raise RuntimeError("cutover failed")
        return r(cmd, **kwargs)

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

    def tracking_runner(cmd: str, **kwargs) -> str:
        if "certificate create" in cmd:
            cert_commands.append(cmd)
        return original_run(cmd, **kwargs)

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
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest": '"tag_name": "v1.27.0; id"',
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


# --- A probe that never answers -----------------------------------------------
#
# The motivating case: an instance wedged badly enough to accept a connection
# and never reply. The probe is what notices, so a probe that hangs used to
# take the whole run with it — and once it is bounded, a timeout has to read as
# a failed health check rather than as one that was skipped.


class _ProbeNeverAnswers(FakeRunner):
    """Every command answers as usual except the health probe, which hangs."""

    def __call__(self, cmd, **kwargs):
        if cmd.startswith("curl -s -o /dev/null"):
            raise CommandTimeout("curl", PROBE_TIMEOUT, kwargs.get("what"))
        return super().__call__(cmd, **kwargs)


def _wedged_runner() -> _ProbeNeverAnswers:
    return _ProbeNeverAnswers(_base_runner().responses)


def test_every_health_check_runs_the_probe_under_the_probe_timeout():
    for command in (cmd_status, cmd_selftest, cmd_restart, cmd_upgrade):
        r = _base_runner()
        kwargs = {"health": True} if command is cmd_status else {}
        command(runner=r, **kwargs)
        probe = r.invocation("curl -s -o /dev/null")
        assert probe.timeout == PROBE_TIMEOUT, command.__name__
        assert "test.example.ch" in probe.what, command.__name__


def test_status_reports_a_probe_that_timed_out_as_such():
    _, health_map = cmd_status(health=True, runner=_wedged_runner())
    assert health_map is not None
    assert "timed out" in health_map["test.example.ch"]


def test_selftest_counts_a_probe_that_timed_out_as_a_failed_check():
    result = cmd_selftest(runner=_wedged_runner())
    assert not result.success
    assert any("timed out" in w for w in result.warnings)


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
def test_a_rolling_restart_stops_when_a_health_probe_times_out(command):
    result = command(runner=_wedged_runner())
    assert not result.success
    assert "timed out" in " ".join(result.warnings)
    assert "test.example.ch" in result.error


# --- One place declares a default ---------------------------------------------


def test_command_defaults_are_the_settings_defaults():
    """A library caller and a CLI caller must mean the same thing by "default"."""
    from nine_manage_anubis.settings import Settings

    assert DEFAULT_ANUBIS_USER == Settings.anubis_user
    assert ANUBIS_VERSION == Settings.anubis_version


# --- A probe that answered, and what its answer meant -------------------------
#
# The status code is a number, so it is compared as one. Classifying it by its
# first character made 301 and 500 depend on the shape of the string curl
# printed rather than on the code it stands for.


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
@pytest.mark.parametrize("code", ["200", "204", "301", "302", "399"])
def test_a_rolling_restart_accepts_a_2xx_or_3xx(command, code):
    r = _base_runner(**{"curl -s -o /dev/null -w '%{http_code}'": code})
    result = command(runner=r)
    assert result.success, result.error
    assert f"HTTP {code}" in " ".join(result.steps)


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
@pytest.mark.parametrize("code", ["000", "400", "404", "500", "502"])
def test_a_rolling_restart_stops_on_anything_else(command, code):
    r = _base_runner(**{"curl -s -o /dev/null -w '%{http_code}'": code})
    result = command(runner=r)
    assert not result.success
    assert "test.example.ch" in result.error


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
@pytest.mark.parametrize("code,reads_as", [
    ("500", "HTTP 500"),
    ("301", "HTTP 301"),
    ("000", "no response"),
])
def test_a_rolling_restart_says_what_the_probe_answered(command, code, reads_as):
    """000 is curl saying it never got a response, not an HTTP 000."""
    r = _base_runner(**{"curl -s -o /dev/null -w '%{http_code}'": code})
    result = command(runner=r)
    reported = " ".join(result.steps + result.warnings + [result.error or ""])
    assert reads_as in reported


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
def test_a_rolling_restart_stops_on_an_answer_that_is_not_a_status_code(command):
    r = _base_runner(**{"curl -s -o /dev/null -w '%{http_code}'": ""})
    result = command(runner=r)
    assert not result.success
    assert "test.example.ch" in result.error


# --- A probe that could not be made -------------------------------------------
#
# Connection refused, DNS failure, curl missing: the runner raises, and the
# rolling restart used to catch it and write "HTTP probe skipped" into the
# steps — a green light on the way to restarting the next instance.


class _ProbeFails(FakeRunner):
    """Every command answers as usual except the health probe, which fails."""

    def __call__(self, cmd, **kwargs):
        if cmd.startswith("curl -s -o /dev/null"):
            raise CommandFailed("curl", 7, "Failed to connect to localhost port 7010")
        return super().__call__(cmd, **kwargs)


def _refusing_runner() -> _ProbeFails:
    return _ProbeFails(_base_runner().responses)


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
def test_a_rolling_restart_stops_when_the_probe_could_not_be_made(command):
    r = _refusing_runner()
    result = command(runner=r, sleep=_no_sleep)
    assert not result.success
    assert "test.example.ch" in result.error
    assert "skipped" not in " ".join(result.steps).lower()
    assert any("curl" in w for w in result.warnings)


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
def test_a_rolling_restart_that_stops_does_not_restart_the_next_instance(command):
    """The point of a rolling restart: a broken instance is the last one."""
    r = _ProbeFails(_base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_TWO_INSTANCES,
        "ss -tlnp": "",
        _SU + "ls ~/.config/anubis/*.env 2>/dev/null": (
            "/home/www-anubis/.config/anubis/test.example.ch.env\n"
            "/home/www-anubis/.config/anubis/second.example.ch.env\n"
        ),
        _SU + "cat -- /home/www-anubis/.config/anubis/second.example.ch.env":
            "BIND=:7012\nMETRICS_BIND=:7013\n",
    }).responses)
    result = command(runner=r, sleep=_no_sleep)
    assert not result.success
    restarts = [c for c in r.calls if "restart anubis@" in c]
    assert len(restarts) == 1, restarts


# --- A just-restarted instance can be slow to come up -------------------------
#
# `systemctl restart` on a Type=simple unit returns as soon as the process
# spawns, at which point its port may still be closed. The health check that
# follows a restart therefore retries the "not yet" verdicts for a bounded
# grace period — an instance that answers within it is healthy; one that does
# not is a failure like any other.


def _no_sleep(_seconds: float) -> None:
    """Tests do not wait for real time; a restart's grace lets them not."""


class _SlowToBind(FakeRunner):
    """Everything answers as usual, but the probe refuses its first
    ``refusals`` times — the instance that is still binding its port."""

    def __init__(self, refusals: int, responses: dict[str, str]) -> None:
        super().__init__(responses)
        self.refusals = refusals
        self.probes = 0

    def __call__(self, cmd, **kwargs):
        if cmd.startswith("curl -s -o /dev/null"):
            self.probes += 1
            if self.probes <= self.refusals:
                raise CommandFailed("curl", 7, "Failed to connect to localhost port 7010")
        return super().__call__(cmd, **kwargs)


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
def test_a_rolling_restart_waits_for_an_instance_that_is_slow_to_bind(command):
    """Probes are retried while the instance is still coming up, not failed."""
    r = _SlowToBind(refusals=2, responses=_base_runner().responses)
    result = command(runner=r, sleep=_no_sleep)
    assert result.success, result.error
    assert r.probes == 3


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
def test_a_rolling_restart_gives_an_instance_the_whole_grace_to_come_up(command):
    """The grace is inclusive: binding on the last try is still healthy."""
    r = _SlowToBind(
        refusals=STARTUP_ATTEMPTS - 1, responses=_base_runner().responses
    )
    result = command(runner=r, sleep=_no_sleep)
    assert result.success, result.error
    assert r.probes == STARTUP_ATTEMPTS


@pytest.mark.parametrize("command", [cmd_restart, cmd_upgrade])
def test_a_rolling_restart_gives_up_once_the_grace_is_spent(command):
    """An instance still down after the grace is a failure, retries bounded."""
    r = _SlowToBind(
        refusals=STARTUP_ATTEMPTS + 1, responses=_base_runner().responses
    )
    result = command(runner=r, sleep=_no_sleep)
    assert not result.success
    assert "test.example.ch" in result.error
    assert r.probes == STARTUP_ATTEMPTS


def test_selftest_reports_a_probe_that_could_not_be_made():
    result = cmd_selftest(runner=_refusing_runner())
    assert not result.success
    assert any("curl" in w for w in result.warnings)


def test_status_reports_a_probe_that_could_not_be_made():
    _, health_map = cmd_status(health=True, runner=_refusing_runner())
    assert health_map is not None
    assert health_map["test.example.ch"] != "HTTP 200"


def test_status_reports_a_probe_that_never_connected_as_no_response():
    """curl prints 000 when it got no response at all — not an HTTP 000."""
    r = _base_runner(**{"curl -s -o /dev/null -w '%{http_code}'": "000"})
    _, health_map = cmd_status(health=True, runner=r)
    assert health_map is not None
    assert health_map["test.example.ch"] == "no response"


# --- A vhost record missing a field we need -----------------------------------
#
# webroot, user and template are read off the vhost list and built into
# commands. A vhost type we have not seen, or a change to the JSON upstream,
# used to surface as a bare KeyError halfway through a batch.

VHOST_WITHOUT = {
    "webroot": """[
  {"domain": "example.com", "user": "www-example", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
]""",
    "user": """[
  {"domain": "example.com", "webroot": "/home/www-example/example.com", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
]""",
    "template": """[
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/example.com", "template_variables": {}, "aliases": [], "jobs": []}
]""",
}


@pytest.mark.parametrize("missing", ["webroot", "user", "template"])
def test_enable_names_the_vhost_and_the_field_it_is_missing(missing):
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOST_WITHOUT[missing],
    })
    result = cmd_enable("example.com", runner=r)
    assert not result.success
    assert "example.com" in result.error
    assert missing in result.error
    assert not any("virtual-host update" in c for c in r.calls)


DISABLE_VHOST_WITHOUT = {
    "webroot": """[
  {"domain": "example.com", "user": "www-example", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []}
]""",
    "user": """[
  {"domain": "example.com", "webroot": "/home/www-example/example.com", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []}
]""",
    "template": """[
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/example.com", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []}
]""",
}


@pytest.mark.parametrize("missing", ["webroot", "user", "template"])
def test_disable_names_the_vhost_and_the_field_it_is_missing(missing):
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json":
            DISABLE_VHOST_WITHOUT[missing],
    })
    result = cmd_disable("example.com", runner=r)
    assert not result.success
    assert "example.com" in result.error
    assert missing in result.error


@pytest.mark.parametrize("missing", ["webroot", "user", "template"])
def test_a_dry_run_reports_the_missing_field_too(missing):
    """Dry run is where an operator checks a batch before running it."""
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOST_WITHOUT[missing],
    })
    result = cmd_enable("example.com", runner=r, dry_run=True)
    assert not result.success
    assert missing in result.error


def test_disable_says_not_behind_anubis_before_it_says_anything_else():
    """The template is what an operator asked about; a missing webroot only
    matters once there is an instance to tear down."""
    r = _base_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": VHOST_WITHOUT["webroot"],
    })
    result = cmd_disable("example.com", runner=r)
    assert not result.success
    assert "not behind Anubis" in result.error


def test_one_wording_for_a_probe_that_could_not_be_made():
    """A rolling restart and `status` must not name the same thing differently."""
    result = cmd_restart(runner=_refusing_runner(), sleep=_no_sleep)
    _, health_map = cmd_status(health=True, runner=_refusing_runner())
    assert health_map is not None
    assert PROBE_FAILED in result.error
    assert PROBE_FAILED in " ".join(result.warnings)
    assert PROBE_FAILED in health_map["test.example.ch"]



# --- disable is transactional -------------------------------------------------
#
# Teardown is several destructive steps in a row — the service, the origin
# vhost, the webroot fixups, the instance's own files. A failure part-way used
# to leave the site switched away from Anubis *and* the instance half removed,
# which is neither state an operator can reason about. Every step therefore
# carries its undo, and the failure of any one of them puts the rest back.

# The protected site in VHOSTS_WITH_PROXY, and the artifacts of its instance.
PROTECTED = "test.example.ch"
PROTECTED_WEBROOT = f"/home/www-anubis/{PROTECTED}"
INSTANCE_ENV = f"/home/www-anubis/.config/anubis/{PROTECTED}.env"
INSTANCE_KEY = f"/home/www-anubis/.config/anubis/{PROTECTED}.key"

# Each teardown step and each undo, named by the command it issues. Tests match
# on the command rather than on the function that builds it: a refactor that
# still does the same thing to the host still passes, and one that quietly
# stops doing it does not.
SWITCH_AWAY = "--template=default_letsencrypt_https"
STOP_SERVICE = "systemctl --user disable --now"
REMOVE_ORIGIN = f"virtual-host remove origin-{PROTECTED}"
RESTORE_FIXUPS = f"rm -f -- {PROTECTED_WEBROOT}/.user.ini"
REMOVE_ENV = f"rm -f -- {INSTANCE_ENV}"
REMOVE_KEY = f"rm -f -- {INSTANCE_KEY}"

SWITCH_BACK = "--template=proxy_letsencrypt_https_redirect"
START_SERVICE = "systemctl --user enable --now"
RECREATE_ORIGIN = f"virtual-host create origin-{PROTECTED}"
REINSTALL_FIXUPS = f"cat > {PROTECTED_WEBROOT}/anubis-origin-shim.php"
RESTORE_ENV = f"cat > {INSTANCE_ENV}"


class _RunnerFailingAt(FakeRunner):
    """Answers as usual until a command matches a needle, then refuses it once.

    The failure is injected at the command, not at the Python function that
    builds it, so a test says "the host refused to stop the service" rather
    than "this call raised" — which is what an operator hits, and what stays
    true across a refactor.

    ``base_responses`` replaces the canned base runner for hosts in another
    state — a prepared instance — so the same injection works there without
    a second class.
    """

    def __init__(
        self,
        *needles: str,
        base_responses: dict[str, str] | None = None,
        **responses: str,
    ):
        if base_responses is None:
            super().__init__(_base_runner(**responses).responses)
        else:
            super().__init__({**base_responses, **responses})
        self._pending = list(needles)

    def __call__(self, cmd, **kwargs):
        for needle in self._pending:
            if needle in cmd:
                self._pending.remove(needle)
                raise RuntimeError(f"the host refused: {needle}")
        return super().__call__(cmd, **kwargs)


def _issued(runner: FakeRunner, needle: str) -> bool:
    return any(needle in c for c in runner.calls)


# Each teardown step, and everything that must be back in place if it fails.
# A step that is one command is either done or not, so its own undo is absent
# from its row; the fixups are several commands and can fail half done, so
# theirs is the one row that includes its own undo.
TEARDOWN_STEPS = [
    pytest.param(SWITCH_AWAY, [], id="switching the public vhost away"),
    pytest.param(STOP_SERVICE, [SWITCH_BACK], id="stopping the service"),
    pytest.param(
        REMOVE_ORIGIN,
        [START_SERVICE, SWITCH_BACK],
        id="removing the origin vhost",
    ),
    pytest.param(
        RESTORE_FIXUPS,
        [REINSTALL_FIXUPS, RECREATE_ORIGIN, START_SERVICE, SWITCH_BACK],
        id="restoring the webroot fixups",
    ),
    pytest.param(
        REMOVE_ENV,
        [REINSTALL_FIXUPS, RECREATE_ORIGIN, START_SERVICE, SWITCH_BACK],
        id="removing the env file",
    ),
    pytest.param(
        REMOVE_KEY,
        [RESTORE_ENV, REINSTALL_FIXUPS, RECREATE_ORIGIN, START_SERVICE, SWITCH_BACK],
        id="removing the key file",
    ),
]


@pytest.mark.parametrize("failing_step,expected_undos", TEARDOWN_STEPS)
def test_a_failed_teardown_step_puts_the_preceding_ones_back(
    failing_step, expected_undos
):
    r = _RunnerFailingAt(failing_step)
    result = cmd_disable(PROTECTED, runner=r)

    assert not result.success
    assert "Disable failed" in result.error
    for undo in expected_undos:
        assert _issued(r, undo), f"{undo} was never issued"


@pytest.mark.parametrize("failing_step,expected_undos", TEARDOWN_STEPS)
def test_a_failed_teardown_reports_which_steps_were_undone(
    failing_step, expected_undos
):
    """A traceback says what broke; only the report says what state you are in."""
    r = _RunnerFailingAt(failing_step)
    result = cmd_disable(PROTECTED, runner=r)

    rolled_back = [s for s in result.steps if s.startswith("Rolled back:")]
    assert len(rolled_back) == len(expected_undos)
    assert f"Rolled back {len(expected_undos)}" in result.error


def test_a_failed_teardown_names_the_artifacts_it_put_back():
    """"Rolled back 3 steps" is a count; an operator needs the nouns."""
    r = _RunnerFailingAt(RESTORE_FIXUPS)
    result = cmd_disable(PROTECTED, runner=r)

    report = " ".join(s for s in result.steps if s.startswith("Rolled back:"))
    assert f"origin-{PROTECTED}" in report
    assert f"anubis@{PROTECTED}.service" in report
    assert PROTECTED_WEBROOT in report
    assert PROTECTED in report


def test_a_rollback_step_that_fails_names_what_needs_manual_cleanup():
    r = _RunnerFailingAt(REMOVE_ORIGIN, START_SERVICE)
    result = cmd_disable(PROTECTED, runner=r)

    assert not result.success
    warning = " ".join(result.warnings)
    assert f"anubis@{PROTECTED}.service" in warning
    assert "manual" in warning.lower()


def test_a_rollback_step_that_fails_does_not_abort_the_rest_of_the_rollback():
    """The one thing worse than a half-torn-down instance is a half-restored one."""
    r = _RunnerFailingAt(REMOVE_ORIGIN, START_SERVICE)
    cmd_disable(PROTECTED, runner=r)

    assert _issued(r, SWITCH_BACK), "the public vhost was left off Anubis"


def test_the_origin_vhost_comes_back_with_the_php_version_it_had():
    """Recreating it without PHP_VERSION serves the site's PHP as plain text."""
    r = _RunnerFailingAt(RESTORE_FIXUPS)
    cmd_disable(PROTECTED, runner=r)

    recreate = [c for c in r.calls if RECREATE_ORIGIN in c]
    assert len(recreate) == 1
    assert "--template-variable=PHP_VERSION=8.2" in recreate[0]


def test_the_env_file_comes_back_with_the_content_it_had():
    """A restored env file naming the wrong port is worse than no env file."""
    r = _RunnerFailingAt(REMOVE_KEY)
    cmd_disable(PROTECTED, runner=r)

    rewrite = [c for c in r.calls if RESTORE_ENV in c]
    assert len(rewrite) == 1
    assert "BIND=:7010" in rewrite[0]
    assert "TARGET_HOST=origin-test.example.ch" in rewrite[0]


def test_the_env_file_comes_back_at_the_mode_it_had():
    """It names the key's path and the instance's ports — nobody else's business."""
    r = _RunnerFailingAt(REMOVE_KEY)
    cmd_disable(PROTECTED, runner=r)

    rewrite = [c for c in r.calls if RESTORE_ENV in c]
    assert "umask 177" in rewrite[0].splitlines()


def test_a_webroot_with_no_fixups_does_not_gain_any_from_a_rollback():
    """`restore` is a no-op there, so its undo must be one too.

    A shared webroot whose sibling is not behind Anubis is the case: installing
    a shim and an .htaccess block that were never there is not putting the host
    back as we found it, it is changing somebody else's site.
    """
    r = _RunnerFailingAt(REMOVE_ENV, **{
        # Nothing in the webroot: no .user.ini, no .htaccess, no shim, no chain.
        # (The env and key reads keep their own, more specific, answers.)
        _SU + "test -f": "no\n",
        _SU + "cat --": "__NINE_SU_FILE_NOT_FOUND__",
    })
    result = cmd_disable(PROTECTED, runner=r)

    assert not result.success
    assert not _issued(r, REINSTALL_FIXUPS), "a rollback installed fixups"
    assert any("No fixup files to restore" in s for s in result.steps)


def test_a_disable_that_completes_reports_no_rollback():
    r = _base_runner()
    result = cmd_disable(PROTECTED, runner=r)

    assert result.success
    assert not any(s.startswith("Rolled back") for s in result.steps)


# --- disable refcounts against a fresh listing --------------------------------
#
# Whether this is the last vhost on the port used to be decided from a listing
# taken before the public vhost was switched away, and never re-checked. A
# concurrent enable landing in that window made disable tear down an instance
# other live vhosts were still proxying to.

# What the vhost list says once a concurrent `enable` has put a second site on
# port 7010 and our own switch has landed.
VHOSTS_AFTER_A_CONCURRENT_ENABLE = """[
  {"domain": "test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []},
  {"domain": "blog.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []},
  {"domain": "origin-test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "default_snakeoil_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
]"""

_VHOST_LIST = "sudo nine-manage-vhosts virtual-host list --json"


class _RunnerGainingAVhostDuringTheSwitch(FakeRunner):
    """A host on which another vhost joins the port while disable is running.

    The canned listing is rewritten the moment the public vhost is switched
    away — a concurrent `enable` landing in exactly the window the teardown
    decision used to be made before.
    """

    def __init__(self):
        super().__init__(_base_runner().responses)

    def __call__(self, cmd, **kwargs):
        if SWITCH_AWAY in cmd:
            self.responses[_VHOST_LIST] = VHOSTS_AFTER_A_CONCURRENT_ENABLE
        return super().__call__(cmd, **kwargs)


def _teardown_was_attempted(runner: FakeRunner) -> bool:
    return any(
        _issued(runner, needle)
        for needle in (STOP_SERVICE, REMOVE_ORIGIN, RESTORE_FIXUPS, REMOVE_ENV)
    )


def test_a_vhost_that_joins_the_port_during_the_switch_saves_the_instance():
    r = _RunnerGainingAVhostDuringTheSwitch()
    result = cmd_disable(PROTECTED, runner=r)

    assert result.success
    assert not _teardown_was_attempted(r), "an instance other sites use was torn down"


def test_a_vhost_that_joins_the_port_during_the_switch_is_named_in_the_report():
    r = _RunnerGainingAVhostDuringTheSwitch()
    result = cmd_disable(PROTECTED, runner=r)

    report = " ".join(result.steps)
    assert "blog.example.ch" in report
    assert "left running" in report


def test_the_vhost_asked_about_is_still_switched_off_anubis():
    """Sparing the instance is not the same as refusing the operator's request."""
    r = _RunnerGainingAVhostDuringTheSwitch()
    result = cmd_disable(PROTECTED, runner=r)

    assert _issued(r, SWITCH_AWAY)
    assert any("Switched" in s for s in result.steps)


# --- disable tears down an instance that was prepared but never cut over ------
#
# `enable --prepare-only` leaves a whole instance behind — env file, key,
# running service, origin vhost, fixups — while the public vhost is still on
# its old template. The proxy template therefore cannot be how a disable knows
# the instance exists: the env file's port claim is the marker, and the
# teardown that follows it is the cut-over path's own, minus the template
# switch there is nothing to switch back.

PREPARED = "prepared.example.ch"
PREPARED_WEBROOT = "/home/www-anubis/prepared.example.ch"
PREPARED_PORT = 7020
PREPARED_ENV = f"/home/www-anubis/.config/anubis/{PREPARED}.env"
PREPARED_KEY = f"/home/www-anubis/.config/anubis/{PREPARED}.key"

# The state `enable --prepare-only` leaves behind: the public vhost on its
# original template, the origin vhost and the env file all present, nothing on
# the proxy template.
VHOSTS_PREPARED = json.dumps([
    {
        "domain": PREPARED,
        "user": "www-anubis",
        "webroot": PREPARED_WEBROOT,
        "template": "default_letsencrypt_https",
        "template_variables": {"TIMEOUT": "300", "PHP_VERSION": "8.2", "MODSEC": "Off"},
        "aliases": [],
        "jobs": [],
    },
    {
        "domain": f"origin-{PREPARED}",
        "user": "www-anubis",
        "webroot": PREPARED_WEBROOT,
        "template": "default_snakeoil_https",
        "template_variables": {"PHP_VERSION": "8.2"},
        "aliases": [],
        "jobs": [],
    },
])


def _prepared_runner(**overrides) -> FakeRunner:
    """Runner for the state `enable --prepare-only` leaves behind."""
    responses = {
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_PREPARED,
        _SU + f"cat -- {PREPARED_ENV}": (
            f"BIND=:{PREPARED_PORT}\nMETRICS_BIND=:{PREPARED_PORT + 1}\n"
            f"TARGET_HOST=origin-{PREPARED}\n"
        ),
        _SU + f"cat -- {PREPARED_KEY}": "0123456789abcdef\n",
    }
    responses.update(overrides)
    return _base_runner(**responses)


PREP_REMOVE_ORIGIN = f"virtual-host remove origin-{PREPARED}"
PREP_RECREATE_ORIGIN = f"virtual-host create origin-{PREPARED}"
PREP_RESTORE_FIXUPS = f"rm -f -- {PREPARED_WEBROOT}/.user.ini"
PREP_REINSTALL_FIXUPS = f"cat > {PREPARED_WEBROOT}/anubis-origin-shim.php"
PREP_REMOVE_ENV = f"rm -f -- {PREPARED_ENV}"
PREP_REMOVE_KEY = f"rm -f -- {PREPARED_KEY}"
PREP_RESTORE_ENV = f"cat > {PREPARED_ENV}"


def test_disable_tears_down_an_instance_that_was_prepared_but_never_cut_over():
    r = _prepared_runner()
    result = cmd_disable(PREPARED, runner=r)

    assert result.success
    report = " ".join(result.steps)
    assert "Stopped" in report
    assert f"origin-{PREPARED}" in report
    assert "env file + key" in report
    assert not any("Switched" in s for s in result.steps)
    assert not _issued(r, SWITCH_AWAY)
    assert _issued(r, STOP_SERVICE)
    assert _issued(r, PREP_REMOVE_ORIGIN)
    assert _issued(r, PREP_REMOVE_ENV)
    assert _issued(r, PREP_REMOVE_KEY)


def test_disable_dry_run_prepared_skips_the_switch_and_describes_the_teardown():
    r = _prepared_runner()
    result = cmd_disable(PREPARED, runner=r, dry_run=True)

    assert result.success
    report = " ".join(result.steps)
    assert "tear down" in report
    assert f"Switch {PREPARED} back" not in report


def test_an_env_file_that_claims_no_port_pair_is_still_not_behind_anubis():
    """The env file is the marker only because it records the pair."""
    r = _prepared_runner(**{
        _SU + f"cat -- {PREPARED_ENV}": (
            f"METRICS_BIND=:{PREPARED_PORT + 1}\n"
            f"TARGET_HOST=origin-{PREPARED}\n"
        ),
    })
    result = cmd_disable(PREPARED, runner=r)

    assert not result.success
    assert "not behind Anubis" in result.error
    assert not _issued(r, SWITCH_AWAY)


def test_a_prepared_domain_sharing_its_port_with_a_live_vhost_is_left_running():
    vhosts = """[
      {"domain": "prepared.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/prepared.example.ch", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []},
      {"domain": "blog.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/prepared.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7020"}, "aliases": [], "jobs": []},
      {"domain": "origin-prepared.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/prepared.example.ch", "template": "default_snakeoil_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
    ]"""
    r = _prepared_runner(**{
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
    })
    result = cmd_disable(PREPARED, runner=r)

    assert result.success
    report = " ".join(result.steps)
    assert "still serving" in report
    assert "blog.example.ch" in report
    assert "left running" in report
    assert not _teardown_was_attempted(r)
    assert not _issued(r, SWITCH_AWAY)


# The prepared path's teardown steps and what must be back in place when each
# fails. Same rows as TEARDOWN_STEPS, minus the template switch and its undo:
# a prepared public vhost was never on Anubis, so there is nothing to switch.
PREPARED_TEARDOWN_STEPS = [
    pytest.param(STOP_SERVICE, [], id="stopping the service"),
    pytest.param(PREP_REMOVE_ORIGIN, [START_SERVICE], id="removing the origin vhost"),
    pytest.param(
        PREP_RESTORE_FIXUPS,
        [PREP_REINSTALL_FIXUPS, PREP_RECREATE_ORIGIN, START_SERVICE],
        id="restoring the webroot fixups",
    ),
    pytest.param(
        PREP_REMOVE_ENV,
        [PREP_REINSTALL_FIXUPS, PREP_RECREATE_ORIGIN, START_SERVICE],
        id="removing the env file",
    ),
    pytest.param(
        PREP_REMOVE_KEY,
        [PREP_RESTORE_ENV, PREP_REINSTALL_FIXUPS, PREP_RECREATE_ORIGIN, START_SERVICE],
        id="removing the key file",
    ),
]


@pytest.mark.parametrize("failing_step,expected_undos", PREPARED_TEARDOWN_STEPS)
def test_a_failed_prepared_teardown_step_puts_the_preceding_ones_back(
    failing_step, expected_undos
):
    r = _RunnerFailingAt(failing_step, base_responses=_prepared_runner().responses)
    result = cmd_disable(PREPARED, runner=r)

    assert not result.success
    assert "Disable failed" in result.error
    for undo in expected_undos:
        assert _issued(r, undo), f"{undo} was never issued"


@pytest.mark.parametrize("failing_step,expected_undos", PREPARED_TEARDOWN_STEPS)
def test_a_failed_prepared_teardown_reports_which_steps_were_undone(
    failing_step, expected_undos
):
    r = _RunnerFailingAt(failing_step, base_responses=_prepared_runner().responses)
    result = cmd_disable(PREPARED, runner=r)

    rolled_back = [s for s in result.steps if s.startswith("Rolled back:")]
    assert len(rolled_back) == len(expected_undos)
    assert f"Rolled back {len(expected_undos)}" in result.error


def test_a_failed_prepared_teardown_never_touches_the_public_vhost():
    """The deepest failure would undo the most steps — none of them a switch."""
    r = _RunnerFailingAt(PREP_REMOVE_KEY, base_responses=_prepared_runner().responses)
    result = cmd_disable(PREPARED, runner=r)

    assert not result.success
    assert not _issued(r, SWITCH_AWAY)
    assert not _issued(r, SWITCH_BACK)


class _PreparedHostSim(FakeRunner):
    """A host that keeps the facts `enable` writes and `disable` removes.

    The vhost list and the instance's env and key files are real state here —
    the env file stops being listed once it is removed, the origin vhost stops
    existing once it is removed — because those are what `uninstall`'s
    instance scan reads to decide whether anything is left. Everything else
    answers from the canned base runner.
    """

    def __init__(self):
        super().__init__(_base_runner().responses)
        self.vhosts: list[dict] = [
            {
                "domain": PREPARED,
                "user": "www-anubis",
                "webroot": PREPARED_WEBROOT,
                "template": "default_letsencrypt_https",
                "template_variables": {},
                "aliases": [],
                "jobs": [],
            },
        ]
        self.env_files: dict[str, str] = {}
        self.key_files: dict[str, str] = {}

    def __call__(self, cmd, **kwargs):
        canned = super().__call__(cmd, **kwargs)

        if cmd.startswith("sudo nine-manage-vhosts virtual-host list --json"):
            return json.dumps(self.vhosts)
        if cmd.startswith("sudo nine-manage-vhosts virtual-host create "):
            self.vhosts.append(self._parse_create(cmd))
            return ""
        if cmd.startswith("sudo nine-manage-vhosts virtual-host remove "):
            domain = cmd.split("virtual-host remove ", 1)[1].split()[0]
            self.vhosts = [vh for vh in self.vhosts if vh["domain"] != domain]
            return ""
        if "ls ~/.config/anubis/*.env" in cmd:
            return "".join(f"{path}\n" for path in sorted(self.env_files))
        if "rm -f -- " in cmd:
            for word in cmd.split():
                if "/.config/anubis/" in word:
                    self.env_files.pop(word, None)
                    self.key_files.pop(word, None)
        if "cat -- " in cmd:
            for path, content in {**self.env_files, **self.key_files}.items():
                if f"cat -- {path}" in cmd:
                    return content
        for path, content in self._heredoc_writes(cmd):
            if path.endswith(".env"):
                self.env_files[path] = content
            elif path.endswith(".key"):
                self.key_files[path] = content
        return canned

    @staticmethod
    def _heredoc_writes(cmd: str) -> list[tuple[str, str]]:
        return [
            (path, body)
            for path, body in re.findall(
                r"cat > (\S+) <<'FILE_EOF(?:_[0-9a-f]+)?'\n(.*?)\nFILE_EOF(?:_[0-9a-f]+)?(?!\S)",
                cmd,
                re.DOTALL,
            )
        ]

    @staticmethod
    def _parse_create(cmd: str) -> dict:
        parts = cmd[len("sudo nine-manage-vhosts virtual-host create "):].split()
        opts: dict[str, str] = {}
        tv: dict[str, str] = {}
        for word in parts[1:]:
            if word.startswith("--template-variable="):
                key, _, value = word[len("--template-variable="):].partition("=")
                tv[key] = value
            elif word.startswith("--") and "=" in word:
                key, _, value = word.partition("=")
                opts[key[2:]] = value
        return {
            "domain": parts[0],
            "user": opts["user"],
            "webroot": opts.get("webroot", ""),
            "template": opts["template"],
            "template_variables": tv,
            "aliases": [],
            "jobs": [],
        }


def test_prepare_only_then_disable_leaves_nothing_behind_and_uninstall_proceeds():
    host = _PreparedHostSim()

    prepared = cmd_enable(PREPARED, runner=host, prepare_only=True)
    assert prepared.success
    assert PREPARED_ENV in host.env_files
    assert PREPARED_KEY in host.key_files
    assert any(vh["domain"] == f"origin-{PREPARED}" for vh in host.vhosts)

    disabled = cmd_disable(PREPARED, runner=host)
    assert disabled.success
    assert not host.env_files
    assert not host.key_files
    assert not any(vh["domain"].startswith("origin-") for vh in host.vhosts)

    uninstall = cmd_uninstall(runner=host)
    assert uninstall.success
