"""Tests for ports.py — port discovery & allocation.

Uses a FakeRunner to inject canned command outputs. The nine-su commands
are now heredoc-based (sudo nine-su <user> <<'EOF' ... EOF) instead of
the broken -c pattern.
"""

import pytest

from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.validate import ValidationError
from nine_manage_anubis.ports import (
    AnubisInstance,
    PortAllocation,
    PORT_RANGE_START,
    PORT_RANGE_END,
    _parse_vhosts_json,
    _is_anubis_proxy,
    _get_proxy_port,
    find_instance_for_webroot,
    find_vhosts_for_port,
    get_vhost,
    _parse_ss_output,
    get_listening_ports,
    _parse_env_file,
    _find_anubis_users,
    get_claimed_ports,
    _get_service_state,
    discover_instances,
    _all_used_ports,
    next_free_pair,
    allocate_for_domain,
    find_port_for_domain,
    find_prepared_port_for_webroot,
)

# --- Sample data --------------------------------------------------------------

VHOSTS_JSON = """[
  {"domain": "example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7014"}, "aliases": ["example.ch.web04.nine.ch"], "jobs": []},
  {"domain": "blog.example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7014"}, "aliases": ["blog.example.ch.web04.nine.ch"], "jobs": []},
  {"domain": "app.example.ch", "user": "www-example", "webroot": "/home/www-example/app.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7012"}, "aliases": [], "jobs": []},
  {"domain": "test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []},
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/example.com", "template": "default_letsencrypt_https", "template_variables": {"TIMEOUT": "300", "PHP_VERSION": "8.2", "MODSEC": "Off"}, "aliases": [], "jobs": []},
  {"domain": "origin-example.ch", "user": "www-example", "webroot": "/home/www-example/example.ch", "template": "default_snakeoil_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
]"""

SS_OUTPUT = """State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN  0       4096    0.0.0.0:7010         0.0.0.0:*          users:(("anubis",pid=1234,fd=3))
LISTEN  0       4096    0.0.0.0:7011         0.0.0.0:*          users:(("anubis",pid=1234,fd=4))
LISTEN  0       4096    0.0.0.0:7012         0.0.0.0:*          users:(("anubis",pid=1235,fd=3))
LISTEN  0       4096    0.0.0.0:7013         0.0.0.0:*          users:(("anubis",pid=1235,fd=4))
LISTEN  0       4096    0.0.0.0:7014         0.0.0.0:*          users:(("anubis",pid=1236,fd=3))
LISTEN  0       4096    0.0.0.0:7015         0.0.0.0:*          users:(("anubis",pid=1236,fd=4))
LISTEN  0       4096    0.0.0.0:8443         0.0.0.0:*          users:(("apache2",pid=5678,fd=5))
"""

ENV_EXAMPLE = """# Anubis instance for example.ch
BIND=:7014
METRICS_BIND=:7015
TARGET=https://127.0.0.1:443
TARGET_HOST=origin-example.ch
ED25519_PRIVATE_KEY_HEX_FILE=/home/www-anubis/.config/anubis/example.ch.key
"""

ENV_DEMOVOX = """BIND=:7012
METRICS_BIND=:7013
TARGET_HOST=origin-app.example.ch
"""

ENV_TEST = """BIND=:7010
METRICS_BIND=:7011
TARGET_HOST=origin-test.example.ch
"""

_SU_PREFIX = "sudo nine-su www-anubis <<'NINE_SU_EOF'\n"


def _su_key(script: str) -> str:
    """Build a FakeRunner key matching a nine-su heredoc command."""
    return _SU_PREFIX + script


def _runner_with_data(**overrides) -> FakeRunner:
    responses = {
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS_JSON,
        "ss -tlnp": SS_OUTPUT,
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n/home/www-example/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        "test -d /home/www-example/.config/anubis && echo yes || echo no": "no",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"): (
            "/home/www-anubis/.config/anubis/test.example.ch.env\n"
            "/home/www-anubis/.config/anubis/example.ch.env\n"
            "/home/www-anubis/.config/anubis/app.example.ch.env\n"
        ),
        _su_key("cat '/home/www-anubis/.config/anubis/test.example.ch.env'"): ENV_TEST,
        _su_key("cat '/home/www-anubis/.config/anubis/example.ch.env'"): ENV_EXAMPLE,
        _su_key("cat '/home/www-anubis/.config/anubis/app.example.ch.env'"): ENV_DEMOVOX,
        _su_key("export XDG_RUNTIME_DIR"): "active",
        _su_key("/home/www-anubis/bin/anubis --version"): "Anubis version 1.27.0\n",
    }
    responses.update(overrides)
    return FakeRunner(responses)


# --- Vhost parsing tests ------------------------------------------------------


def test_parse_vhosts_json():
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": VHOSTS_JSON})
    vhosts = _parse_vhosts_json(r)
    assert len(vhosts) == 6
    assert vhosts[0]["domain"] == "example.ch"


def test_is_anubis_proxy():
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": VHOSTS_JSON})
    vhosts = _parse_vhosts_json(r)
    assert _is_anubis_proxy(vhosts[0])
    assert not _is_anubis_proxy(vhosts[4])
    assert not _is_anubis_proxy(vhosts[5])


def test_get_proxy_port():
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": VHOSTS_JSON})
    vhosts = _parse_vhosts_json(r)
    assert _get_proxy_port(vhosts[0]) == 7014
    assert _get_proxy_port(vhosts[4]) is None


def test_get_vhost():
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": VHOSTS_JSON})
    vh = get_vhost("example.ch", r)
    assert vh is not None
    assert vh["webroot"] == "/home/www-example/example.ch"
    assert get_vhost("nonexistent.com", r) is None


# --- Multisite reuse tests ----------------------------------------------------


def test_find_instance_for_webroot_match():
    r = _runner_with_data()
    port = find_instance_for_webroot("/home/www-example/example.ch", r)
    assert port == 7014


def test_find_instance_for_webroot_no_match():
    r = _runner_with_data()
    port = find_instance_for_webroot("/home/www-example/example.com", r)
    assert port is None


def test_find_vhosts_for_port():
    r = _runner_with_data()
    vhosts = find_vhosts_for_port(7014, r)
    assert sorted(vhosts) == ["blog.example.ch", "example.ch"]
    assert len(vhosts) == 2


def test_find_vhosts_for_port_single():
    r = _runner_with_data()
    vhosts = find_vhosts_for_port(7010, r)
    assert vhosts == ["test.example.ch"]


# --- ss parsing tests ---------------------------------------------------------


def test_parse_ss_output():
    ports = _parse_ss_output(SS_OUTPUT)
    assert 7010 in ports
    assert 7011 in ports
    assert 7014 in ports
    assert 7015 in ports
    assert 8443 not in ports
    assert len(ports) == 6


def test_get_listening_ports():
    r = FakeRunner({"ss -tlnp": SS_OUTPUT})
    ports = get_listening_ports(r)
    assert ports == {7010, 7011, 7012, 7013, 7014, 7015}


# --- Env file parsing tests ---------------------------------------------------


def test_parse_env_file():
    env = _parse_env_file(ENV_EXAMPLE)
    assert env["BIND"] == ":7014"
    assert env["METRICS_BIND"] == ":7015"
    assert env["TARGET_HOST"] == "origin-example.ch"


def test_find_anubis_users():
    r = _runner_with_data()
    users = _find_anubis_users(r)
    assert "www-anubis" in users
    assert "www-example" not in users


def test_get_claimed_ports():
    r = _runner_with_data()
    claimed = get_claimed_ports(r)
    assert 7014 in claimed
    assert claimed[7014] == ("www-anubis", "example.ch")
    assert 7010 in claimed
    assert claimed[7010] == ("www-anubis", "test.example.ch")
    assert 7012 in claimed


# --- Service state tests ------------------------------------------------------


def test_get_service_state_active():
    r = FakeRunner({_su_key("export XDG_RUNTIME_DIR"): "active\n"})
    state = _get_service_state("www-anubis", "example.ch", r)
    assert state == "active"


def test_get_service_state_not_found():
    r = FakeRunner()
    state = _get_service_state("www-anubis", "nonexistent.com", r)
    assert state == "not-found"


def test_get_service_state_tolerates_nonzero_exit():
    """`systemctl is-active` exits 3 for any non-active unit — discovery
    must still report the state instead of the Runner raising."""
    r = FakeRunner()
    _get_service_state("www-anubis", "example.ch", r)
    assert "is-active anubis@example.ch.service || true" in r.calls[0]


def test_get_service_state_failed():
    r = FakeRunner({_su_key("export XDG_RUNTIME_DIR"): "failed\n"})
    assert _get_service_state("www-anubis", "example.ch", r) == "failed"


# --- Instance discovery tests -------------------------------------------------


def test_discover_instances():
    r = _runner_with_data()
    instances = discover_instances(r)
    ports = [inst.port for inst in instances]
    assert 7010 in ports
    assert 7012 in ports
    assert 7014 in ports
    example = next(i for i in instances if i.port == 7014)
    assert len(example.vhosts) == 2
    assert "example.ch" in example.vhosts
    assert "blog.example.ch" in example.vhosts


# --- Port allocation tests ----------------------------------------------------


def test_all_used_ports():
    r = _runner_with_data()
    used = _all_used_ports(r)
    assert 7010 in used
    assert 7011 in used
    assert 7012 in used
    assert 7014 in used


def test_next_free_pair_empty_host():
    r = FakeRunner({
        "sudo nine-manage-vhosts virtual-host list --json": "[]",
        "ss -tlnp": "",
        "ls -d /home/www-*/ 2>/dev/null": "",
    })
    app, metrics = next_free_pair(r)
    assert app == 7010
    assert metrics == 7011


def test_next_free_pair_with_existing():
    r = _runner_with_data()
    app, metrics = next_free_pair(r)
    assert app == 7016
    assert metrics == 7017


def test_next_free_pair_skips_odd_allocated():
    r = FakeRunner({
        "sudo nine-manage-vhosts virtual-host list --json": """[
          {"domain": "a.com", "user": "www-anubis", "webroot": "/home/www-anubis/a.com", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []},
          {"domain": "b.com", "user": "www-anubis", "webroot": "/home/www-anubis/b.com", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7012"}, "aliases": [], "jobs": []}
        ]""",
        "ss -tlnp": 'LISTEN 0 4096 0.0.0.0:7010 0.0.0.0:* users:(("anubis",pid=1,fd=3))\nLISTEN 0 4096 0.0.0.0:7012 0.0.0.0:* users:(("anubis",pid=2,fd=3))\n',
        "ls -d /home/www-*/ 2>/dev/null": "",
    })
    app, metrics = next_free_pair(r)
    assert app == 7014
    assert metrics == 7015


# --- Allocation for domain tests ----------------------------------------------


def test_allocate_for_domain_new():
    r = _runner_with_data()
    alloc = allocate_for_domain("example.com", r)
    assert not alloc.is_reused
    assert alloc.app_port == 7016
    assert alloc.metrics_port == 7017


def test_allocate_for_domain_multisite_reuse():
    r = _runner_with_data()
    alloc = allocate_for_domain("blog.example.ch", r)
    assert alloc.is_reused
    assert alloc.app_port == 7014
    assert alloc.reused_from == "example.ch"


def test_allocate_for_domain_not_found():
    r = _runner_with_data()
    try:
        allocate_for_domain("nonexistent.com", r)
        assert False, "should have raised"
    except ValueError:
        pass


def test_find_port_for_domain():
    r = _runner_with_data()
    assert find_port_for_domain("example.ch", r) == 7014
    assert find_port_for_domain("app.example.ch", r) == 7012
    assert find_port_for_domain("nonexistent.com", r) is None


def test_allocate_for_domain_with_existing_env_file():
    """A prepared-but-not-yet-cut-over domain must reuse its env-file port.

    This is the --prepare-only then --cutover-only scenario: the vhost
    template is still default_letsencrypt_https, but an env file exists
    from the prepare step. allocate_for_domain must read the port from
    the env file rather than allocating a new pair.
    """
    env_example = "BIND=:7020\nMETRICS_BIND=:7021\nTARGET_HOST=origin-example.com\n"
    r = _runner_with_data(**{
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"): (
            "/home/www-anubis/.config/anubis/test.example.ch.env\n"
            "/home/www-anubis/.config/anubis/example.ch.env\n"
            "/home/www-anubis/.config/anubis/app.example.ch.env\n"
            "/home/www-anubis/.config/anubis/example.com.env\n"
        ),
        _su_key("cat '/home/www-anubis/.config/anubis/example.com.env'"): env_example,
    })
    alloc = allocate_for_domain("example.com", r)
    assert not alloc.is_reused
    assert alloc.app_port == 7020
    assert alloc.metrics_port == 7021


def test_find_prepared_port_for_webroot():
    """find_prepared_port_for_webroot finds env file of a sibling domain."""
    # example.com shares webroot with example2.com (both /home/www-example/example.com)
    vhosts = VHOSTS_JSON.replace(
        '"example.com"',
        '"example.com","webroot": "/home/www-example/example.com","template": "default_letsencrypt_https","template_variables": {"TIMEOUT": "300","PHP_VERSION": "8.2","MODSEC": "Off"}, "aliases": [], "jobs": []},'
        '\n  {"domain": "example2.com", "user": "www-example"'
    )
    # Actually, let's build clean vhost data
    vhosts = """[
  {"domain": "site-a.ch", "user": "www-example", "webroot": "/home/www-example/shared", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []},
  {"domain": "site-b.ch", "user": "www-example", "webroot": "/home/www-example/shared", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []},
  {"domain": "other.com", "user": "www-example", "webroot": "/home/www-example/other", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
]"""
    env_a = "BIND=:7020\nMETRICS_BIND=:7021\nTARGET_HOST=origin-site-a.ch\n"
    r = FakeRunner({
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
        "ss -tlnp": "",
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n/home/www-example/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        "test -d /home/www-example/.config/anubis && echo yes || echo no": "no",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"): (
            "/home/www-anubis/.config/anubis/site-a.ch.env\n"
        ),
        _su_key("cat '/home/www-anubis/.config/anubis/site-a.ch.env'"): env_a,
    })
    port = find_prepared_port_for_webroot("/home/www-example/shared", runner=r)
    assert port == 7020


def test_find_prepared_port_for_webroot_no_match():
    """Returns None when no sibling has an env file."""
    vhosts = """[
  {"domain": "site-a.ch", "user": "www-example", "webroot": "/home/www-example/shared", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
]"""
    r = FakeRunner({
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"): "",
    })
    port = find_prepared_port_for_webroot("/home/www-example/shared", runner=r)
    assert port is None


def test_allocate_for_domain_reuses_prepared_sibling():
    """During --prepare-only, a domain sharing a webroot with an already-prepared
    sibling must reuse the sibling's port instead of allocating a new pair.

    Without this, each domain in a shared-webroot group gets its own instance
    during prepare, and the cutover later reassigns them all to the first
    domain's instance — leaving the others as orphans.
    """
    vhosts = """[
  {"domain": "site-a.ch", "user": "www-example", "webroot": "/home/www-example/shared", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7020"}, "aliases": [], "jobs": []},
  {"domain": "site-b.ch", "user": "www-example", "webroot": "/home/www-example/shared", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
]"""
    env_a = "BIND=:7020\nMETRICS_BIND=:7021\nTARGET_HOST=origin-site-a.ch\n"
    r = FakeRunner({
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
        "ss -tlnp": "LISTEN 0 4096 0.0.0.0:7020 0.0.0.0:* users:((\"anubis\",pid=1,fd=3))\n",
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n/home/www-example/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        "test -d /home/www-example/.config/anubis && echo yes || echo no": "no",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"): (
            "/home/www-anubis/.config/anubis/site-a.ch.env\n"
        ),
        _su_key("cat '/home/www-anubis/.config/anubis/site-a.ch.env'"): env_a,
    })
    # site-b.ch shares webroot with site-a.ch which is already behind Anubis
    alloc = allocate_for_domain("site-b.ch", r)
    assert alloc.is_reused
    assert alloc.app_port == 7020
    assert alloc.reused_from == "site-a.ch"


def test_allocate_for_domain_reuses_prepared_sibling_not_yet_cut_over():
    """During --prepare-only (no proxy vhost yet), a domain sharing a webroot
    with an already-prepared sibling must reuse the sibling's env-file port.

    This is the key orphan-prevention test: neither domain is behind Anubis
    yet, but site-a.ch has an env file from being prepared first in the batch.
    site-b.ch must reuse that port, not allocate a new one.
    """
    vhosts = """[
  {"domain": "site-a.ch", "user": "www-example", "webroot": "/home/www-example/shared", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []},
  {"domain": "site-b.ch", "user": "www-example", "webroot": "/home/www-example/shared", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
]"""
    env_a = "BIND=:7020\nMETRICS_BIND=:7021\nTARGET_HOST=origin-site-a.ch\n"
    r = FakeRunner({
        "sudo nine-manage-vhosts virtual-host list --json": vhosts,
        "ss -tlnp": "LISTEN 0 4096 0.0.0.0:7020 0.0.0.0:* users:((\"anubis\",pid=1,fd=3))\n",
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n/home/www-example/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        "test -d /home/www-example/.config/anubis && echo yes || echo no": "no",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"): (
            "/home/www-anubis/.config/anubis/site-a.ch.env\n"
        ),
        _su_key("cat '/home/www-anubis/.config/anubis/site-a.ch.env'"): env_a,
    })
    # Neither is behind Anubis, but site-a.ch has an env file
    alloc = allocate_for_domain("site-b.ch", r)
    assert alloc.is_reused
    assert alloc.app_port == 7020
    assert alloc.reused_from == "site-a.ch"


# --- Untrusted input from nine-manage-vhosts JSON -----------------------------
#
# The JSON comes back from a privileged command, but its contents are
# operator-supplied strings that get interpolated straight into further
# sudo commands. Treat them as untrusted.


def test_parse_vhosts_json_rejects_injected_domain():
    hostile = """[
  {"domain": "evil.com; id", "user": "www-example", "webroot": "/home/www-example/x", "template": "default_letsencrypt_https", "template_variables": {}}
]"""
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": hostile})
    with pytest.raises(ValidationError) as exc:
        _parse_vhosts_json(r)
    assert "evil.com; id" in str(exc.value)


def test_parse_vhosts_json_rejects_injected_user():
    hostile = """[
  {"domain": "example.com", "user": "www-example`id`", "webroot": "/home/www-example/x", "template": "default_letsencrypt_https", "template_variables": {}}
]"""
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": hostile})
    with pytest.raises(ValidationError) as exc:
        _parse_vhosts_json(r)
    assert "www-example`id`" in str(exc.value)


def test_parse_vhosts_json_rejects_injected_proxyport():
    hostile = """[
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/x", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010; id"}}
]"""
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": hostile})
    with pytest.raises(ValidationError):
        _parse_vhosts_json(r)


def test_parse_vhosts_json_tolerates_entry_without_user():
    """Not every vhost record is guaranteed to carry a user field."""
    sparse = """[
  {"domain": "example.com", "webroot": "/home/www-example/x", "template": "default_letsencrypt_https", "template_variables": {}}
]"""
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": sparse})
    assert _parse_vhosts_json(r)[0]["domain"] == "example.com"


def test_parse_vhosts_json_rejects_non_list():
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": '{"domain": "x"}'})
    with pytest.raises(ValidationError):
        _parse_vhosts_json(r)


def test_get_vhost_rejects_injected_lookup_domain():
    r = _runner_with_data()
    with pytest.raises(ValidationError):
        get_vhost("example.com; id", r)
    assert r.calls == []


def test_find_instance_for_webroot_rejects_injected_webroot():
    r = _runner_with_data()
    with pytest.raises(ValidationError):
        find_instance_for_webroot("/home/www-example/x; id", r)
    assert r.calls == []


def test_allocate_for_domain_rejects_injected_domain():
    r = _runner_with_data()
    with pytest.raises(ValidationError):
        allocate_for_domain("example.com$(id)", r)
    assert r.calls == []


# --- Untrusted input from env-file scanning -----------------------------------


def test_find_anubis_users_skips_directory_names_that_are_not_users():
    """/home holds whatever the operator put there. A name that can't be a
    system user is skipped — never interpolated into the probe command, and
    never fatal, because one odd directory must not take down the whole scan."""
    r = FakeRunner({
        "ls -d /home/www-*/ 2>/dev/null": (
            "/home/www-evil`id`/\n"
            "/home/www-old.bak/\n"
            "/home/www-anubis/\n"
        ),
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
    })
    assert _find_anubis_users(r) == ["www-anubis"]
    assert not any("www-evil" in c for c in r.calls[1:])
    assert not any("www-old.bak" in c for c in r.calls[1:])


def test_get_claimed_ports_rejects_injected_env_filename():
    r = FakeRunner({
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"):
            "/home/www-anubis/.config/anubis/evil.com; id.env\n",
    })
    with pytest.raises(ValidationError) as exc:
        get_claimed_ports(r)
    assert "evil.com; id" in str(exc.value)


def _env_scan_runner(env_content: str, stem: str = "example.com") -> FakeRunner:
    return FakeRunner({
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"):
            f"/home/www-anubis/.config/anubis/{stem}.env\n",
        _su_key(f"cat '/home/www-anubis/.config/anubis/{stem}.env'"): env_content,
    })


def test_get_claimed_ports_rejects_absurd_bind_port():
    """Not a plausible TCP port at all — the env file is corrupt."""
    with pytest.raises(ValidationError):
        get_claimed_ports(_env_scan_runner("BIND=:99999\n"))


def test_get_claimed_ports_skips_bind_port_outside_the_anubis_range():
    """A valid port that isn't ours to claim is skipped, not fatal — the same
    way discover_instances() filters out-of-range vhosts. Aborting here would
    take down `status` for the whole host over one stray env file."""
    assert get_claimed_ports(_env_scan_runner("BIND=:3000\n")) == {}


def test_get_claimed_ports_claims_bind_port_inside_the_anubis_range():
    claimed = get_claimed_ports(_env_scan_runner("BIND=:7010\n"))
    assert claimed == {7010: ("www-anubis", "example.com")}


def test_get_claimed_ports_rejects_env_stem_that_is_not_a_domain():
    """The stem becomes the systemd instance name, so it has to be a domain.
    Deliberately fatal: a file we don't recognise in our own config directory
    is either corruption or someone else's doing."""
    with pytest.raises(ValidationError) as exc:
        get_claimed_ports(_env_scan_runner("BIND=:7010\n", stem="not_a_domain"))
    assert "not_a_domain" in str(exc.value)


def test_get_claimed_ports_ignores_env_file_without_bind():
    r = FakeRunner({
        "ls -d /home/www-*/ 2>/dev/null": "/home/www-anubis/\n",
        "test -d /home/www-anubis/.config/anubis && echo yes || echo no": "yes",
        _su_key("ls ~/.config/anubis/*.env 2>/dev/null"):
            "/home/www-anubis/.config/anubis/example.com.env\n",
        _su_key("cat '/home/www-anubis/.config/anubis/example.com.env'"):
            "TARGET_HOST=origin-example.com\n",
    })
    assert get_claimed_ports(r) == {}


def test_parse_vhosts_json_rejects_injected_webroot():
    hostile = """[
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/x; id", "template": "default_letsencrypt_https", "template_variables": {}}
]"""
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": hostile})
    with pytest.raises(ValidationError) as exc:
        _parse_vhosts_json(r)
    assert "/home/www-example/x; id" in str(exc.value)


def test_parse_vhosts_json_rejects_injected_php_version():
    """PHP_VERSION is copied into the origin vhost's --template-variable."""
    hostile = """[
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/x", "template": "default_letsencrypt_https", "template_variables": {"PHP_VERSION": "8.2; id"}}
]"""
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": hostile})
    with pytest.raises(ValidationError) as exc:
        _parse_vhosts_json(r)
    assert "8.2; id" in str(exc.value)


def test_parse_vhosts_json_keeps_out_of_range_proxyport():
    """A non-Anubis proxy vhost (e.g. a node app on 3000) is not an error —
    it is simply filtered out later by the allocation-range check."""
    other = """[
  {"domain": "app.example.com", "user": "www-example", "webroot": "/home/www-example/x", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "3000"}}
]"""
    r = FakeRunner({"sudo nine-manage-vhosts virtual-host list --json": other})
    vhosts = _parse_vhosts_json(r)
    assert _get_proxy_port(vhosts[0]) == 3000
    assert discover_instances(r) == []
