"""Tests for ports.py — port discovery & allocation.

Uses a FakeRunner to inject canned command outputs. The nine-su commands
are now heredoc-based (sudo nine-su <user> <<'EOF' ... EOF) instead of
the broken -c pattern.
"""

from nine_manage_anubis.runner import FakeRunner
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
