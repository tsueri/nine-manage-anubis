"""Tests for cli.py — argument parsing and command dispatch."""

import io
import json
from contextlib import redirect_stdout, redirect_stderr

from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.cli import main, build_parser, _resolve_domains

import argparse

_SU = "sudo nine-su www-anubis <<'NINE_SU_EOF'\n"

VHOSTS = """[
  {"domain": "test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "proxy_letsencrypt_https_redirect", "template_variables": {"PROXYPORT": "7010"}, "aliases": [], "jobs": []},
  {"domain": "example.com", "user": "www-example", "webroot": "/home/www-example/example.com", "template": "default_letsencrypt_https", "template_variables": {"TIMEOUT": "300", "PHP_VERSION": "8.2", "MODSEC": "Off"}, "aliases": [], "jobs": []},
  {"domain": "origin-test.example.ch", "user": "www-anubis", "webroot": "/home/www-anubis/test.example.ch", "template": "default_snakeoil_https", "template_variables": {"PHP_VERSION": "8.2"}, "aliases": [], "jobs": []}
]"""

USERS_JSON = """[{"name": "www-data"}, {"name": "www-anubis"}]"""

CERT_LIST = """test.example.ch
================
       DOMAIN: test.example.ch
  VALID UNTIL: 2026-12-01
"""


def _runner(**overrides) -> FakeRunner:
    responses = {
        "sudo nine-manage-vhosts virtual-host list --json": VHOSTS,
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


def _run(argv, runner=None):
    buf = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        rc = main(argv, runner=runner)
    return rc, buf.getvalue(), err.getvalue()


# --- Argument parsing ---------------------------------------------------------


def test_parser_has_all_commands():
    parser = build_parser()
    for cmd in ("install", "uninstall", "enable", "disable", "upgrade", "status", "self-test"):
        args = parser.parse_args([cmd] if cmd != "enable" else [cmd, "x.com"])
        assert args.command == cmd


def test_parser_enable_with_domains():
    parser = build_parser()
    args = parser.parse_args(["enable", "a.com", "b.com"])
    assert args.command == "enable"
    assert args.domains == ["a.com", "b.com"]


def test_parser_enable_with_all_and_user():
    parser = build_parser()
    args = parser.parse_args(["enable", "--all", "--user", "www-example"])
    assert args.all is True
    assert args.user == "www-example"


def test_parser_dry_run():
    parser = build_parser()
    args = parser.parse_args(["--dry-run", "status"])
    assert args.dry_run is True


def test_parser_json():
    parser = build_parser()
    args = parser.parse_args(["--json", "status"])
    assert args.json is True


def test_parser_anubis_user():
    parser = build_parser()
    args = parser.parse_args(["--anubis-user", "custom-user", "status"])
    assert args.anubis_user == "custom-user"


def test_parser_upgrade_version():
    parser = build_parser()
    args = parser.parse_args(["upgrade", "--version", "1.26.0"])
    assert args.version == "1.26.0"


def test_parser_upgrade_no_rolling():
    parser = build_parser()
    args = parser.parse_args(["upgrade", "--no-rolling"])
    assert args.no_rolling is True


def test_parser_enable_prepare_only():
    parser = build_parser()
    args = parser.parse_args(["enable", "a.com", "--prepare-only"])
    assert args.prepare_only is True


def test_parser_enable_cutover_only():
    parser = build_parser()
    args = parser.parse_args(["enable", "a.com", "--cutover-only"])
    assert args.cutover_only is True


def test_parser_status_domain():
    parser = build_parser()
    args = parser.parse_args(["status", "--domain", "a.com"])
    assert args.domain == "a.com"


def test_parser_status_health():
    parser = build_parser()
    args = parser.parse_args(["status", "--health"])
    assert args.health is True


# --- _resolve_domains ---------------------------------------------------------


def test_resolve_domains_positional():
    args = argparse.Namespace(all=False, domains=["a.com", "b.com"], command="enable")
    assert _resolve_domains(args, _runner()) == ["a.com", "b.com"]


def test_resolve_domains_all_enable():
    args = argparse.Namespace(all=True, user="www-example", domains=[], command="enable")
    r = _runner()
    domains = _resolve_domains(args, r)
    assert "example.com" in domains
    assert "test.example.ch" not in domains  # already behind Anubis


def test_resolve_domains_all_disable():
    args = argparse.Namespace(all=True, user="www-anubis", domains=[], command="disable")
    r = _runner()
    domains = _resolve_domains(args, r)
    assert "test.example.ch" in domains
    assert "example.com" not in domains  # not behind Anubis


# --- Command dispatch ---------------------------------------------------------


def test_status_output():
    r = _runner()
    rc, out, err = _run(["status"], runner=r)
    assert rc == 0
    assert "test.example.ch" in out
    assert "DOMAIN" in out


def test_status_json():
    r = _runner()
    rc, out, err = _run(["--json", "status"], runner=r)
    assert rc == 0
    data = json.loads(out)
    assert len(data) == 1
    assert data[0]["domain"] == "test.example.ch"


def test_status_domain_filter():
    r = _runner()
    rc, out, err = _run(["status", "--domain", "test.example.ch"], runner=r)
    assert rc == 0
    assert "test.example.ch" in out


def test_status_domain_no_match():
    r = _runner()
    rc, out, err = _run(["status", "--domain", "nonexistent.com"], runner=r)
    assert rc == 0
    assert "No Anubis" in out


def test_install_dry_run():
    r = _runner()
    rc, out, err = _run(["--dry-run", "install"], runner=r)
    assert rc == 0
    assert "Would" in out


def test_uninstall_refuses():
    r = _runner()
    rc, out, err = _run(["uninstall"], runner=r)
    assert rc == 0
    assert "Error" in err or "Cannot" in err


def test_enable_dry_run():
    r = _runner()
    rc, out, err = _run(["--dry-run", "enable", "example.com"], runner=r)
    assert rc == 0
    assert "Would" in out or "proxy" in out.lower()


def test_enable_not_found():
    r = _runner()
    rc, out, err = _run(["--dry-run", "enable", "nonexistent.com"], runner=r)
    assert "not found" in err.lower() or "Error" in err


def test_enable_no_domains():
    r = _runner()
    rc, out, err = _run(["enable"], runner=r)
    assert rc == 1
    assert "No domains" in err


def test_disable_dry_run():
    r = _runner()
    rc, out, err = _run(["--dry-run", "disable", "test.example.ch"], runner=r)
    assert rc == 0
    assert "Would" in out or "tear down" in out.lower()


def test_upgrade_dry_run():
    r = _runner()
    rc, out, err = _run(["--dry-run", "upgrade"], runner=r)
    assert rc == 0
    assert "1.27.0" in out


def test_self_test():
    r = _runner()
    rc, out, err = _run(["self-test"], runner=r)
    assert rc == 0
    assert "test.example.ch" in out


def test_self_test_dry_run():
    r = _runner()
    rc, out, err = _run(["--dry-run", "self-test"], runner=r)
    assert rc == 0
    assert "Would" in out


def test_self_test_failure_shows_detail():
    """On failure, steps and warnings must still be printed alongside the error."""
    r = _runner(**{
        _SU + "export XDG_RUNTIME_DIR": "failed",
    })
    rc, out, err = _run(["self-test"], runner=r)
    assert rc == 0
    assert "User www-anubis exists" in out
    assert "not active" in err.lower() or "failed" in err.lower()
    assert "check(s) failed" in err
