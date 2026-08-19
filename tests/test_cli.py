"""Tests for cli.py — argument parsing and command dispatch."""

import io
import json
from contextlib import redirect_stdout, redirect_stderr

import pytest

from conftest import hostile, hostile_metacharacters
from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.cli import main, build_parser, _resolve_domains
from nine_manage_anubis.settings import Settings

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
    parser = build_parser(Settings())
    for cmd in ("install", "uninstall", "enable", "disable", "upgrade", "restart", "status", "self-test", "config"):
        args = parser.parse_args([cmd] if cmd not in ("enable", "disable") else [cmd, "x.com"])
        assert args.command == cmd


def test_parser_enable_with_domains():
    parser = build_parser(Settings())
    args = parser.parse_args(["enable", "a.com", "b.com"])
    assert args.command == "enable"
    assert args.domains == ["a.com", "b.com"]


def test_parser_enable_with_all_and_user():
    parser = build_parser(Settings())
    args = parser.parse_args(["enable", "--all", "--user", "www-example"])
    assert args.all is True
    assert args.user == "www-example"


def test_parser_dry_run():
    parser = build_parser(Settings())
    args = parser.parse_args(["--dry-run", "status"])
    assert args.dry_run is True


def test_parser_json():
    parser = build_parser(Settings())
    args = parser.parse_args(["--json", "status"])
    assert args.json is True


def test_parser_anubis_user():
    parser = build_parser(Settings())
    args = parser.parse_args(["--anubis-user", "custom-user", "status"])
    assert args.anubis_user == "custom-user"


def test_parser_upgrade_version():
    parser = build_parser(Settings())
    args = parser.parse_args(["upgrade", "--version", "1.26.0"])
    assert args.version == "1.26.0"


def test_parser_upgrade_no_rolling():
    parser = build_parser(Settings())
    args = parser.parse_args(["upgrade", "--no-rolling"])
    assert args.no_rolling is True


def test_parser_enable_prepare_only():
    parser = build_parser(Settings())
    args = parser.parse_args(["enable", "a.com", "--prepare-only"])
    assert args.prepare_only is True


def test_parser_enable_cutover_only():
    parser = build_parser(Settings())
    args = parser.parse_args(["enable", "a.com", "--cutover-only"])
    assert args.cutover_only is True


def test_parser_enable_no_notify_services():
    parser = build_parser(Settings())
    args = parser.parse_args(["enable", "--all", "--user", "www-example", "--no-notify-services"])
    assert args.no_notify_services is True


def test_parser_disable_no_notify_services():
    parser = build_parser(Settings())
    args = parser.parse_args(["disable", "--all", "--user", "www-example", "--no-notify-services"])
    assert args.no_notify_services is True


def test_parser_status_domain():
    parser = build_parser(Settings())
    args = parser.parse_args(["status", "--domain", "a.com"])
    assert args.domain == "a.com"


def test_parser_status_health():
    parser = build_parser(Settings())
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


def test_resolve_domains_all_enable_excludes_origin():
    """origin-* vhosts must never be picked up by --all.

    They are internal backend vhosts created during the prepare step,
    not public-facing sites that should be put behind Anubis.
    """
    args = argparse.Namespace(all=True, user="www-anubis", domains=[], command="enable")
    r = _runner()
    domains = _resolve_domains(args, r)
    assert "origin-test.example.ch" not in domains


def test_resolve_domains_all_disable():
    args = argparse.Namespace(all=True, user="www-anubis", domains=[], command="disable")
    r = _runner()
    domains = _resolve_domains(args, r)
    assert "test.example.ch" in domains
    assert "example.com" not in domains  # not behind Anubis


def test_resolve_domains_skip_pattern():
    """--skip with a glob pattern excludes matching domains."""
    args = argparse.Namespace(
        all=True, user="www-example", domains=[], command="enable",
        skip=["example*"],
    )
    r = _runner()
    domains = _resolve_domains(args, r)
    assert "example.com" not in domains


def test_resolve_domains_skip_multiple_patterns():
    """--skip can be repeated to exclude multiple patterns."""
    vhosts = """[
      {"domain": "a.com", "user": "www-example", "webroot": "/home/www-example/a.com", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []},
      {"domain": "b.com", "user": "www-example", "webroot": "/home/www-example/b.com", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []},
      {"domain": "c.com", "user": "www-example", "webroot": "/home/www-example/c.com", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
    ]"""
    r = _runner(**{"sudo nine-manage-vhosts virtual-host list --json": vhosts})
    args = argparse.Namespace(
        all=True, user="www-example", domains=[], command="enable",
        skip=["a.com", "c*"],
    )
    domains = _resolve_domains(args, r)
    assert domains == ["b.com"]


def test_resolve_domains_skip_no_match():
    """--skip with a non-matching pattern does not exclude anything."""
    args = argparse.Namespace(
        all=True, user="www-example", domains=[], command="enable",
        skip=["nonexistent*"],
    )
    r = _runner()
    domains = _resolve_domains(args, r)
    assert "example.com" in domains


def test_enable_no_notify_services_passes_flag_and_reloads():
    """--no-notify-services adds --no-notify-services to vhost update
    and does a single webserver reload at the end of the batch."""
    r = _runner()
    rc, out, err = _run(
        ["enable", "example.com", "--no-notify-services"],
        runner=r,
    )
    assert rc == 0
    # The vhost update command should include --no-notify-services
    update_calls = [c for c in r.calls if "virtual-host update" in c]
    assert any("--no-notify-services" in c for c in update_calls)
    # A single webserver reload should have been called
    reload_calls = [c for c in r.calls if "webserver reload" in c]
    assert len(reload_calls) == 1


def test_enable_without_no_notify_does_not_reload():
    """Without --no-notify-services, no batch webserver reload is issued."""
    r = _runner()
    rc, out, err = _run(["enable", "example.com"], runner=r)
    assert rc == 0
    reload_calls = [c for c in r.calls if "webserver reload" in c]
    assert len(reload_calls) == 0


def test_enable_no_notify_dry_run_skips_reload():
    """--no-notify-services with --dry-run should not reload."""
    r = _runner()
    rc, out, err = _run(
        ["--dry-run", "enable", "example.com", "--no-notify-services"],
        runner=r,
    )
    assert rc == 0
    reload_calls = [c for c in r.calls if "webserver reload" in c]
    assert len(reload_calls) == 0


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


def test_restart_dry_run():
    r = _runner()
    rc, out, err = _run(["--dry-run", "restart"], runner=r)
    assert rc == 0
    assert "rolling" in out.lower()


def test_restart_dry_run_no_rolling():
    r = _runner()
    rc, out, err = _run(["--dry-run", "restart", "--no-rolling"], runner=r)
    assert rc == 0
    assert "at once" in out.lower()


def test_restart_real():
    r = _runner()
    rc, out, err = _run(["restart"], runner=r)
    assert rc == 0
    assert "Restarted" in out


def test_command_failure_prints_error_not_traceback():
    """A failing external command must surface as a one-line error, not a
    Python traceback dumped in the operator's face."""
    class _Boom(FakeRunner):
        def __call__(self, cmd):
            raise RuntimeError("Command failed (exit 3): systemctl --user is-active")

    rc, out, err = _run(["restart"], runner=_Boom())
    assert rc == 1
    assert "Traceback" not in err
    assert "Command failed (exit 3)" in err


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


def test_config_shows_settings():
    rc, out, err = _run(["config"])
    assert rc == 0
    assert "anubis_user" in out
    assert "www-anubis" in out
    assert "policy_file" in out


def test_config_init_creates_file(tmp_path, monkeypatch):
    import nine_manage_anubis.settings as settings_mod
    monkeypatch.setattr(settings_mod, "default_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr("nine_manage_anubis.cli.default_config_path", lambda: tmp_path / "config.json")
    rc, out, err = _run(["config", "--init"])
    assert rc == 0
    assert "Created config file" in out
    config_file = tmp_path / "config.json"
    assert config_file.exists()
    import json
    data = json.loads(config_file.read_text())
    assert data["anubis_user"] == "www-anubis"
    assert "policy_file" in data


def test_settings_provide_defaults(tmp_path, monkeypatch):
    """Config file values should be used as argparse defaults."""
    import nine_manage_anubis.settings as settings_mod
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "anubis_user": "www-data",
        "anubis_version": "1.30.0",
        "policy_file": "/home/www-data/.config/anubis/policy.yaml",
    }))
    monkeypatch.setattr(settings_mod, "default_config_path", lambda: config)
    settings = settings_mod.load_settings()
    assert settings.anubis_user == "www-data"
    assert settings.anubis_version == "1.30.0"
    assert settings.policy_file == "/home/www-data/.config/anubis/policy.yaml"
    parser = build_parser(settings)
    args = parser.parse_args(["install"])
    assert args.version == "1.30.0"


# --- Input validation at the CLI boundary -------------------------------------
#
# An interactive user must get a clear message and a non-zero exit, and no
# sudo command may be built for a rejected value.

def _rejection_code(argv, runner) -> int:
    """Run expecting rejection, returning the exit code.

    argparse rejects some shapes (a leading dash looks like a flag) before our
    validators see them; both paths must end in a non-zero exit with nothing
    executed, which is what the caller asserts.
    """
    try:
        return _run(argv, runner=runner)[0]
    except SystemExit as e:
        return int(e.code or 0)


METACHARACTERS = hostile_metacharacters("example.com")
HOSTILE = hostile("example.com")


@pytest.mark.parametrize("value", HOSTILE)
def test_enable_rejects_malformed_domain(value):
    r = _runner()
    rc = _rejection_code(["enable", value], runner=r)
    assert rc != 0
    assert r.calls == []


@pytest.mark.parametrize("value", METACHARACTERS)
def test_enable_rejection_message_names_value_and_expected_form(value):
    r = _runner()
    rc, out, err = _run(["enable", value], runner=r)
    assert rc != 0
    assert repr(value) in err
    assert "expected" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("value", HOSTILE)
def test_disable_rejects_malformed_domain(value):
    r = _runner()
    rc = _rejection_code(["disable", value], runner=r)
    assert rc != 0
    assert r.calls == []


@pytest.mark.parametrize("value", ["www-anubis; id", "-anubis", "../../root", ""])
def test_rejects_malformed_anubis_user_flag(value):
    r = _runner()
    rc = _rejection_code(["--anubis-user", value, "status"], runner=r)
    assert rc != 0
    assert r.calls == []


def test_anubis_user_rejection_message_names_value_and_expected_form():
    r = _runner()
    rc, out, err = _run(["--anubis-user", "www-anubis; id", "status"], runner=r)
    assert rc != 0
    assert "www-anubis; id" in err
    assert "expected" in err


@pytest.mark.parametrize("value", ["1.27.0; id", "-1.27.0", "latest", ""])
def test_install_rejects_malformed_version_flag(value):
    r = _runner()
    rc = _rejection_code(["install", "--version", value], runner=r)
    assert rc != 0
    assert r.calls == []


def test_install_version_rejection_message_names_value_and_expected_form():
    r = _runner()
    rc, out, err = _run(["install", "--version", "1.27.0; id"], runner=r)
    assert rc != 0
    assert "1.27.0; id" in err
    assert "expected" in err


@pytest.mark.parametrize("value", ["www-example; id", "-example", ""])
def test_enable_all_rejects_malformed_user_flag(value):
    r = _runner()
    rc = _rejection_code(["enable", "--all", "--user", value], runner=r)
    assert rc != 0
    assert r.calls == []


def test_status_rejects_malformed_domain_filter():
    r = _runner()
    rc, out, err = _run(["status", "--domain", "example.com; id"], runner=r)
    assert rc != 0
    assert r.calls == []


def test_enable_rejects_whole_batch_when_one_domain_is_malformed():
    """One bad domain must not let the good ones start touching the host."""
    r = _runner()
    rc, out, err = _run(["enable", "example.com", "evil.com; id"], runner=r)
    assert rc != 0
    assert "evil.com; id" in err
    assert r.calls == []


def test_enable_all_rejects_malformed_domain_from_vhost_json():
    """Domains parsed out of nine-manage-vhosts JSON are untrusted too."""
    hostile = """[
  {"domain": "evil.com; id", "user": "www-example", "webroot": "/home/www-example/x", "template": "default_letsencrypt_https", "template_variables": {}, "aliases": [], "jobs": []}
]"""
    r = _runner(**{"sudo nine-manage-vhosts virtual-host list --json": hostile})
    rc, out, err = _run(["enable", "--all", "--user", "www-example"], runner=r)
    assert rc != 0
    assert "evil.com; id" in err
    assert not any("virtual-host update" in c for c in r.calls)


def test_settings_file_with_malformed_user_is_rejected(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-anubis; id"}))
    monkeypatch.setattr(
        "nine_manage_anubis.settings.default_config_path", lambda: config
    )
    rc, out, err = _run(["status"], runner=_runner())
    assert rc != 0
    assert "www-anubis; id" in err
    assert "Traceback" not in err


def test_settings_file_with_malformed_version_is_rejected(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_version": "1.27.0; id"}))
    monkeypatch.setattr(
        "nine_manage_anubis.settings.default_config_path", lambda: config
    )
    rc, out, err = _run(["install"], runner=_runner())
    assert rc != 0
    assert "1.27.0; id" in err


def test_valid_domain_still_enables():
    """The whitelist must not get in the way of the ordinary case."""
    r = _runner()
    rc, out, err = _run(["--dry-run", "enable", "example.com"], runner=r)
    assert rc == 0


def test_leading_dash_domain_reaches_our_validator_after_a_double_dash():
    """`--` stops argparse eating the leading dash, so the value lands on our
    validator rather than on argparse's "unrecognized arguments"."""
    r = _runner()
    rc, out, err = _run(["enable", "--", "-example.com"], runner=r)
    assert rc != 0
    assert "-example.com" in err
    assert "expected" in err
    assert r.calls == []


def test_leading_dash_user_reaches_our_validator_via_equals_form():
    r = _runner()
    rc, out, err = _run(["--anubis-user=-anubis", "status"], runner=r)
    assert rc != 0
    assert "-anubis" in err
    assert "expected" in err
    assert r.calls == []


@pytest.mark.parametrize("argv", [
    ["--dry-run", "enable", "example.com; id"],
    ["--dry-run", "disable", "example.com; id"],
    ["--dry-run", "install", "--version", "1.27.0; id"],
    ["--dry-run", "upgrade", "--version", "1.27.0; id"],
])
def test_dry_run_builds_nothing_for_a_rejected_input(argv):
    """Dry run is not a way to smuggle a value into a constructed command."""
    r = _runner()
    rc, out, err = _run(argv, runner=r)
    assert rc != 0
    assert r.calls == []
    assert "1.27.0; id" not in out
    assert "example.com; id" not in out


def test_json_output_mode_also_rejects():
    r = _runner()
    rc, out, err = _run(["--json", "enable", "example.com; id"], runner=r)
    assert rc != 0
    assert r.calls == []


def test_config_still_reports_a_rejected_config_file(tmp_path, monkeypatch):
    """A bad config file must not lock you out of the command that repairs it."""
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-anubis; id"}))
    monkeypatch.setattr(
        "nine_manage_anubis.settings.default_config_path", lambda: config
    )
    monkeypatch.setattr(
        "nine_manage_anubis.cli.default_config_path", lambda: config
    )
    rc, out, err = _run(["config"], runner=_runner())
    assert rc == 1
    assert "www-anubis; id" in out
    assert "config --init" in out
    assert "Traceback" not in err


def test_config_init_overwrites_a_rejected_config_file(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-anubis; id"}))
    monkeypatch.setattr(
        "nine_manage_anubis.settings.default_config_path", lambda: config
    )
    monkeypatch.setattr(
        "nine_manage_anubis.cli.default_config_path", lambda: config
    )
    rc, out, err = _run(["config", "--init"], runner=_runner())
    assert rc == 0
    # The file it wrote is now loadable.
    from nine_manage_anubis.settings import load_settings
    assert load_settings(config).anubis_user == "www-anubis"
