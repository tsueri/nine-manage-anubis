"""CLI argument parsing and command dispatch.

Uses argparse (stdlib) for the command surface:
  install / uninstall / enable / disable / upgrade / status / self-test / config

Global flags: --dry-run, --json, --anubis-user
Domain targeting: positional args or --all --user <user>

Defaults loaded from ~/.config/nine-manage-anubis/config.json (see settings.py).
CLI flags override config file values.
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
from typing import Sequence

from .runner import SubprocessRunner
from .commands import (
    cmd_install,
    cmd_uninstall,
    cmd_enable,
    cmd_disable,
    cmd_upgrade,
    cmd_restart,
    cmd_status,
    cmd_selftest,
    CommandResult,
)
from .output import format_status, format_steps, format_dry_run
from .vhosts import webserver_reload
from .ports import _parse_vhosts_json
from .settings import Settings, load_settings, default_config_path, default_config_content


def build_parser(settings: Settings) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nine-manage-anubis",
        description="Manage Anubis bot protection on nine.ch Managed Servers.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without making changes.",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON.",
    )
    parser.add_argument(
        "--anubis-user", default=settings.anubis_user,
        help=f"Anubis system user (default: {settings.anubis_user}).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # install
    p = sub.add_parser("install", help="Set up Anubis infrastructure (user, binary, systemd template).")
    p.add_argument("--version", default=settings.anubis_version, help="Anubis version to install.")
    p.add_argument("--init-policy", action="store_true",
                   help="Extract default bot policy to the configured policy_file path.")

    # uninstall
    sub.add_parser("uninstall", help="Remove Anubis infrastructure. Refuses if instances exist.")

    # enable
    p = sub.add_parser("enable", help="Put a vhost behind Anubis.")
    p.add_argument("domains", nargs="*", help="Domain(s) to enable.")
    p.add_argument("--prepare-only", action="store_true", help="Do everything except the cutover.")
    p.add_argument("--cutover-only", action="store_true", help="Only do the cutover step.")
    p.add_argument("--all", action="store_true", help="Enable all vhosts for --user.")
    p.add_argument("--user", help="Website user to filter --all by.")
    p.add_argument("--skip", action="append", default=[], metavar="PATTERN",
                   help="Skip domains matching glob pattern (e.g. 'vorlage*', '*.test'). Repeatable.")
    p.add_argument("--no-notify-services", action="store_true",
                   help="Skip Apache reload on each vhost change; reload once at end of batch.")

    # disable
    p = sub.add_parser("disable", help="Remove Anubis protection from a vhost.")
    p.add_argument("domains", nargs="*", help="Domain(s) to disable.")
    p.add_argument("--all", action="store_true", help="Disable all Anubis vhosts for --user.")
    p.add_argument("--user", help="Website user to filter --all by.")
    p.add_argument("--skip", action="append", default=[], metavar="PATTERN",
                   help="Skip domains matching glob pattern (e.g. 'vorlage*', '*.test'). Repeatable.")
    p.add_argument("--no-notify-services", action="store_true",
                   help="Skip Apache reload on each vhost change; reload once at end of batch.")

    # upgrade
    p = sub.add_parser("upgrade", help="Download new Anubis binary and restart instances.")
    p.add_argument("--version", help="Target version (default: latest).")
    p.add_argument("--no-rolling", action="store_true", help="Restart all instances at once.")

    # restart
    p = sub.add_parser("restart", help="Restart all Anubis instances (e.g. after policy changes).")
    p.add_argument("--no-rolling", action="store_true", help="Restart all instances at once.")

    # status
    p = sub.add_parser("status", help="List Anubis instances.")
    p.add_argument("--domain", help="Filter by domain.")
    p.add_argument("--health", action="store_true", help="Active health check (curl).")

    # self-test
    sub.add_parser("self-test", help="Verify Anubis infrastructure health.")

    # config
    p = sub.add_parser("config", help="Show current settings and config file location.")
    p.add_argument("--init", action="store_true", help="Create a default config file.")

    return parser


def _resolve_domains(args: argparse.Namespace, runner) -> list[str]:
    """Resolve --all --user into a list of domains."""
    if not getattr(args, "all", False):
        return list(getattr(args, "domains", []))

    if not getattr(args, "user", None):
        print("Error: --all requires --user", file=sys.stderr)
        sys.exit(1)

    vhosts = _parse_vhosts_json(runner)
    user = args.user
    skip_patterns = getattr(args, "skip", []) or []

    def _is_skipped(domain: str) -> bool:
        return any(fnmatch.fnmatch(domain, pat) for pat in skip_patterns)

    if args.command == "enable":
        return [
            vh["domain"] for vh in vhosts
            if vh.get("user") == user
            and vh.get("template") != "proxy_letsencrypt_https_redirect"
            and not vh["domain"].startswith("origin-")
            and not _is_skipped(vh["domain"])
        ]
    elif args.command == "disable":
        return [
            vh["domain"] for vh in vhosts
            if vh.get("user") == user
            and vh.get("template") == "proxy_letsencrypt_https_redirect"
            and not vh["domain"].startswith("origin-")
            and not _is_skipped(vh["domain"])
        ]
    return []


def main(argv: Sequence[str] | None = None, runner=None) -> int:
    settings = load_settings()
    parser = build_parser(settings)
    args = parser.parse_args(argv)
    if runner is None:
        runner = SubprocessRunner()
    dry_run = args.dry_run
    as_json = args.json
    anubis_user = args.anubis_user

    if args.command == "install":
        result = cmd_install(
            anubis_user=anubis_user,
            version=args.version,
            runner=runner,
            dry_run=dry_run,
            policy_file=settings.policy_file,
            init_policy=args.init_policy,
        )
        _print_result(result, dry_run, as_json, title="Install:")

    elif args.command == "uninstall":
        result = cmd_uninstall(
            anubis_user=anubis_user,
            runner=runner,
            dry_run=dry_run,
        )
        _print_result(result, dry_run, as_json, title="Uninstall:")

    elif args.command == "enable":
        domains = _resolve_domains(args, runner)
        if not domains:
            print("No domains to enable.", file=sys.stderr)
            return 1
        no_notify = args.no_notify_services
        any_error = False
        any_changes = False
        for domain in domains:
            try:
                result = cmd_enable(
                    domain,
                    runner=runner,
                    dry_run=dry_run,
                    prepare_only=args.prepare_only,
                    cutover_only=args.cutover_only,
                    anubis_user=anubis_user,
                    policy_file=settings.policy_file,
                    no_notify=no_notify,
                )
            except Exception as e:
                result = CommandResult(error=f"Unexpected error: {e}")
            _print_result(result, dry_run, as_json, title=f"Enable {domain}:")
            if not result.success:
                any_error = True
            if result.steps:
                any_changes = True
        if no_notify and any_changes and not dry_run:
            webserver_reload(runner=runner)
            print("Apache reloaded once after batch.")
        return 1 if any_error else 0

    elif args.command == "disable":
        domains = _resolve_domains(args, runner)
        if not domains:
            print("No domains to disable.", file=sys.stderr)
            return 1
        no_notify = args.no_notify_services
        any_error = False
        any_changes = False
        for domain in domains:
            try:
                result = cmd_disable(
                    domain,
                    runner=runner,
                    dry_run=dry_run,
                    anubis_user=anubis_user,
                    no_notify=no_notify,
                )
            except Exception as e:
                result = CommandResult(error=f"Unexpected error: {e}")
            _print_result(result, dry_run, as_json, title=f"Disable {domain}:")
            if not result.success:
                any_error = True
            if result.steps:
                any_changes = True
        if no_notify and any_changes and not dry_run:
            webserver_reload(runner=runner)
            print("Apache reloaded once after batch.")
        return 1 if any_error else 0

    elif args.command == "upgrade":
        result = cmd_upgrade(
            version=args.version,
            runner=runner,
            dry_run=dry_run,
            no_rolling=args.no_rolling,
            anubis_user=anubis_user,
        )
        _print_result(result, dry_run, as_json, title="Upgrade:")

    elif args.command == "restart":
        result = cmd_restart(
            runner=runner,
            dry_run=dry_run,
            no_rolling=args.no_rolling,
            anubis_user=anubis_user,
        )
        _print_result(result, dry_run, as_json, title="Restart:")

    elif args.command == "status":
        instances, health_map = cmd_status(
            domain=args.domain,
            runner=runner,
            health=args.health,
        )
        print(format_status(instances, health_map=health_map, as_json=as_json))

    elif args.command == "self-test":
        result = cmd_selftest(
            runner=runner,
            dry_run=dry_run,
            anubis_user=anubis_user,
        )
        _print_result(result, dry_run, as_json, title="Self-test:")

    elif args.command == "config":
        _cmd_config(settings, args)

    return 0


def _cmd_config(settings: Settings, args: argparse.Namespace) -> None:
    path = default_config_path()
    if args.init:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(default_config_content(settings.anubis_user))
        print(f"Created config file: {path}")
        return
    exists = "exists" if path.exists() else "does not exist"
    print(f"Config file: {path} ({exists})")
    print()
    print(f"  anubis_user:    {settings.anubis_user}")
    print(f"  anubis_version: {settings.anubis_version}")
    pf = settings.policy_file or "(not set — instances use embedded default policy)"
    print(f"  policy_file:    {pf}")


def _print_result(result, dry_run: bool, as_json: bool, title: str = ""):
    if as_json:
        import json
        data: dict = {"steps": result.steps}
        if result.warnings:
            data["warnings"] = result.warnings
        if result.error:
            data["error"] = result.error
        print(json.dumps(data, indent=2))
        return

    if dry_run:
        dry_title = f"[DRY RUN] {title}" if title else "[DRY RUN]"
        print(format_dry_run(result.steps, title=dry_title))
    else:
        print(format_steps(result.steps, title=title))

    for w in result.warnings:
        print(f"  WARNING: {w}", file=sys.stderr)
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr)
