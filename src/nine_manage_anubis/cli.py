"""CLI argument parsing and command dispatch.

Uses argparse (stdlib) for the command surface:
  install / uninstall / enable / disable / upgrade / status

Global flags: --dry-run, --json, --anubis-user
Domain targeting: positional args or --all --user <user>
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from .runner import SubprocessRunner
from .commands import (
    cmd_install,
    cmd_uninstall,
    cmd_enable,
    cmd_disable,
    cmd_upgrade,
    cmd_status,
    cmd_selftest,
    DEFAULT_ANUBIS_USER,
)
from .output import format_status, format_steps, format_dry_run
from .ports import _parse_vhosts_json


def build_parser() -> argparse.ArgumentParser:
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
        "--anubis-user", default=DEFAULT_ANUBIS_USER,
        help=f"Anubis system user (default: {DEFAULT_ANUBIS_USER}).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # install
    p = sub.add_parser("install", help="Set up Anubis infrastructure (user, binary, systemd template).")
    p.add_argument("--version", default="1.27.0", help="Anubis version to install.")

    # uninstall
    sub.add_parser("uninstall", help="Remove Anubis infrastructure. Refuses if instances exist.")

    # enable
    p = sub.add_parser("enable", help="Put a vhost behind Anubis.")
    p.add_argument("domains", nargs="*", help="Domain(s) to enable.")
    p.add_argument("--prepare-only", action="store_true", help="Do everything except the cutover.")
    p.add_argument("--cutover-only", action="store_true", help="Only do the cutover step.")
    p.add_argument("--all", action="store_true", help="Enable all vhosts for --user.")
    p.add_argument("--user", help="Website user to filter --all by.")

    # disable
    p = sub.add_parser("disable", help="Remove Anubis protection from a vhost.")
    p.add_argument("domains", nargs="*", help="Domain(s) to disable.")
    p.add_argument("--all", action="store_true", help="Disable all Anubis vhosts for --user.")
    p.add_argument("--user", help="Website user to filter --all by.")

    # upgrade
    p = sub.add_parser("upgrade", help="Download new Anubis binary and restart instances.")
    p.add_argument("--version", help="Target version (default: latest).")
    p.add_argument("--no-rolling", action="store_true", help="Restart all instances at once.")

    # status
    p = sub.add_parser("status", help="List Anubis instances.")
    p.add_argument("--domain", help="Filter by domain.")
    p.add_argument("--health", action="store_true", help="Active health check (curl).")

    # self-test
    sub.add_parser("self-test", help="Verify Anubis infrastructure health.")

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

    if args.command == "enable":
        return [
            vh["domain"] for vh in vhosts
            if vh.get("user") == user
            and vh.get("template") != "proxy_letsencrypt_https_redirect"
        ]
    elif args.command == "disable":
        return [
            vh["domain"] for vh in vhosts
            if vh.get("user") == user
            and vh.get("template") == "proxy_letsencrypt_https_redirect"
        ]
    return []


def main(argv: Sequence[str] | None = None, runner=None) -> int:
    parser = build_parser()
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
        any_error = False
        for domain in domains:
            result = cmd_enable(
                domain,
                runner=runner,
                dry_run=dry_run,
                prepare_only=args.prepare_only,
                cutover_only=args.cutover_only,
                anubis_user=anubis_user,
            )
            _print_result(result, dry_run, as_json, title=f"Enable {domain}:")
            if not result.success:
                any_error = True
        return 1 if any_error else 0

    elif args.command == "disable":
        domains = _resolve_domains(args, runner)
        if not domains:
            print("No domains to disable.", file=sys.stderr)
            return 1
        any_error = False
        for domain in domains:
            result = cmd_disable(
                domain,
                runner=runner,
                dry_run=dry_run,
                anubis_user=anubis_user,
            )
            _print_result(result, dry_run, as_json, title=f"Disable {domain}:")
            if not result.success:
                any_error = True
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

    return 0


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
        print(format_dry_run(result.steps, title=title))
    else:
        print(format_steps(result.steps, title=title))

    for w in result.warnings:
        print(f"  WARNING: {w}", file=sys.stderr)
    if result.error:
        print(f"Error: {result.error}", file=sys.stderr)
