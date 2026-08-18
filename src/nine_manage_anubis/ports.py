"""Port discovery & allocation for Anubis-on-Nine.

Discovers existing Anubis instances, finds the next free port pair in
7010-7999, and detects multisite reuse.

All external commands go through an injectable Runner callable so tests
can supply canned outputs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .runner import Runner, SubprocessRunner
from .nine_su import nine_su, nine_su_systemd

PORT_RANGE_START = 7010
PORT_RANGE_END = 7999
PAIR_STRIDE = 2


@dataclass
class AnubisInstance:
    domain: str
    port: int
    metrics_port: int
    user: str
    service_state: str
    vhosts: list[str] = field(default_factory=list)
    version: str = ""

    @property
    def is_running(self) -> bool:
        return self.service_state == "active"


@dataclass
class PortAllocation:
    app_port: int
    metrics_port: int
    reused_from: str | None = None

    @property
    def is_reused(self) -> bool:
        return self.reused_from is not None


# --- Vhost discovery ----------------------------------------------------------


def _parse_vhosts_json(runner: Runner) -> list[dict]:
    raw = runner("sudo nine-manage-vhosts virtual-host list --json")
    return json.loads(raw)


def _is_anubis_proxy(vhost: dict) -> bool:
    return (
        vhost.get("template") == "proxy_letsencrypt_https_redirect"
        and "PROXYPORT" in vhost.get("template_variables", {})
    )


def _get_proxy_port(vhost: dict) -> int | None:
    tv = vhost.get("template_variables", {})
    if "PROXYPORT" in tv:
        return int(tv["PROXYPORT"])
    return None


def find_instance_for_webroot(
    webroot: str, runner: Runner = SubprocessRunner()
) -> int | None:
    vhosts = _parse_vhosts_json(runner)
    for vh in vhosts:
        if vh.get("webroot") == webroot and _is_anubis_proxy(vh):
            port = _get_proxy_port(vh)
            if port is not None:
                return port
    return None


def find_vhosts_for_port(port: int, runner: Runner = SubprocessRunner()) -> list[str]:
    vhosts = _parse_vhosts_json(runner)
    return [
        vh["domain"]
        for vh in vhosts
        if _is_anubis_proxy(vh) and _get_proxy_port(vh) == port
    ]


def get_vhost(domain: str, runner: Runner = SubprocessRunner()) -> dict | None:
    vhosts = _parse_vhosts_json(runner)
    for vh in vhosts:
        if vh["domain"] == domain:
            return vh
    return None


# --- Listening ports ---------------------------------------------------------


def _parse_ss_output(ss_output: str) -> set[int]:
    ports = set()
    for line in ss_output.strip().splitlines():
        for match in re.finditer(r":(\d{4})\b", line):
            port = int(match.group(1))
            if PORT_RANGE_START <= port <= PORT_RANGE_END:
                ports.add(port)
    return ports


def get_listening_ports(runner: Runner = SubprocessRunner()) -> set[int]:
    return _parse_ss_output(runner("ss -tlnp"))


# --- Env file scanning --------------------------------------------------------


def _parse_env_file(content: str) -> dict[str, str]:
    env = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip()
    return env


def _find_anubis_users(runner: Runner) -> list[str]:
    output = runner("ls -d /home/www-*/ 2>/dev/null")
    users = []
    for line in output.strip().splitlines():
        path = line.strip().rstrip("/")
        user = path.rsplit("/", 1)[-1]
        check = runner(f"test -d /home/{user}/.config/anubis && echo yes || echo no")
        if check.strip() == "yes":
            users.append(user)
    return users


def get_claimed_ports(runner: Runner = SubprocessRunner()) -> dict[int, tuple[str, str]]:
    """Scan env files for claimed ports. Returns {port: (user, domain)}."""
    users = _find_anubis_users(runner)
    claimed = {}
    for user in users:
        listing = nine_su(
            user,
            "ls ~/.config/anubis/*.env 2>/dev/null",
            runner,
        )
        for env_path in listing.strip().splitlines():
            env_path = env_path.strip()
            if not env_path:
                continue
            content = nine_su(user, f"cat '{env_path}'", runner)
            env = _parse_env_file(content)
            bind = env.get("BIND", "")
            port_match = re.match(r":(\d+)", bind)
            if port_match:
                port = int(port_match.group(1))
                domain = env_path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                if domain.endswith(".env"):
                    domain = env_path.rsplit("/", 1)[-1][:-4]
                claimed[port] = (user, domain)
    return claimed


# --- Service discovery --------------------------------------------------------


def _get_service_state(
    user: str, instance: str, runner: Runner
) -> str:
    result = nine_su_systemd(
        user,
        f"systemctl --user is-active anubis@{instance}.service",
        runner,
    )
    result = result.strip()
    return result if result else "not-found"


def _get_binary_version(user: str, runner: Runner) -> str:
    result = nine_su(user, f"/home/{user}/bin/anubis --version 2>&1 || true", runner)
    return result.strip()


def discover_instances(
    runner: Runner = SubprocessRunner(),
) -> list[AnubisInstance]:
    vhosts = _parse_vhosts_json(runner)

    port_vhosts: dict[int, list[str]] = {}
    for vh in vhosts:
        if _is_anubis_proxy(vh):
            port = _get_proxy_port(vh)
            if port is not None:
                port_vhosts.setdefault(port, []).append(vh["domain"])

    claimed = get_claimed_ports(runner)
    all_ports = set(port_vhosts.keys()) | set(claimed.keys())

    instances = []
    for port in sorted(all_ports):
        if port < PORT_RANGE_START or port > PORT_RANGE_END:
            continue
        user, domain = claimed.get(port, ("unknown", "unknown"))
        metrics_port = port + 1
        state = _get_service_state(user, domain, runner)
        vhost_list = port_vhosts.get(port, [])
        ver = _get_binary_version(user, runner)
        instances.append(
            AnubisInstance(
                domain=domain,
                port=port,
                metrics_port=metrics_port,
                user=user,
                service_state=state,
                vhosts=vhost_list,
                version=ver,
            )
        )
    return instances


# --- Port allocation ----------------------------------------------------------


def _all_used_ports(runner: Runner) -> set[int]:
    listening = get_listening_ports(runner)
    claimed = get_claimed_ports(runner)
    vhosts = _parse_vhosts_json(runner)
    assigned = {
        _get_proxy_port(vh)
        for vh in vhosts
        if _is_anubis_proxy(vh) and _get_proxy_port(vh) is not None
    }
    return listening | set(claimed.keys()) | assigned


def next_free_pair(runner: Runner = SubprocessRunner()) -> tuple[int, int]:
    used = _all_used_ports(runner)
    port = PORT_RANGE_START
    while port <= PORT_RANGE_END - 1:
        if port not in used and (port + 1) not in used:
            return (port, port + 1)
        port += PAIR_STRIDE
    raise RuntimeError(f"No free port pair in range {PORT_RANGE_START}-{PORT_RANGE_END}")


def find_port_for_domain(
    domain: str, runner: Runner = SubprocessRunner()
) -> int | None:
    """Find the port allocated for a domain from its env file."""
    claimed = get_claimed_ports(runner)
    for port, (user, dom) in claimed.items():
        if dom == domain:
            return port
    return None


def allocate_for_domain(
    domain: str, runner: Runner = SubprocessRunner()
) -> PortAllocation:
    vh = get_vhost(domain, runner)
    if vh is None:
        raise ValueError(f"Vhost {domain} not found")

    webroot = vh.get("webroot", "")
    if webroot:
        existing = find_instance_for_webroot(webroot, runner)
        if existing is not None:
            claimed = get_claimed_ports(runner)
            if existing in claimed:
                primary = claimed[existing][1]
            else:
                vhosts_for_port = find_vhosts_for_port(existing, runner)
                primary = vhosts_for_port[0] if vhosts_for_port else "unknown"
            return PortAllocation(
                app_port=existing,
                metrics_port=existing + 1,
                reused_from=primary,
            )

    # An env file from --prepare-only already has the port we need.
    existing_port = find_port_for_domain(domain, runner)
    if existing_port is not None:
        return PortAllocation(
            app_port=existing_port,
            metrics_port=existing_port + 1,
        )

    app, metrics = next_free_pair(runner)
    return PortAllocation(app_port=app, metrics_port=metrics)
