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
from .nine_su import nine_su, nine_su_read_file
from .shell import quote
from .systemd import binary_version, is_active
from .validate import (
    MAX_TCP_PORT,
    MIN_TCP_PORT,
    PORT_RANGE_END,
    PORT_RANGE_START,
    ValidationError,
    validate_domain,
    validate_path,
    validate_port,
    validate_system_user,
    validate_vhost_record,
)

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
    """Read the vhost list, validating every field we later interpolate."""
    raw = runner("sudo nine-manage-vhosts virtual-host list --json")
    vhosts = json.loads(raw)
    if not isinstance(vhosts, list):
        raise ValidationError(
            f"Invalid vhost list from nine-manage-vhosts: expected a JSON "
            f"array, got {type(vhosts).__name__}."
        )
    for vh in vhosts:
        validate_vhost_record(vh)
    return vhosts


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
    validate_path(webroot, field="webroot")
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
    validate_domain(domain)
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
        # /home holds whatever the operator put there, so a name that isn't a
        # valid system user is just not a user — skip it rather than abort the
        # scan. Skipping is safe: it can't hide an Anubis instance, because an
        # instance lives in a real user's home. It also keeps the name out of
        # the command below, which is the point.
        try:
            validate_system_user(user, field="home directory user")
        except ValidationError:
            continue
        check = runner(
            f"test -d {quote(f'/home/{user}/.config/anubis')} && echo yes || echo no"
        )
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
            # The instance domain is the env file's stem, and it becomes the
            # systemd instance name — validate it before it reaches a command.
            domain = env_path.rsplit("/", 1)[-1]
            if domain.endswith(".env"):
                domain = domain[: -len(".env")]
            validate_domain(domain, field="instance domain from env file")
            validate_path(env_path, field="env file path")
            # The listing and the read are separate round trips, so an
            # instance torn down in between leaves a path that no longer
            # exists — not a reason to abort the whole scan.
            content = nine_su_read_file(user, env_path, runner)
            if content is None:
                continue
            env = _parse_env_file(content)
            bind = env.get("BIND", "")
            port_match = re.match(r":(\d+)", bind)
            if port_match:
                # A non-numeric or absurd BIND is corruption and is fatal, but
                # a valid port outside our range just isn't ours to claim —
                # skip it the same way discover_instances() filters vhosts.
                port = validate_port(
                    port_match.group(1),
                    field="BIND port in env file",
                    minimum=MIN_TCP_PORT,
                    maximum=MAX_TCP_PORT,
                )
                if PORT_RANGE_START <= port <= PORT_RANGE_END:
                    claimed[port] = (user, domain)
    return claimed


# --- Service discovery --------------------------------------------------------


def _get_service_state(
    user: str, instance: str, runner: Runner
) -> str:
    """The unit state, with silence reported as ``not-found``.

    Delegates to the systemd wrapper rather than repeating its script: a second
    copy is a second place the quoting has to be right.
    """
    return is_active(user, instance, runner=runner) or "not-found"


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
        ver = binary_version(user, runner=runner)
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
    validate_domain(domain)
    claimed = get_claimed_ports(runner)
    for port, (user, dom) in claimed.items():
        if dom == domain:
            return port
    return None


def find_prepared_port_for_webroot(
    webroot: str, exclude_domain: str | None = None, runner: Runner = SubprocessRunner()
) -> int | None:
    """Find a port from an env file for any domain sharing this webroot.

    During --prepare-only, no vhost is behind Anubis yet, so
    find_instance_for_webroot returns None.  But a sibling domain
    processed earlier in the same batch may already have an env file.
    Reuse that port instead of allocating a new one (which would
    become an orphan once the cutover detects the webroot match).
    """
    validate_path(webroot, field="webroot")
    if exclude_domain is not None:
        validate_domain(exclude_domain)
    vhosts = _parse_vhosts_json(runner)
    domains_with_webroot = {
        vh["domain"] for vh in vhosts
        if vh.get("webroot") == webroot
        and not vh["domain"].startswith("origin-")
        and vh["domain"] != exclude_domain
    }
    if not domains_with_webroot:
        return None
    claimed = get_claimed_ports(runner)
    for port, (user, dom) in claimed.items():
        if dom in domains_with_webroot:
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
        # 1. A proxy vhost sharing this webroot is already behind Anubis.
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

        # 2. A sibling domain sharing this webroot was already prepared
        #    (env file exists) but not yet cut over.  Reuse its port so
        #    we don't create an orphan instance.
        prepared_port = find_prepared_port_for_webroot(webroot, exclude_domain=domain, runner=runner)
        if prepared_port is not None:
            claimed = get_claimed_ports(runner)
            primary = claimed.get(prepared_port, ("", "unknown"))[1]
            return PortAllocation(
                app_port=prepared_port,
                metrics_port=prepared_port + 1,
                reused_from=primary,
            )

    # 3. This domain's own env file from --prepare-only.
    existing_port = find_port_for_domain(domain, runner)
    if existing_port is not None:
        return PortAllocation(
            app_port=existing_port,
            metrics_port=existing_port + 1,
        )

    # 4. Nothing exists yet — allocate a fresh pair.
    app, metrics = next_free_pair(runner)
    return PortAllocation(app_port=app, metrics_port=metrics)
