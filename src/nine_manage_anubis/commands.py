"""Command implementations for nine-manage-anubis.

Six commands: install, uninstall, enable, disable, upgrade, status.
Each takes an injectable Runner and returns a list of step strings
(what was done, or what would be done in dry-run mode).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .runner import CommandFailed, CommandTimeout, Runner, SubprocessRunner
from .ports import (
    AnubisInstance,
    allocate_for_domain,
    discover_instances,
    find_vhosts_for_port,
    get_vhost,
)
from .vhosts import (
    create_origin_vhost,
    remove_origin_vhost,
    switch_to_proxy,
    switch_to_default,
    create_user,
    remove_user,
    user_exists,
    certificate_exists,
    create_certificate,
    PROXY_TEMPLATE,
)
from .config import (
    AnubisConfig,
    SYSTEMD_TEMPLATE,
    generate_env_file,
    key_path_for,
    env_path_for,
)
from .systemd import (
    daemon_reload,
    enable_service,
    disable_service,
    restart_service,
    is_active,
    write_systemd_template,
    template_exists,
    remove_systemd_template,
    write_env_file,
    write_key_file,
    remove_file,
    binary_exists,
    binary_version,
    download_binary,
    generate_key,
    get_latest_version,
    extract_policy,
)
from .fixups import apply as apply_fixups, restore as restore_fixups
from .settings import Settings
from .fileops import RemoteFileOps
from .shell import quote
from .validate import (
    ValidationError,
    required_vhost_field,
    validate_domain,
    validate_path,
    validate_system_user,
    validate_version,
)


# The defaults live on the Settings dataclass — the same values the config
# file falls back to — so driving the library directly and driving it through
# the CLI cannot disagree about which user or version is meant.
DEFAULT_ANUBIS_USER = Settings.anubis_user
ANUBIS_VERSION = Settings.anubis_version

# A healthy instance answers a loopback probe in milliseconds, so this bounds
# the case the limit exists for: an instance wedged badly enough to accept the
# connection and never reply. curl gets no --max-time of its own here — the
# probe runs locally and unprivileged, so the runner's own kill lands, and the
# failure then reads as a timeout rather than as curl exit code 28.
PROBE_TIMEOUT = 10.0


def _validate_inputs(
    anubis_user: str | None = None,
    policy_file: str | None = None,
    domain: str | None = None,
    version: str | None = None,
) -> None:
    """Whitelist every caller-supplied value before any command is built.

    Called first thing in each public command entry point so the library is
    safe when driven directly, not just through the CLI. Raises
    ValidationError; no sudo command has been constructed at that point.
    Arguments a given command doesn't take are simply left out.
    """
    if anubis_user is not None:
        validate_system_user(anubis_user, field="Anubis user")
    if policy_file is not None:
        validate_path(policy_file, field="policy_file")
    if domain is not None:
        validate_domain(domain)
    if version is not None:
        validate_version(version)


def _http_probe(domain: str, port: int, runner: Runner) -> str:
    """The HTTP status code an instance returns for a loopback probe.

    Every health check asks the same question, so the command is built in one
    place — including the quoting of the Host header, which carries a domain,
    and of the URL, which carries a port. The `X-Real-Ip` header keeps Anubis
    from challenging its own health check.
    """
    response = runner(
        f"curl -s -o /dev/null -w {quote('%{http_code}')} "
        f"-H {quote('X-Real-Ip: 127.0.0.1')} -H {quote(f'Host: {domain}')} "
        f"{quote(f'http://localhost:{port}/')}",
        timeout=PROBE_TIMEOUT,
        what=f"probing {domain} on port {port}",
    )
    return response.strip()


# What a probe that never answered is called, wherever it is reported: as a
# health column in `status`, and inside the warning below everywhere else. One
# phrase, because an operator comparing the two is looking at one instance.
PROBE_TIMED_OUT = f"timed out after {PROBE_TIMEOUT:g}s"


def _probe_timed_out(domain: str) -> str:
    """The warning a command raises about an instance whose probe never answered."""
    return f"anubis@{domain}.service HTTP probe {PROBE_TIMED_OUT}"


# What a probe that could not be made at all is called, wherever it is
# reported — connection refused, DNS failure, no curl. Same reason as the
# phrase above: one wording, so two commands cannot describe it differently.
PROBE_FAILED = "probe failed"


def _probe_failed(domain: str, exc: Exception) -> str:
    """The warning for a probe that could not be made at all.

    The probe never reached the instance, so nothing is known about it —
    which is a failed health check, not a check that did not apply.
    """
    return f"anubis@{domain}.service HTTP {PROBE_FAILED}: {exc}"


# A probe answers with the status code of an HTTP response, or with 000 when
# curl never got one. 2xx and 3xx are Anubis serving or challenging; 4xx and
# 5xx are the instance answering with its own failure.
HEALTHY_STATUS = range(200, 400)
NO_RESPONSE_STATUS = 0


def _status_code(raw: str) -> int | None:
    """The probe's answer as a number, or None if it was not one.

    A status code is a number and is compared as one. Reading it as text —
    "does it start with a 2 or a 3" — makes the verdict depend on the shape
    of what curl printed rather than on the code it stands for.
    """
    try:
        return int(raw.strip())
    except ValueError:
        return None


def _probe_answer(raw: str) -> str:
    """How a probe's answer reads in a message.

    ``000`` is curl reporting that it never got a response, so it is not
    reported as an HTTP status: "HTTP 000" reads like the instance answered.
    """
    code = _status_code(raw)
    if code is None:
        return f"unreadable answer {raw!r}"
    if code == NO_RESPONSE_STATUS:
        return "no response"
    return f"HTTP {code}"


@dataclass
class CommandResult:
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None


# --- Rolling restart ----------------------------------------------------------
#
# `upgrade` and `restart` both restart every instance one at a time, checking
# each before touching the next. One implementation, because the check is the
# whole point of restarting them one at a time: a version of it that passes
# where the other fails would let a bad rollout continue.


@dataclass
class HealthVerdict:
    """What one health check found.

    ``detail`` is the whole story, as a warning tells it ("HTTP probe timed
    out after 10s"); ``reason`` is the short phrase an error names it by
    ("probe timed out"). Deciding and reporting are separate so that every
    way of *not knowing* an instance is healthy comes back as a verdict
    rather than as a caller's guess: a check that could not be made is not
    a check that passed, and treating it as one carries the fault to the
    next instance — the failure a rolling restart exists to prevent.
    """

    ok: bool
    detail: str
    reason: str = ""


def _health_verdict(
    anubis_user: str, inst: AnubisInstance, runner: Runner
) -> HealthVerdict:
    """Is the instance up and answering, and if not, what happened?"""
    state = is_active(anubis_user, inst.domain, runner=runner)
    if state != "active":
        return HealthVerdict(
            False, f"is {state} after restart", "service not active"
        )

    try:
        raw = _http_probe(inst.domain, inst.port, runner)
    except CommandTimeout:
        # A probe that never answered is the wedged instance a rolling
        # restart exists to catch, not a probe to shrug at.
        return HealthVerdict(
            False, f"HTTP probe {PROBE_TIMED_OUT}", "probe timed out"
        )
    except CommandFailed as e:
        return HealthVerdict(False, f"HTTP {PROBE_FAILED}: {e}", PROBE_FAILED)

    answer = _probe_answer(raw)
    if _status_code(raw) not in HEALTHY_STATUS:
        return HealthVerdict(False, f"HTTP probe returned {answer}", answer)
    return HealthVerdict(True, answer)


def _restart_one(
    anubis_user: str, inst: AnubisInstance, runner: Runner, result: CommandResult
) -> None:
    """Restart one instance and say so — the step both restart modes share."""
    restart_service(anubis_user, inst.domain, runner=runner)
    result.steps.append(f"Restarted anubis@{inst.domain}.service")


def _rolling_restart(
    anubis_user: str,
    instances: list[AnubisInstance],
    runner: Runner,
    result: CommandResult,
) -> None:
    """Restart each instance, stopping at the first that fails its check."""
    for inst in instances:
        _restart_one(anubis_user, inst, runner, result)
        verdict = _health_verdict(anubis_user, inst, runner)
        if not verdict.ok:
            result.warnings.append(
                f"anubis@{inst.domain}.service {verdict.detail} — stopping"
            )
            result.error = f"Health check failed for {inst.domain} ({verdict.reason})"
            return
        result.steps.append(f"  Health check: active ({verdict.detail})")


def _restart_all_at_once(
    anubis_user: str,
    instances: list[AnubisInstance],
    runner: Runner,
    result: CommandResult,
) -> None:
    """Restart every instance without checking — what --no-rolling asks for."""
    for inst in instances:
        _restart_one(anubis_user, inst, runner, result)


# --- install ------------------------------------------------------------------


def cmd_install(
    anubis_user: str = DEFAULT_ANUBIS_USER,
    version: str = ANUBIS_VERSION,
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
    policy_file: str | None = None,
    init_policy: bool = False,
) -> CommandResult:
    _validate_inputs(anubis_user, policy_file=policy_file, version=version)

    result = CommandResult()

    if not dry_run:
        if not user_exists(anubis_user, runner):
            create_user(anubis_user, runner=runner)
            result.steps.append(f"Created user {anubis_user}")
        else:
            result.steps.append(f"User {anubis_user} already exists")

        if not binary_exists(anubis_user, runner=runner):
            ver = download_binary(anubis_user, version, runner=runner)
            result.steps.append(f"Downloaded Anubis binary v{version} ({ver.strip()})")
        else:
            ver = binary_version(anubis_user, runner=runner)
            result.steps.append(f"Anubis binary already installed ({ver})")

        if not template_exists(anubis_user, runner=runner):
            write_systemd_template(anubis_user, SYSTEMD_TEMPLATE, runner=runner)
            daemon_reload(anubis_user, runner=runner)
            result.steps.append("Installed systemd template anubis@.service")
        else:
            result.steps.append("Systemd template anubis@.service already exists")

        if init_policy:
            if not policy_file:
                result.warnings.append(
                    "--init-policy ignored: no policy_file in config")
            else:
                extract_policy(anubis_user, policy_file, runner=runner)
                result.steps.append(f"Extracted default bot policy to {policy_file}")
    else:
        result.steps.append(f"Would create user {anubis_user} (if not exists)")
        result.steps.append(f"Would download Anubis binary v{version}")
        result.steps.append("Would install systemd template anubis@.service (if not exists)")
        if init_policy and policy_file:
            result.steps.append(f"Would extract default bot policy to {policy_file}")

    return result


# --- uninstall ----------------------------------------------------------------


def cmd_uninstall(
    anubis_user: str = DEFAULT_ANUBIS_USER,
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
) -> CommandResult:
    _validate_inputs(anubis_user)

    result = CommandResult()

    instances = discover_instances(runner=runner)
    if instances:
        result.error = (
            f"Cannot uninstall: {len(instances)} Anubis instance(s) still exist. "
            f"Disable all domains first:\n  "
            + "\n  ".join(f"nine-manage-anubis disable {i.domain}" for i in instances)
        )
        return result

    if not dry_run:
        remove_systemd_template(anubis_user, runner=runner)
        result.steps.append(f"Removed systemd template")

        remove_file(anubis_user, f"/home/{anubis_user}/bin/anubis", runner=runner)
        result.steps.append(f"Removed Anubis binary")

        remove_user(anubis_user, runner=runner)
        result.steps.append(f"Removed user {anubis_user}")
    else:
        result.steps.append("Would remove systemd template")
        result.steps.append("Would remove Anubis binary")
        result.steps.append(f"Would remove user {anubis_user}")

    return result


# --- enable -------------------------------------------------------------------


def _rollback(undo_stack: list, result: CommandResult) -> None:
    """Execute undo actions in reverse order. Best-effort."""
    undone = 0
    for undo in reversed(undo_stack):
        try:
            undo()
            undone += 1
        except Exception:
            result.warnings.append("A rollback step failed — manual cleanup may be needed")
    result.steps.append(f"Rolled back {undone} of {len(undo_stack)} step(s)")


def _fail_with_rollback(undo_stack: list, result: CommandResult, exc: Exception) -> None:
    """Roll back and set error message."""
    _rollback(undo_stack, result)
    result.error = f"Enable failed: {exc}. Rolled back {len(undo_stack)} step(s)."


def cmd_enable(
    domain: str,
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
    prepare_only: bool = False,
    cutover_only: bool = False,
    anubis_user: str = DEFAULT_ANUBIS_USER,
    policy_file: str | None = None,
    no_notify: bool = False,
) -> CommandResult:
    _validate_inputs(anubis_user, policy_file=policy_file, domain=domain)

    result = CommandResult()

    vh = get_vhost(domain, runner=runner)
    if vh is None:
        result.error = f"Vhost {domain} not found"
        return result

    # Read every field this command needs before it does anything, so an
    # incomplete record is a message rather than a KeyError partway through.
    try:
        webroot = required_vhost_field(vh, "webroot")
        website_user = required_vhost_field(vh, "user")
        template = required_vhost_field(vh, "template")
    except ValidationError as e:
        result.error = str(e)
        return result

    tv = vh.get("template_variables", {})
    php_version = tv.get("PHP_VERSION")

    if template == PROXY_TEMPLATE:
        result.error = f"{domain} is already behind Anubis"
        return result

    alloc = allocate_for_domain(domain, runner=runner)

    if alloc.is_reused:
        result.steps.append(
            f"Reusing existing Anubis instance for {alloc.reused_from} "
            f"(port {alloc.app_port})"
        )
        if dry_run:
            if not prepare_only:
                result.steps.append(f"Would switch {domain} to proxy template (PROXYPORT={alloc.app_port})")
            return result

        if not cutover_only:
            result.warnings.append(
                f"{domain} shares webroot with {alloc.reused_from} — "
                f"fixups should already be installed"
            )

        if not prepare_only:
            undo_stack: list = []
            try:
                if not certificate_exists(domain, runner=runner):
                    create_certificate(domain, runner=runner)
                    result.steps.append(f"Created Let's Encrypt certificate for {domain}")
                switch_to_proxy(domain, alloc.app_port, no_notify=no_notify, runner=runner)
                undo_stack.append(lambda: switch_to_default(domain, no_notify=no_notify, runner=runner))
                result.steps.append(f"Switched {domain} to proxy template (PROXYPORT={alloc.app_port})")
            except Exception as e:
                _fail_with_rollback(undo_stack, result, e)
                return result
        return result

    config = AnubisConfig(
        domain=domain,
        app_port=alloc.app_port,
        metrics_port=alloc.metrics_port,
        anubis_user=anubis_user,
        key_path=key_path_for(anubis_user, domain),
    )

    undo_stack: list = []
    ops = RemoteFileOps(website_user, runner)

    if not cutover_only:
        key_content = generate_key(runner=runner)
        result.steps.append(f"Generated JWT key")

        env_content = generate_env_file(config, policy_file=policy_file)
        result.steps.append(f"Prepared env file ({config.env_path})")

        if not template_exists(anubis_user, runner=runner):
            if dry_run:
                result.steps.append("Would install systemd template anubis@.service")
            else:
                write_systemd_template(anubis_user, SYSTEMD_TEMPLATE, runner=runner)
                daemon_reload(anubis_user, runner=runner)
                result.steps.append("Installed systemd template anubis@.service")
        else:
            result.steps.append("Systemd template already installed")

        fixup_plan = apply_fixups(webroot, ops, dry_run=True)
        result.steps.extend(f"Fixup: {s}" for s in fixup_plan.steps)

        result.steps.append(f"Create origin vhost origin-{domain}")

        result.steps.append(f"Start anubis@{domain}.service")

        if not dry_run:
            try:
                write_key_file(anubis_user, config.key_path, key_content, runner=runner)
                undo_stack.append(lambda: remove_file(anubis_user, config.key_path, runner=runner))

                write_env_file(anubis_user, config.env_path, env_content, runner=runner)
                undo_stack.append(lambda: remove_file(anubis_user, config.env_path, runner=runner))

                if not template_exists(anubis_user, runner=runner):
                    write_systemd_template(anubis_user, SYSTEMD_TEMPLATE, runner=runner)

                daemon_reload(anubis_user, runner=runner)

                apply_fixups(webroot, ops, dry_run=False)
                undo_stack.append(lambda: restore_fixups(webroot, ops, dry_run=False))

                create_origin_vhost(domain, website_user, webroot, php_version, no_notify=no_notify, runner=runner)
                undo_stack.append(lambda: remove_origin_vhost(domain, no_notify=no_notify, runner=runner))

                enable_service(anubis_user, domain, runner=runner)
                undo_stack.append(lambda: disable_service(anubis_user, domain, runner=runner))
            except Exception as e:
                _fail_with_rollback(undo_stack, result, e)
                return result

    if not prepare_only:
        if dry_run:
            result.steps.append(f"Would cut over {domain} to proxy template (PROXYPORT={alloc.app_port})")
        else:
            try:
                if not certificate_exists(domain, runner=runner):
                    create_certificate(domain, runner=runner)
                    result.steps.append(f"Created Let's Encrypt certificate for {domain}")
                switch_to_proxy(domain, alloc.app_port, no_notify=no_notify, runner=runner)
                undo_stack.append(lambda: switch_to_default(domain, no_notify=no_notify, runner=runner))
                result.steps.append(f"Cut over {domain} to proxy template (PROXYPORT={alloc.app_port})")
            except Exception as e:
                _fail_with_rollback(undo_stack, result, e)
                return result

    return result


# --- disable ------------------------------------------------------------------


def cmd_disable(
    domain: str,
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
    anubis_user: str = DEFAULT_ANUBIS_USER,
    no_notify: bool = False,
) -> CommandResult:
    _validate_inputs(anubis_user, domain=domain)

    result = CommandResult()

    vh = get_vhost(domain, runner=runner)
    if vh is None:
        result.error = f"Vhost {domain} not found"
        return result

    try:
        template = required_vhost_field(vh, "template")
    except ValidationError as e:
        result.error = str(e)
        return result

    if template != PROXY_TEMPLATE:
        result.error = f"{domain} is not behind Anubis (template is {template})"
        return result

    # The webroot and the user are only needed to tear the instance down, but
    # they are read here anyway: a disable that switched the template and then
    # discovered it could not finish would leave the vhost unprotected and the
    # instance still running.
    try:
        webroot = required_vhost_field(vh, "webroot")
        website_user = required_vhost_field(vh, "user")
    except ValidationError as e:
        result.error = str(e)
        return result

    tv = vh.get("template_variables", {})
    port = int(tv.get("PROXYPORT", 0))
    if not port:
        result.error = f"Cannot determine PROXYPORT for {domain}"
        return result

    vhosts_for_port = find_vhosts_for_port(port, runner=runner)
    is_last = len(vhosts_for_port) <= 1

    if dry_run:
        result.steps.append(f"Switch {domain} back to default_letsencrypt_https")
        if is_last:
            result.steps.append(f"This is the last vhost on port {port} — would tear down instance:")
            result.steps.append(f"  Stop + disable anubis@{domain}.service")
            result.steps.append(f"  Remove origin vhost origin-{domain}")
            result.steps.append(f"  Restore fixup files")
            result.steps.append(f"  Remove env file + key")
        else:
            result.steps.append(
                f"Other vhosts still on port {port}: {', '.join(v for v in vhosts_for_port if v != domain)} — "
                f"instance stays running"
            )
        return result

    switch_to_default(domain, no_notify=no_notify, runner=runner)
    result.steps.append(f"Switched {domain} back to default_letsencrypt_https")

    if is_last:
        disable_service(anubis_user, domain, runner=runner)
        result.steps.append(f"Stopped + disabled anubis@{domain}.service")

        remove_origin_vhost(domain, no_notify=no_notify, runner=runner)
        result.steps.append(f"Removed origin vhost origin-{domain}")

        ops = RemoteFileOps(website_user, runner)
        restore_fixups(webroot, ops, dry_run=False)
        result.steps.append("Restored fixup files")

        env_path = env_path_for(anubis_user, domain)
        key_path = key_path_for(anubis_user, domain)
        remove_file(anubis_user, env_path, runner=runner)
        remove_file(anubis_user, key_path, runner=runner)
        result.steps.append("Removed env file + key")
    else:
        others = [v for v in vhosts_for_port if v != domain]
        result.steps.append(
            f"Instance still serving: {', '.join(others)} — left running"
        )

    return result


# --- upgrade ------------------------------------------------------------------


def cmd_upgrade(
    version: str | None = None,
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
    no_rolling: bool = False,
    anubis_user: str = DEFAULT_ANUBIS_USER,
) -> CommandResult:
    _validate_inputs(anubis_user, version=version)

    result = CommandResult()

    target_version = version or get_latest_version(runner=runner)
    result.steps.append(f"Target version: {target_version}")

    current = binary_version(anubis_user, runner=runner)
    result.steps.append(f"Current version: {current}")

    if dry_run:
        result.steps.append(f"Would download Anubis v{target_version}")
        instances = discover_instances(runner=runner)
        if no_rolling:
            result.steps.append(f"Would restart all {len(instances)} instances at once")
        else:
            result.steps.append(f"Would rolling-restart {len(instances)} instances (one at a time with health check)")
        return result

    download_binary(anubis_user, target_version, runner=runner)
    result.steps.append(f"Downloaded Anubis v{target_version}")

    daemon_reload(anubis_user, runner=runner)

    instances = discover_instances(runner=runner)
    if not instances:
        result.steps.append("No instances to restart")
        return result

    if no_rolling:
        _restart_all_at_once(anubis_user, instances, runner, result)
    else:
        _rolling_restart(anubis_user, instances, runner, result)

    return result


# --- status -------------------------------------------------------------------


def cmd_status(
    domain: str | None = None,
    runner: Runner = SubprocessRunner(),
    health: bool = False,
) -> tuple[list[AnubisInstance], dict[str, str] | None]:
    _validate_inputs(domain=domain)

    instances = discover_instances(runner=runner)

    if domain:
        instances = [i for i in instances if i.domain == domain or domain in i.vhosts]

    health_map = None
    if health:
        health_map = {}
        for inst in instances:
            if inst.is_running:
                try:
                    health_map[inst.domain] = _probe_answer(
                        _http_probe(inst.domain, inst.port, runner)
                    )
                except CommandTimeout:
                    health_map[inst.domain] = PROBE_TIMED_OUT
                except CommandFailed as e:
                    health_map[inst.domain] = f"{PROBE_FAILED} (exit {e.returncode})"
            else:
                health_map[inst.domain] = "inactive"

    return instances, health_map


# --- self-test ----------------------------------------------------------------


def _check(result: CommandResult, ok: bool, pass_msg: str, fail_msg: str) -> None:
    if ok:
        result.steps.append(pass_msg)
    else:
        result.warnings.append(fail_msg)


def cmd_selftest(
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
    anubis_user: str = DEFAULT_ANUBIS_USER,
) -> CommandResult:
    _validate_inputs(anubis_user)

    result = CommandResult()

    if dry_run:
        result.steps.append(f"Would check user {anubis_user} exists")
        result.steps.append("Would check binary runs")
        result.steps.append("Would check systemd template exists")
        result.steps.append("Would check each instance is active + HTTP-responding")
        return result

    _check(result, user_exists(anubis_user, runner=runner),
           f"User {anubis_user} exists", f"User {anubis_user} does not exist")

    _check(result, binary_exists(anubis_user, runner=runner),
           f"Binary: {binary_version(anubis_user, runner=runner).strip()}",
           f"Binary not found for {anubis_user}")

    _check(result, template_exists(anubis_user, runner=runner),
           "Systemd template installed", "Systemd template not installed")

    instances = discover_instances(runner=runner)
    if not instances:
        result.steps.append("No instances to check")
        if result.warnings:
            result.error = f"{len(result.warnings)} check(s) failed"
        return result

    for inst in instances:
        if not inst.is_running:
            result.warnings.append(
                f"anubis@{inst.domain}.service is not active (state: {inst.service_state})")
            continue
        result.steps.append(f"anubis@{inst.domain}.service: active")
        # Any answer at all means Anubis is listening, so self-test reports a
        # 502 as a pass where a rolling restart would stop: it is describing
        # the box, not deciding whether to touch the next instance.
        try:
            raw = _http_probe(inst.domain, inst.port, runner)
        except CommandTimeout:
            result.warnings.append(_probe_timed_out(inst.domain))
            continue
        except CommandFailed as e:
            result.warnings.append(_probe_failed(inst.domain, e))
            continue
        code = _status_code(raw)
        if code is None or code == NO_RESPONSE_STATUS:
            result.warnings.append(
                f"anubis@{inst.domain}.service HTTP probe returned "
                f"{_probe_answer(raw)}"
            )
        else:
            result.steps.append(f"  HTTP probe: {code}")

    if result.warnings:
        result.error = f"{len(result.warnings)} check(s) failed"
    return result


# --- restart ------------------------------------------------------------------


def cmd_restart(
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
    no_rolling: bool = False,
    anubis_user: str = DEFAULT_ANUBIS_USER,
) -> CommandResult:
    _validate_inputs(anubis_user)

    result = CommandResult()

    instances = discover_instances(runner=runner)
    if not instances:
        result.steps.append("No instances to restart")
        return result

    if dry_run:
        if no_rolling:
            result.steps.append(f"Would restart all {len(instances)} instances at once")
        else:
            result.steps.append(
                f"Would rolling-restart {len(instances)} instances "
                f"(one at a time with health check)"
            )
        return result

    if no_rolling:
        _restart_all_at_once(anubis_user, instances, runner, result)
    else:
        _rolling_restart(anubis_user, instances, runner, result)

    return result
