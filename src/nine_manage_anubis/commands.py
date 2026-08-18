"""Command implementations for nine-manage-anubis.

Six commands: install, uninstall, enable, disable, upgrade, status.
Each takes an injectable Runner and returns a list of step strings
(what was done, or what would be done in dry-run mode).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .runner import Runner, SubprocessRunner
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
from .fileops import RemoteFileOps


DEFAULT_ANUBIS_USER = "www-anubis"
ANUBIS_VERSION = "1.27.0"


@dataclass
class CommandResult:
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None


# --- install ------------------------------------------------------------------


def cmd_install(
    anubis_user: str = DEFAULT_ANUBIS_USER,
    version: str = ANUBIS_VERSION,
    runner: Runner = SubprocessRunner(),
    dry_run: bool = False,
    policy_file: str | None = None,
    init_policy: bool = False,
) -> CommandResult:
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
) -> CommandResult:
    result = CommandResult()

    vh = get_vhost(domain, runner=runner)
    if vh is None:
        result.error = f"Vhost {domain} not found"
        return result

    webroot = vh["webroot"]
    website_user = vh["user"]
    tv = vh.get("template_variables", {})
    php_version = tv.get("PHP_VERSION")

    if vh["template"] == PROXY_TEMPLATE:
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
                switch_to_proxy(domain, alloc.app_port, runner=runner)
                undo_stack.append(lambda: switch_to_default(domain, runner=runner))
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

                create_origin_vhost(domain, website_user, webroot, php_version, runner=runner)
                undo_stack.append(lambda: remove_origin_vhost(domain, runner=runner))

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
                switch_to_proxy(domain, alloc.app_port, runner=runner)
                undo_stack.append(lambda: switch_to_default(domain, runner=runner))
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
) -> CommandResult:
    result = CommandResult()

    vh = get_vhost(domain, runner=runner)
    if vh is None:
        result.error = f"Vhost {domain} not found"
        return result

    if vh["template"] != PROXY_TEMPLATE:
        result.error = f"{domain} is not behind Anubis (template is {vh['template']})"
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

    switch_to_default(domain, runner=runner)
    result.steps.append(f"Switched {domain} back to default_letsencrypt_https")

    if is_last:
        disable_service(anubis_user, domain, runner=runner)
        result.steps.append(f"Stopped + disabled anubis@{domain}.service")

        remove_origin_vhost(domain, runner=runner)
        result.steps.append(f"Removed origin vhost origin-{domain}")

        ops = RemoteFileOps(vh["user"], runner)
        restore_fixups(vh["webroot"], ops, dry_run=False)
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
        for inst in instances:
            restart_service(anubis_user, inst.domain, runner=runner)
            result.steps.append(f"Restarted anubis@{inst.domain}.service")
    else:
        for inst in instances:
            restart_service(anubis_user, inst.domain, runner=runner)
            result.steps.append(f"Restarted anubis@{inst.domain}.service")
            state = is_active(anubis_user, inst.domain, runner=runner)
            if state != "active":
                result.warnings.append(
                    f"anubis@{inst.domain}.service is {state} after restart — stopping upgrade"
                )
                result.error = f"Health check failed for {inst.domain} (service not active)"
                return result
            try:
                response = runner(
                    f"curl -s -o /dev/null -w '%{{http_code}}' "
                    f"-H 'X-Real-Ip: 127.0.0.1' -H 'Host: {inst.domain}' "
                    f"http://localhost:{inst.port}/"
                )
                code = response.strip().strip("'")
                if code and code[0] in "23":
                    result.steps.append(f"  Health check: active (HTTP {code})")
                else:
                    result.warnings.append(f"anubis@{inst.domain}.service HTTP probe returned {code}")
                    result.error = f"Health check failed for {inst.domain} (HTTP {code})"
                    return result
            except Exception:
                result.steps.append(f"  Health check: active (service, HTTP probe skipped)")

    return result


# --- status -------------------------------------------------------------------


def cmd_status(
    domain: str | None = None,
    runner: Runner = SubprocessRunner(),
    health: bool = False,
) -> tuple[list[AnubisInstance], dict[str, str] | None]:
    instances = discover_instances(runner=runner)

    if domain:
        instances = [i for i in instances if i.domain == domain or domain in i.vhosts]

    health_map = None
    if health:
        health_map = {}
        for inst in instances:
            if inst.is_running:
                try:
                    response = runner(
                        f"curl -s -o /dev/null -w '%{{http_code}}' "
                        f"-H 'X-Real-Ip: 127.0.0.1' -H 'Host: {inst.domain}' "
                        f"http://localhost:{inst.port}/"
                    )
                    code = response.strip().strip("'")
                    health_map[inst.domain] = f"HTTP {code}" if code else "no response"
                except Exception:
                    health_map[inst.domain] = "error"
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
        try:
            response = runner(
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-H 'X-Real-Ip: 127.0.0.1' -H 'Host: {inst.domain}' "
                f"http://localhost:{inst.port}/"
            )
            code_str = response.strip().strip("'")
            try:
                code = int(code_str)
                ok = 200 <= code < 400
            except ValueError:
                code = code_str
                ok = False
            if ok:
                result.steps.append(f"  HTTP probe: {code}")
            else:
                result.warnings.append(
                    f"anubis@{inst.domain}.service HTTP probe returned {code}")
        except Exception:
            result.warnings.append(f"anubis@{inst.domain}.service HTTP probe failed")

    if result.warnings:
        result.error = f"{len(result.warnings)} check(s) failed"
    return result
