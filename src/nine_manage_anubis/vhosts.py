"""Wrapper for nine-manage-vhosts CLI commands.

All functions take an injectable Runner. Commands that modify vhost
state (create, update, remove) are thin wrappers that build the correct
command string and execute it via the runner.
"""

from __future__ import annotations

import re

from .runner import Runner, SubprocessRunner

# --- Templates ----------------------------------------------------------------

PROXY_TEMPLATE = "proxy_letsencrypt_https_redirect"
ORIGIN_TEMPLATE = "default_snakeoil_https"
DEFAULT_LE_TEMPLATE = "default_letsencrypt_https"
DEFAULT_TEMPLATE = "default"

# --- Vhost operations ---------------------------------------------------------


def create_vhost(
    domain: str,
    user: str,
    template: str = DEFAULT_TEMPLATE,
    webroot: str | None = None,
    template_variables: dict[str, str] | None = None,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    parts = [
        "sudo nine-manage-vhosts virtual-host create",
        domain,
        f"--user={user}",
        f"--template={template}",
    ]
    if webroot:
        parts.append(f"--webroot={webroot}")
    if template_variables:
        for key, val in template_variables.items():
            parts.append(f"--template-variable={key}={val}")
    if no_notify:
        parts.append("--no-notify-services")
    return runner(" ".join(parts))


def update_vhost(
    domain: str,
    template: str | None = None,
    template_variables: dict[str, str] | None = None,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    parts = ["sudo nine-manage-vhosts virtual-host update", domain]
    if template:
        parts.append(f"--template={template}")
    if template_variables:
        for key, val in template_variables.items():
            parts.append(f"--template-variable={key}={val}")
    if no_notify:
        parts.append("--no-notify-services")
    return runner(" ".join(parts))


def remove_vhost(
    domain: str,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    cmd = f"sudo nine-manage-vhosts virtual-host remove {domain}"
    if no_notify:
        cmd += " --no-notify-services"
    return runner(cmd)


def webserver_reload(runner: Runner = SubprocessRunner()) -> str:
    return runner("sudo nine-manage-vhosts webserver reload")


def create_origin_vhost(
    domain: str,
    user: str,
    webroot: str,
    php_version: str | None = None,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    origin_domain = f"origin-{domain}"
    tv: dict[str, str] = {}
    if php_version:
        tv["PHP_VERSION"] = php_version
    return create_vhost(
        origin_domain,
        user,
        template=ORIGIN_TEMPLATE,
        webroot=webroot,
        template_variables=tv or None,
        no_notify=no_notify,
        runner=runner,
    )


def remove_origin_vhost(
    domain: str,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    return remove_vhost(f"origin-{domain}", no_notify=no_notify, runner=runner)


def switch_to_proxy(
    domain: str,
    proxyport: int,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    return update_vhost(
        domain,
        template=PROXY_TEMPLATE,
        template_variables={"PROXYPORT": str(proxyport)},
        no_notify=no_notify,
        runner=runner,
    )


def switch_to_default(
    domain: str,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    return update_vhost(
        domain,
        template=DEFAULT_LE_TEMPLATE,
        no_notify=no_notify,
        runner=runner,
    )


# --- Certificate operations ---------------------------------------------------


_CERT_RE = re.compile(r"DOMAIN:\s+(\S+)\s+VALID UNTIL:\s+(\d{4}-\d{2}-\d{2})")


def list_certificates(runner: Runner = SubprocessRunner()) -> dict[str, str]:
    """Parse `certificate list` text output. Returns {domain: expiry_date}."""
    raw = runner("sudo nine-manage-vhosts certificate list")
    certs = {}
    for m in _CERT_RE.finditer(raw):
        certs[m.group(1)] = m.group(2)
    return certs


def certificate_exists(domain: str, runner: Runner = SubprocessRunner()) -> bool:
    return domain in list_certificates(runner)


def create_certificate(domain: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(f"sudo nine-manage-vhosts certificate create --virtual-host={domain}")


def remove_certificate(domain: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(f"sudo nine-manage-vhosts certificate remove --virtual-host={domain}")


# --- User operations ----------------------------------------------------------


def list_users(runner: Runner = SubprocessRunner()) -> list[dict]:
    import json
    raw = runner("sudo nine-manage-vhosts user list --json")
    return json.loads(raw)


def user_exists(name: str, runner: Runner = SubprocessRunner()) -> bool:
    users = list_users(runner)
    return any(u.get("name") == name for u in users)


def create_user(name: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(f"sudo nine-manage-vhosts user create {name} --no-password")


def remove_user(name: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(f"sudo nine-manage-vhosts user remove {name}")
