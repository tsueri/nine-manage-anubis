"""Wrapper for nine-manage-vhosts CLI commands.

All functions take an injectable Runner. Commands that modify vhost
state (create, update, remove) are thin wrappers that build the correct
command string and execute it via the runner.

Every value these wrappers splice into a command is quoted here, so callers
pass raw values and cannot forget. That matters most for the values no
whitelist can constrain: a webroot is whatever nine-manage-vhosts reports,
and a template variable is an arbitrary key/value pair.
"""

from __future__ import annotations

import re

from .runner import Runner, SubprocessRunner
from .shell import quote

# A vhost change rewrites Apache config and notifies the webserver, so it is
# slower than a query but not slow in the way the network is.
VHOST_TIMEOUT = 120.0

# Issuing a certificate means an ACME round trip with Let's Encrypt, including
# a challenge Apache has to serve. Generous on purpose: a timeout here aborts
# an enable and rolls it back, so a slow CA must not look like a broken one.
CERTIFICATE_TIMEOUT = 300.0

# --- Templates ----------------------------------------------------------------

PROXY_TEMPLATE = "proxy_letsencrypt_https_redirect"
ORIGIN_TEMPLATE = "default_snakeoil_https"
DEFAULT_LE_TEMPLATE = "default_letsencrypt_https"
DEFAULT_TEMPLATE = "default"

# --- Vhost operations ---------------------------------------------------------


def _template_variable_options(
    template_variables: dict[str, str] | None,
) -> list[str]:
    """Render template variables as quoted --template-variable options.

    Key and value are quoted separately so a readable option survives in the
    common case; either one can carry anything, so both need it.
    """
    if not template_variables:
        return []
    return [
        f"--template-variable={quote(key)}={quote(value)}"
        for key, value in template_variables.items()
    ]


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
        quote(domain),
        f"--user={quote(user)}",
        f"--template={quote(template)}",
    ]
    if webroot:
        parts.append(f"--webroot={quote(webroot)}")
    parts.extend(_template_variable_options(template_variables))
    if no_notify:
        parts.append("--no-notify-services")
    return runner(
        " ".join(parts), timeout=VHOST_TIMEOUT, what=f"creating vhost {domain}"
    )


def update_vhost(
    domain: str,
    template: str | None = None,
    template_variables: dict[str, str] | None = None,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    parts = ["sudo nine-manage-vhosts virtual-host update", quote(domain)]
    if template:
        parts.append(f"--template={quote(template)}")
    parts.extend(_template_variable_options(template_variables))
    if no_notify:
        parts.append("--no-notify-services")
    return runner(
        " ".join(parts), timeout=VHOST_TIMEOUT, what=f"updating vhost {domain}"
    )


def remove_vhost(
    domain: str,
    no_notify: bool = False,
    runner: Runner = SubprocessRunner(),
) -> str:
    cmd = f"sudo nine-manage-vhosts virtual-host remove {quote(domain)}"
    if no_notify:
        cmd += " --no-notify-services"
    return runner(cmd, timeout=VHOST_TIMEOUT, what=f"removing vhost {domain}")


def webserver_reload(runner: Runner = SubprocessRunner()) -> str:
    return runner(
        "sudo nine-manage-vhosts webserver reload",
        timeout=VHOST_TIMEOUT,
        what="reloading the webserver",
    )


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
    raw = runner(
        "sudo nine-manage-vhosts certificate list", what="listing certificates"
    )
    certs = {}
    for m in _CERT_RE.finditer(raw):
        certs[m.group(1)] = m.group(2)
    return certs


def certificate_exists(domain: str, runner: Runner = SubprocessRunner()) -> bool:
    return domain in list_certificates(runner)


def create_certificate(domain: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(
        f"sudo nine-manage-vhosts certificate create --virtual-host={quote(domain)}",
        timeout=CERTIFICATE_TIMEOUT,
        what=f"requesting a certificate for {domain}",
    )


def remove_certificate(domain: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(
        f"sudo nine-manage-vhosts certificate remove --virtual-host={quote(domain)}",
        timeout=CERTIFICATE_TIMEOUT,
        what=f"removing the certificate for {domain}",
    )


# --- User operations ----------------------------------------------------------


def list_users(runner: Runner = SubprocessRunner()) -> list[dict]:
    import json
    raw = runner("sudo nine-manage-vhosts user list --json", what="listing users")
    return json.loads(raw)


def user_exists(name: str, runner: Runner = SubprocessRunner()) -> bool:
    users = list_users(runner)
    return any(u.get("name") == name for u in users)


def create_user(name: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(
        f"sudo nine-manage-vhosts user create {quote(name)} --no-password",
        what=f"creating user {name}",
    )


def remove_user(name: str, runner: Runner = SubprocessRunner()) -> str:
    return runner(
        f"sudo nine-manage-vhosts user remove {quote(name)}",
        what=f"removing user {name}",
    )
