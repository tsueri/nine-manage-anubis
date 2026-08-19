"""Whitelist validation for every value that reaches a privileged command.

Commands are executed with ``shell=True`` under ``sudo``, so any string
interpolated into a command must first be proven to be one of a small set
of accepted shapes. Nothing here tries to *escape* or *sanitise* input —
a value either matches its whitelist verbatim and is returned unchanged,
or it raises :class:`ValidationError`.

Accepted forms:

===============  ==========================================
domain           ``[a-z0-9.-]``, max 253, DNS label rules
system user      ``[a-z_][a-z0-9_-]*``, max 32
Anubis version   ``N.N.N``
PHP version      ``N.N``
port             integer inside a stated range
path             absolute, no metacharacters, no traversal
filename         one path component, no separator, no traversal
===============  ==========================================

Called from the CLI (so an interactive user gets a good message), from the
public command entry points in :mod:`~nine_manage_anubis.commands` (so the
library is safe when driven directly), and on values read back from
``nine-manage-vhosts`` JSON, env-file scans and the GitHub releases API
(all of which are untrusted).
"""

from __future__ import annotations

import re

# Anubis instances get a port pair from this range. Kept here rather than in
# ports.py so validate.py stays a leaf module with no intra-package imports.
PORT_RANGE_START = 7010
PORT_RANGE_END = 7999

MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_USER_LENGTH = 32  # useradd's limit
MAX_PATH_LENGTH = 4096

_DOMAIN_CHARS = re.compile(r"[a-z0-9.-]+")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?")
_SYSTEM_USER = re.compile(r"[a-z_][a-z0-9_-]*")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_PHP_VERSION = re.compile(r"[0-9]+\.[0-9]+")
_PATH = re.compile(r"/[A-Za-z0-9._/-]*")
_FILENAME = re.compile(r"[A-Za-z0-9._-]+")

MIN_TCP_PORT = 1
MAX_TCP_PORT = 65535

_DOMAIN_FORM = (
    "lowercase letters, digits, dots and hyphens, as dot-separated DNS "
    "labels (e.g. example.com)"
)
_USER_FORM = (
    "a system user name: lowercase letters, digits, underscores and "
    "hyphens, starting with a letter or underscore (e.g. www-anubis)"
)
_VERSION_FORM = "a three-part version number without a leading 'v' (e.g. 1.27.0)"
_PHP_VERSION_FORM = "a two-part PHP version number (e.g. 8.2)"
_PATH_FORM = (
    "an absolute path of letters, digits, dots, underscores, hyphens and "
    "slashes, with no '..' segment (e.g. /home/www-anubis/policy.yaml)"
)
_FILENAME_FORM = (
    "a single file name of letters, digits, dots, underscores and hyphens, "
    "with no path separator and no '..' (e.g. anubis-origin-shim.php)"
)


class ValidationError(ValueError):
    """A value failed its whitelist check and must not reach a command."""


def _reject(field: str, value: object, expected: str) -> ValidationError:
    return ValidationError(
        f"Invalid {field} {value!r}: expected {expected}."
    )


def validate_domain(value: object, field: str = "domain") -> str:
    """Return ``value`` unchanged if it is an acceptable domain name."""
    if not isinstance(value, str):
        raise _reject(field, value, _DOMAIN_FORM)
    # re.fullmatch, not re.match with '$' — '$' also matches before a
    # trailing newline, which would let 'example.com\n' slip through.
    if not _DOMAIN_CHARS.fullmatch(value):
        raise _reject(field, value, _DOMAIN_FORM)
    if len(value) > MAX_DOMAIN_LENGTH:
        raise _reject(field, value, _DOMAIN_FORM)
    for label in value.split("."):
        if not label or len(label) > MAX_LABEL_LENGTH:
            raise _reject(field, value, _DOMAIN_FORM)
        if not _LABEL.fullmatch(label):
            raise _reject(field, value, _DOMAIN_FORM)
    return value


def validate_system_user(value: object, field: str = "system user") -> str:
    """Return ``value`` unchanged if it is an acceptable system user name."""
    if not isinstance(value, str) or not _SYSTEM_USER.fullmatch(value):
        raise _reject(field, value, _USER_FORM)
    if len(value) > MAX_USER_LENGTH:
        raise _reject(field, value, _USER_FORM)
    return value


def validate_version(value: object, field: str = "Anubis version") -> str:
    """Return ``value`` unchanged if it is an acceptable version number."""
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise _reject(field, value, _VERSION_FORM)
    return value


def validate_php_version(value: object, field: str = "PHP version") -> str:
    """Return ``value`` unchanged if it is an acceptable PHP version number."""
    if not isinstance(value, str) or not _PHP_VERSION.fullmatch(value):
        raise _reject(field, value, _PHP_VERSION_FORM)
    return value


def validate_port(
    value: object,
    field: str = "port",
    *,
    minimum: int = PORT_RANGE_START,
    maximum: int = PORT_RANGE_END,
) -> int:
    """Return ``value`` as an int if it is a port inside ``minimum``..``maximum``.

    The default bounds are the Anubis allocation range. Pass
    ``minimum=MIN_TCP_PORT, maximum=MAX_TCP_PORT`` for a port that only has
    to be a plausible TCP port — e.g. the ``PROXYPORT`` of some *other*
    application's proxy vhost, which we must parse safely but not claim.
    """
    expected = f"an integer between {minimum} and {maximum}"
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise _reject(field, value, expected)
    if isinstance(value, str):
        if not value.isascii() or not value.isdigit():
            raise _reject(field, value, expected)
        port = int(value)
    else:
        port = value
    if not minimum <= port <= maximum:
        raise _reject(field, value, expected)
    return port


def validate_path(value: object, field: str = "path") -> str:
    """Return ``value`` unchanged if it is an acceptable absolute path."""
    if not isinstance(value, str) or not _PATH.fullmatch(value):
        raise _reject(field, value, _PATH_FORM)
    if len(value) > MAX_PATH_LENGTH:
        raise _reject(field, value, _PATH_FORM)
    if ".." in value.split("/"):
        raise _reject(field, value, _PATH_FORM)
    return value


def validate_filename(value: object, field: str = "file name") -> str:
    """Return ``value`` unchanged if it is a single safe path component.

    For names read out of a webroot file — a chained ``auto_prepend_file``,
    say — which are joined onto a webroot and then quoted into a shell
    command. A separator or ``..`` would escape the webroot.
    """
    if not isinstance(value, str) or not _FILENAME.fullmatch(value):
        raise _reject(field, value, _FILENAME_FORM)
    if value in (".", ".."):
        raise _reject(field, value, _FILENAME_FORM)
    return value


def required_vhost_field(vhost: dict, key: str, field: str = "vhost") -> str:
    """The value of a vhost field a command cannot be built without.

    ``nine-manage-vhosts`` reports the webroot, the owning user and the
    template, and each of them ends up in a further command. Indexing the
    dict for one turns an unexpected shape — a vhost type we have not seen,
    or an upstream change to the JSON — into a bare ``KeyError``, which names
    neither the vhost it came from nor what the tool wanted from it.
    """
    value = vhost.get(key)
    if not isinstance(value, str):
        name = vhost.get("domain", "(unnamed)")
        reported = "no" if value is None else f"a {type(value).__name__} for"
        raise ValidationError(
            f"Incomplete {field} record for {name}: nine-manage-vhosts "
            f"reported {reported} {key!r}."
        )
    return value


def validate_vhost_record(vhost: object, field: str = "vhost") -> dict:
    """Validate every field of a ``nine-manage-vhosts`` JSON record we use.

    nine-manage-vhosts runs privileged, but the values it reports back are
    operator-supplied strings that end up inside further sudo commands. A
    malformed one is either corruption or an attack: fail loudly rather than
    build a command around it.

    ``PROXYPORT`` is checked as any plausible TCP port rather than an Anubis
    one — a vhost may legitimately proxy to some other application, and the
    allocation-range filter happens later.
    """
    if not isinstance(vhost, dict):
        raise ValidationError(
            f"Invalid {field} record from nine-manage-vhosts: expected a "
            f"JSON object, got {vhost!r}."
        )
    validate_domain(vhost.get("domain"), field=f"{field} domain")
    if vhost.get("user") is not None:
        validate_system_user(vhost["user"], field=f"{field} user")
    if vhost.get("webroot") is not None:
        validate_path(vhost["webroot"], field=f"{field} webroot")
    tv = vhost.get("template_variables") or {}
    if "PROXYPORT" in tv:
        validate_port(
            tv["PROXYPORT"],
            field=f"{field} PROXYPORT",
            minimum=MIN_TCP_PORT,
            maximum=MAX_TCP_PORT,
        )
    if tv.get("PHP_VERSION") is not None:
        validate_php_version(tv["PHP_VERSION"], field=f"{field} PHP_VERSION")
    return vhost
