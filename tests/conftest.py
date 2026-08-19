"""Shared test fixtures and helpers."""

import os
import stat
import sys
from pathlib import Path

import pytest

# Ensure src/ is importable without installation.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from nine_manage_anubis import ports  # noqa: E402  (needs the path above)


@pytest.fixture(autouse=True)
def port_lock_in_a_temporary_file(tmp_path_factory, monkeypatch):
    """Point the allocation lock at a file of this test's own.

    Every enable goes through the lock, so without this the suite would take
    the host's real one — serialising unrelated tests behind each other and
    behind anything actually running on the developer's machine. The short
    timeout is a tripwire: no test but the concurrency ones should ever
    contend, and one that does should say so rather than look like a hang.
    """
    path = tmp_path_factory.mktemp("port-lock") / "ports.lock"
    monkeypatch.setattr(ports, "PORT_LOCK_PATH", str(path))
    monkeypatch.setattr(ports, "PORT_LOCK_TIMEOUT", 2.0)


# The website user a webroot belongs to — the account nine-su switches to, and
# the one a write runs as.
USER = "www-example"


def mode_of(path: Path) -> int:
    """The permission bits of ``path`` — what other users on the box may do with it."""
    return stat.S_IMODE(os.stat(path).st_mode)


def hostile(base: str) -> list[str]:
    """The injection payloads every validator must reject, built onto `base`.

    One list so the coverage the spec asks for — semicolon, backtick, `$( )`,
    newline, leading dash, path traversal, empty string — stays identical
    across the validator, command and CLI test suites instead of drifting
    into three slightly different lists.
    """
    return [
        f"{base}; id",
        f"{base}`id`",
        f"{base}$(id)",
        f"{base}\nid",
        f"-{base}",
        "../../root",
        "",
    ]


# Payloads that reach our validators rather than being eaten by argparse
# (a leading dash looks like a flag, so argparse rejects it first).
def hostile_metacharacters(base: str) -> list[str]:
    return [v for v in hostile(base) if v and not v.startswith("-")]


# Webroots and paths are not covered by a whitelist — nine-manage-vhosts may
# report anything a filesystem allows — so the quoting, not the shape, is what
# keeps them harmless. One list shared by every wrapper's quoting tests.
HOSTILE_PATHS = [
    "/home/www example/my site",
    "/home/www-example/it's mine",
    "/home/www-example/`id`",
    "/home/www-example/$(id)",
    "/home/www-example/x; id",
    "/home/www-example/x\nid",
    "/home/www-example/$HOME",
    "/home/www-example/*",
]


# The heredoc delimiters this tool once hard-coded. Content holding one of them
# on a line ended the heredoc early and had the rest of itself run as commands,
# so they are the payload every write is checked against — one list, for the
# same reason as the one above.
TERMINATORS = ["FILE_EOF", "KEY_EOF", "NINE_SU_EOF"]
