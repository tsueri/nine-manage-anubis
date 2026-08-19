"""Shared test fixtures and helpers."""

import sys
from pathlib import Path

# Ensure src/ is importable without installation.
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


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
