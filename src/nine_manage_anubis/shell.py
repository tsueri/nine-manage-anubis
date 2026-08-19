"""Shell quoting for every value that lands in a command string.

Commands run with ``shell=True`` under ``sudo``, and several are additionally
carried inside a heredoc that a shell on the far side of ``nine-su`` re-parses.
A value spliced into either layer unquoted can end the command it sits in and
start another; a webroot with a space merely word-splits, one with a backtick
runs as root.

:mod:`~nine_manage_anubis.validate` proves a value has an accepted *shape*;
this module makes a value *inert* regardless of shape. The two are independent
on purpose: the whitelist cannot cover webroots, arbitrary template variables
or file paths that legitimately hold characters it would reject, and quoting
does not care whether a value is well-formed.

Quoting is applied by the code that builds each command — the wrappers in
:mod:`~nine_manage_anubis.vhosts`, :mod:`~nine_manage_anubis.systemd`,
:mod:`~nine_manage_anubis.nine_su` and :mod:`~nine_manage_anubis.ports` — not
by their callers, so there is no way to reach a shell without passing through
here. Each shell that parses a value needs its own layer: a value inside a
``nine-su`` script is quoted for the far-side shell, while the heredoc's quoted
delimiter keeps the local shell out of the body entirely.
"""

from __future__ import annotations

import secrets
import shlex


def quote(value: str | int) -> str:
    """Return ``value`` as a single shell word.

    Safe values are returned unchanged, so commands stay readable in logs and
    in the ``Command failed`` message; anything else is single-quoted, which
    disarms every metacharacter a POSIX shell knows.
    """
    return shlex.quote(str(value))


def quote_glob_prefix(prefix: str) -> str:
    """Return a pattern matching everything whose name starts with ``prefix``.

    The trailing ``*`` is the only live glob metacharacter: ``prefix`` itself
    is quoted, so a ``*``, ``?`` or ``[`` inside it matches literally and
    cannot widen the match. For listing our own timestamped backups, where the
    prefix is a path we did not choose and the suffix is the only wildcard.
    """
    return f"{quote(prefix)}*"


def heredoc(command: str, body: str, marker: str) -> str:
    """Feed ``body`` to ``command`` on stdin via a quoted heredoc.

    The quoted delimiter (``<<'MARKER'``) is what makes the body literal: no
    expansion, no substitution, and nothing in it has to be escaped. The one
    remaining way out is a body line that *equals* the delimiter, which would
    end the heredoc early and hand the rest to the shell as commands — so a
    body carrying such a line gets a delimiter it does not contain.
    """
    delimiter = _free_marker(marker, body)
    return f"{command} <<'{delimiter}'\n{body}\n{delimiter}"


def _free_marker(marker: str, body: str) -> str:
    """A delimiter that no line of ``body`` can be mistaken for."""
    while any(line.strip() == marker for line in body.splitlines()):
        marker = f"{marker}_{secrets.token_hex(4)}"
    return marker
