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

A heredoc body is the one place quoting does not reach — inside it, only the
delimiter means anything — so :func:`heredoc` gives every body a delimiter with
a fresh nonce in it. A fixed delimiter is a name the body's author can write,
and the bodies this tool writes are often files it did not author.
"""

from __future__ import annotations

import re
import secrets
import shlex

# 128 bits of delimiter. Long enough that content cannot be written to match a
# delimiter it never sees, short enough to keep a command readable.
_NONCE_BYTES = 16
_NONCE = re.compile(r"_[0-9a-f]{" + str(2 * _NONCE_BYTES) + r"}$")
_OPENER = re.compile(r"<<'([^']+)'")


class HeredocCollision(RuntimeError):
    """A heredoc body contains its own delimiter, so it cannot be written.

    Only reachable if the per-invocation nonce is guessed. Raised rather than
    worked around: a body carrying its delimiter would end the heredoc early
    and hand the rest of itself to the shell as commands.
    """


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


def heredoc(command: str, body: str, prefix: str) -> str:
    """Feed ``body`` to ``command`` on stdin via a quoted heredoc.

    The quoted delimiter (``<<'DELIMITER'``) is what makes the body literal: no
    expansion, no substitution, and nothing in it has to be escaped. The one
    remaining way out is a body line that *equals* the delimiter, which would
    end the heredoc early and hand the rest to the shell as commands.

    A body is often something we do not control — the ``.htaccess`` of a
    customer webroot, read out and written back with our block on top — so the
    delimiter is not a name that body could be written to contain. ``prefix``
    only labels it for a human reading a command; :func:`fresh_delimiter`
    supplies the unguessable part. A body that holds the delimiter anyway raises
    :class:`HeredocCollision` rather than being written.

    The delimiter has to start a line, so a body is newline-terminated on its
    way in — but only if it isn't already. File content usually ends in a
    newline, and adding a second one would leave every file this tool writes
    with a blank line the caller never asked for.
    """
    delimiter = fresh_delimiter(prefix)
    # `sh` ends the body only on a line that *is* the delimiter, so comparing
    # the stripped line refuses a little more than the shell would end on.
    # Erring towards refusing costs nothing: at these odds neither branch runs.
    if any(line.strip() == delimiter for line in body.splitlines()):
        raise HeredocCollision(
            f"Refusing to run {command!r}: its input contains the heredoc "
            f"delimiter {delimiter!r}, which would end the heredoc early and "
            f"run the rest as commands."
        )
    if body and not body.endswith("\n"):
        body += "\n"
    return f"{command} <<'{delimiter}'\n{body}{delimiter}"


def fresh_delimiter(prefix: str) -> str:
    """A fresh heredoc delimiter: ``prefix`` plus a per-invocation nonce.

    Generated, never derived from the body it will carry — a delimiter chosen
    by looking at the content is a delimiter the content's author can predict.
    """
    return f"{prefix}_{secrets.token_hex(_NONCE_BYTES)}"


def strip_delimiter_nonces(command: str) -> str:
    """``command`` with each heredoc delimiter reduced to its bare prefix.

    Fresh nonces make a command different on every invocation, which is the
    point for a shell and a nuisance for anything that wants to *recognise* a
    command. Nothing in production does; :class:`~nine_manage_anubis.runner.FakeRunner`
    does, to match a test's canned response against a nine-su call. It lives
    here because the shape of a delimiter is this module's business, and one
    place should know it.

    Only the two positions where a delimiter is syntax get rewritten: a
    ``<<'...'`` that opens a heredoc on one of *our* delimiters, and the line
    that closes it. A body line that merely mentions a delimiter, or opens a
    heredoc on some other one, is content and is left as it is — which matters
    because a nine-su body is a script carrying a heredoc of its own, so both
    layers have to be folded and nothing else.
    """
    folded: list[str] = []
    open_delimiters: list[str] = []
    for line in command.split("\n"):
        if open_delimiters and line == open_delimiters[-1]:
            folded.append(_NONCE.sub("", open_delimiters.pop()))
            continue
        match = _OPENER.search(line)
        # A delimiter without a nonce is not one of ours, so it is left alone
        # rather than tracked: a webroot file is free to contain a line that
        # looks like a heredoc, and mistaking it for one would lose track of
        # the delimiter actually in force.
        if match and _NONCE.search(match.group(1)):
            open_delimiters.append(match.group(1))
            bare = _NONCE.sub("", match.group(1))
            line = f"{line[:match.start()]}<<'{bare}'{line[match.end():]}"
        folded.append(line)
    return "\n".join(folded)
