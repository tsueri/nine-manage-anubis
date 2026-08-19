"""Heredoc-based nine-su wrapper.

`nine-su <user> -c 'cmd'` silently produces no stdout on nine hosts.
The working pattern is a heredoc:

    sudo nine-su <user> <<'NINE_SU_EOF_<nonce>'
    <script lines>
    NINE_SU_EOF_<nonce>

This module builds those command strings so callers don't have to
hand-craft heredocs. The Runner executes them.

Two shells parse the result, so quoting happens twice over. The local root
shell sees only ``sudo nine-su <user>`` and a quoted heredoc delimiter — the
body is literal to it. The shell on the far side of ``nine-su`` re-parses that
body, so every value inside a script is quoted for *it*. Callers hand over raw
values; the quoting is applied here.

The two names below are only the readable half of a delimiter:
:func:`~shell.heredoc` appends a fresh nonce to each. A file's content is often
not ours — the ``.htaccess`` of a customer webroot, read out and written back —
and a fixed delimiter is one the content's author can name, which would end the
heredoc early and run the rest of the file as commands.
"""

from __future__ import annotations

import posixpath
import time

from .runner import Runner
from .shell import heredoc, quote, quote_glob_prefix

_SU_DELIMITER_PREFIX = "NINE_SU_EOF"
_FILE_DELIMITER_PREFIX = "FILE_EOF"
_NOT_FOUND = "__NINE_SU_FILE_NOT_FOUND__"


def nine_su(user: str, script: str, runner: Runner) -> str:
    """Run a shell script as another user via nine-su heredoc."""
    return runner(heredoc(f"sudo nine-su {quote(user)}", script, _SU_DELIMITER_PREFIX))


def nine_su_systemd(user: str, script: str, runner: Runner) -> str:
    """Run a shell script as another user with XDG_RUNTIME_DIR set for systemctl --user."""
    full = f"export XDG_RUNTIME_DIR=/run/user/$(id -u)\n{script}"
    return nine_su(user, full, runner)


def nine_su_read_file(user: str, path: str, runner: Runner) -> str | None:
    """Read a file as another user. Returns None if the file doesn't exist."""
    script = f"cat -- {quote(path)} 2>/dev/null || echo {quote(_NOT_FOUND)}"
    result = nine_su(user, script, runner)
    # The sentinel is only ever printed on its own, so compare rather than
    # search: a file that happens to *contain* the sentinel is content, not a
    # missing file, and must not be able to make itself invisible.
    if result.strip() == _NOT_FOUND:
        return None
    return result


def nine_su_write_file(
    user: str,
    path: str,
    content: str,
    runner: Runner,
    mode: str | None = None,
) -> None:
    """Write a file as another user. Creates parent dirs if needed.

    Handles read-only files (e.g. .htaccess at 444) by temporarily
    granting write permission before the redirect. ``mode`` chmods the file
    afterwards, in the same round trip — for a key file, which must never
    exist at the default mode even briefly.

    Every file this tool writes goes through here, so the heredoc and the
    quoting around it have a single home.
    """
    lines = [
        mkdir_parent(path),
        f"chmod u+w -- {quote(path)} 2>/dev/null || true",
        heredoc(f"cat > {quote(path)}", content, _FILE_DELIMITER_PREFIX),
    ]
    if mode is not None:
        lines.append(f"chmod {quote(mode)} -- {quote(path)}")
    nine_su(user, "\n".join(lines), runner)


def nine_su_file_exists(user: str, path: str, runner: Runner) -> bool:
    """Check if a file exists as another user."""
    script = f"test -f {quote(path)} && echo yes || echo no"
    return nine_su(user, script, runner).strip() == "yes"


def nine_su_glob_prefix(user: str, prefix: str, runner: Runner) -> list[str]:
    """List files whose names start with ``prefix``, as another user.

    Takes a literal prefix rather than a pattern: the only live wildcard is the
    ``*`` this function appends, so a path containing glob metacharacters
    matches itself instead of widening the listing.
    """
    script = f"ls -1d -- {quote_glob_prefix(prefix)} 2>/dev/null || true"
    result = nine_su(user, script, runner)
    return [line.strip() for line in result.strip().splitlines() if line.strip()]


def nine_su_backup(user: str, path: str, runner: Runner) -> str | None:
    """Create a timestamped backup of a file as another user."""
    backup = f"{path}.anubis-bak.{int(time.time())}"
    script = (
        f"cp -p -- {quote(path)} {quote(backup)} 2>/dev/null "
        f"&& printf '%s\\n' {quote(backup)} || true"
    )
    result = nine_su(user, script, runner).strip()
    return result if result else None


def nine_su_unlink(user: str, path: str, runner: Runner) -> None:
    """Remove a file as another user."""
    nine_su(user, f"rm -f -- {quote(path)}", runner)


def mkdir_parent(path: str) -> str:
    """A script line creating the parent directory of ``path``.

    The parent is computed here rather than by a far-side ``$(dirname ...)``:
    a substitution has to stay live to be useful, which means mixing quoting
    styles around a value we do not control — and single-quoting it instead,
    to be safe, makes a directory literally named ``$(dirname "...")``. One
    quoted literal has neither failure mode.
    """
    return f"mkdir -p -- {quote(posixpath.dirname(path) or '.')}"
