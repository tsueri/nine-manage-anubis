"""Heredoc-based nine-su wrapper.

`nine-su <user> -c 'cmd'` silently produces no stdout on nine hosts.
The working pattern is a heredoc:

    sudo nine-su <user> <<'NINE_SU_EOF'
    <script lines>
    NINE_SU_EOF

This module builds those command strings so callers don't have to
hand-craft heredocs. The Runner executes them.
"""

from __future__ import annotations

from .runner import Runner

_EOF_MARKER = "NINE_SU_EOF"


def nine_su(user: str, script: str, runner: Runner) -> str:
    """Run a shell script as another user via nine-su heredoc."""
    cmd = f"sudo nine-su {user} <<'{_EOF_MARKER}'\n{script}\n{_EOF_MARKER}"
    return runner(cmd)


def nine_su_systemd(user: str, script: str, runner: Runner) -> str:
    """Run a shell script as another user with XDG_RUNTIME_DIR set for systemctl --user."""
    full = f"export XDG_RUNTIME_DIR=/run/user/$(id -u)\n{script}"
    return nine_su(user, full, runner)


def nine_su_read_file(user: str, path: str, runner: Runner) -> str | None:
    """Read a file as another user. Returns None if the file doesn't exist."""
    script = f"cat '{path}' 2>/dev/null || echo '__NINE_SU_FILE_NOT_FOUND__'"
    result = nine_su(user, script, runner)
    if "__NINE_SU_FILE_NOT_FOUND__" in result:
        return None
    return result


def nine_su_write_file(user: str, path: str, content: str, runner: Runner) -> None:
    """Write a file as another user. Creates parent dirs if needed."""
    inner_marker = "FILE_EOF"
    script = (
        f"mkdir -p '$(dirname \"{path}\")'\n"
        f"cat > '{path}' <<'{inner_marker}'\n"
        f"{content}\n"
        f"{inner_marker}"
    )
    nine_su(user, script, runner)


def nine_su_file_exists(user: str, path: str, runner: Runner) -> bool:
    """Check if a file exists as another user."""
    script = f"test -f '{path}' && echo yes || echo no"
    return nine_su(user, script, runner).strip() == "yes"


def nine_su_glob(user: str, pattern: str, runner: Runner) -> list[str]:
    """Glob files as another user. Returns list of matching paths."""
    script = f"ls -1 {pattern} 2>/dev/null || true"
    result = nine_su(user, script, runner)
    return [line.strip() for line in result.strip().splitlines() if line.strip()]


def nine_su_backup(user: str, path: str, runner: Runner) -> str | None:
    """Create a timestamped backup of a file as another user."""
    import time
    suffix = f".anubis-bak.{int(time.time())}"
    script = f"cp -p '{path}' '{path}{suffix}' 2>/dev/null && echo '{path}{suffix}' || echo ''"
    result = nine_su(user, script, runner).strip()
    return result if result else None


def nine_su_unlink(user: str, path: str, runner: Runner) -> None:
    """Remove a file as another user."""
    script = f"rm -f '{path}'"
    nine_su(user, script, runner)
