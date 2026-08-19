"""File operations abstraction for webroot I/O.

www-data cannot write to webroots owned by other users (e.g. www-example).
Two implementations:
  - LocalFileOps: direct Path operations (for tests, or when running as the owner)
  - RemoteFileOps: nine-su heredoc commands (for production as www-data)
"""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path
from typing import Protocol

from .runner import Runner
from .validate import ValidationError, validate_path


_BACKUP_SUFFIX_RE = re.compile(r"\.anubis-bak\.[0-9]+")


def _is_our_backup(path: str, candidate: str) -> bool:
    """Is `candidate` a backup this tool made of `path`?

    Backup names come out of a directory listing in a webroot the website
    user owns, and go straight back into a `sudo nine-su` command. We only
    ever create `<path>.anubis-bak.<unix-timestamp>`, so anything else in
    the glob is not ours to read or restore from — including a name crafted
    to break out of the command's quoting.
    """
    if not candidate.startswith(f"{path}."):
        return False
    if not _BACKUP_SUFFIX_RE.fullmatch(candidate[len(path):]):
        return False
    try:
        validate_path(candidate, field="backup file path")
    except ValidationError:
        return False
    return True


class FileOps(Protocol):
    def read(self, path: str) -> str | None: ...
    def write(self, path: str, content: str) -> None: ...
    def exists(self, path: str) -> bool: ...
    def unlink(self, path: str) -> None: ...
    def backup(self, path: str) -> str | None: ...
    def glob_backups(self, path: str) -> list[str]: ...


class LocalFileOps:
    """Direct filesystem operations. For tests or when running as the file owner."""

    def read(self, path: str) -> str | None:
        p = Path(path)
        if not p.exists():
            return None
        return p.read_text()

    def write(self, path: str, content: str) -> None:
        Path(path).write_text(content)

    def exists(self, path: str) -> bool:
        return Path(path).exists()

    def unlink(self, path: str) -> None:
        Path(path).unlink(missing_ok=True)

    def backup(self, path: str) -> str | None:
        p = Path(path)
        if not p.exists():
            return None
        suffix = f".anubis-bak.{int(time.time())}"
        bak = Path(f"{path}{suffix}")
        shutil.copy2(p, bak)
        return str(bak)

    def glob_backups(self, path: str) -> list[str]:
        p = Path(path)
        candidates = sorted(
            p.parent.glob(p.name + ".anubis-bak.*"),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )
        return [str(c) for c in candidates if _is_our_backup(path, str(c))]


class RemoteFileOps:
    """File operations via nine-su heredoc. For production as www-data."""

    def __init__(self, user: str, runner: Runner):
        self._user = user
        self._runner = runner

    def read(self, path: str) -> str | None:
        from .nine_su import nine_su_read_file
        return nine_su_read_file(self._user, path, self._runner)

    def write(self, path: str, content: str) -> None:
        from .nine_su import nine_su_write_file
        nine_su_write_file(self._user, path, content, self._runner)

    def exists(self, path: str) -> bool:
        from .nine_su import nine_su_file_exists
        return nine_su_file_exists(self._user, path, self._runner)

    def unlink(self, path: str) -> None:
        from .nine_su import nine_su_unlink
        nine_su_unlink(self._user, path, self._runner)

    def backup(self, path: str) -> str | None:
        from .nine_su import nine_su_backup
        return nine_su_backup(self._user, path, self._runner)

    def glob_backups(self, path: str) -> list[str]:
        from .nine_su import nine_su_glob
        pattern = f"{path}.anubis-bak.*"
        listing = nine_su_glob(self._user, pattern, self._runner)
        return [p for p in listing if _is_our_backup(path, p)]
