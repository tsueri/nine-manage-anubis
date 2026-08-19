"""One exclusive lock per host, for the decisions two runs must not make at once.

Allocating a port pair is read-decide-claim: read what is in use, pick the
lowest free pair, write it into an env file and a vhost. Two runs started close
together read the same answer, pick the same pair and both write it — the
second instance then fails to bind, and its vhost points at a port serving
someone else's site. Nothing about the read or the write can fix that on its
own; only running the whole sequence one at a time can.

The lock is ``flock(2)`` on a file, and that choice is the whole design. A lock
whose *existence* means "held" — a PID file, a mkdir, a marker — has to be
cleaned up by the holder, and the holder that matters is the one that does not
get to clean up: SIGKILL, a lost SSH session, a machine that went away
mid-``enable``. Whatever it left behind then wedges every later run until an
operator works out that the lock is a lie. An ``flock`` is held by an open file
description, so the kernel hands it back when the holder's last descriptor
closes — which happens on exit however the exit came about. There is no stale
state to leave, and so nothing to reap.

The lock file lives in ``/run/lock``, the standard place for one, and the
directory is emptied on reboot — which for a lock is the correct thing to
happen. It is not a *safe* directory on every distribution: some ship it
world-writable with the sticky bit, so a local user can plant a file at the
lock's well-known path or simply hold the lock and keep every ``enable``
waiting. That is a denial of service, and this cannot prevent it. What it does
prevent is the same user turning it into a privileged write: the lock file is
opened ``O_NOFOLLOW`` and never written to, and the one privileged command here
refuses to create anything at a path that is a symlink. See :meth:`_open`.

The operator running this tool is not root, and on the distributions where
``/run/lock`` belongs to root a lock file that is not there yet cannot be
created without being. So it is created through the one privilege the tool has
— ``sudo`` — and only when opening it fails in the one way creating it would
fix, which is once per boot rather than once per run.

Waiting is bounded. A run that blocks forever behind another looks exactly like
a run that has hung, and an operator cannot tell the two apart from the
outside; :class:`LockUnavailable` says which it is, names the operation and
names the file to look at.
"""

from __future__ import annotations

import errno
import fcntl
import os
import time
from types import TracebackType

from .runner import Runner, SubprocessRunner
from .shell import quote

# Long enough to sit out the handful of commands another run holds the lock
# for — a key write, an env file write — and short enough that a run stuck
# behind something wedged says so rather than joining it.
DEFAULT_TIMEOUT = 120.0

# Cheap enough to be unnoticeable next to the commands on either side of it.
_POLL_INTERVAL = 0.05

# The lock file carries no content: everything it says, it says by being
# locked. So the mode it is created with only has to let the *next* operator
# open it — a lock only one account can take is not a lock on the host.
_LOCK_FILE_MODE = 0o666

# What `flock` reports for a lock somebody else is holding. EACCES is in here
# because Python's own documentation says a contended flock raises EACCES
# "on some systems" — treating it as contention costs a wait we would not
# otherwise have made, and treating it as a hard error would fail runs on
# whichever system that is.
_CONTENDED = frozenset({errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES})


class LockUnavailable(RuntimeError):
    """This run cannot take the lock, so it must not do the work it guards.

    Raised both when another run is holding it and when the lock file cannot
    be opened at all: the two have different causes and the same consequence,
    which is that proceeding would mean proceeding unserialised. Subclasses
    RuntimeError, so the CLI's handler turns it into a one-line error and
    exit 1.
    """


class ExclusiveLock:
    """A host-wide exclusive lock, taken on entry and released on exit.

    ``what`` names the operation being serialised, for the message a run gets
    when it gives up waiting — "waiting for another run to finish allocating a
    port pair" is something an operator can act on, "could not lock" is not.

    :meth:`release` exists because the exclusion usually has to end before the
    block does — see :meth:`~nine_manage_anubis.ports.PortClaim.release`, which
    is the caller this was written for.
    """

    def __init__(
        self,
        path: str,
        *,
        what: str,
        runner: Runner = SubprocessRunner(),
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.path = path
        self.what = what
        self._runner = runner
        self._timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> ExclusiveLock:
        fd = self._open()
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                if e.errno not in _CONTENDED:
                    os.close(fd)
                    raise LockUnavailable(
                        f"Cannot take the lock for {self.what}: {self.path} "
                        f"could not be locked ({e.strerror})."
                    ) from e
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockUnavailable(
                        f"Gave up after {self._timeout:g}s waiting for another "
                        f"run to finish {self.what} (lock file {self.path}). "
                        f"Check whether one is still running before retrying."
                    ) from e
                time.sleep(_POLL_INTERVAL)
                continue
            self._fd = fd
            return self

    def release(self) -> None:
        """Let go of the lock now. Idempotent, so the exit can call it again."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()

    def _open(self) -> int:
        """A descriptor on the lock file, creating it through sudo if need be.

        Read-only, because nothing is ever written: a descriptor is all
        ``flock`` wants, and asking for write access would fail on a lock file
        root created and left at 0644. ``O_NOFOLLOW`` refuses a symlink — a
        lock file is a fixed, well-known path in a directory a local user may
        be able to write, which is exactly the kind somebody plants one at.

        Only ``EACCES`` sends us to :meth:`_create_lock_file`, because it is
        the only answer creating the file would change: the file is not there
        and the directory it belongs in is root's. Every other errno says
        something about the path that a privileged command would not fix and
        should not be pointed at — ``ELOOP`` for that planted symlink,
        ``ENOENT`` for a ``/run/lock`` that does not exist.
        """
        flags = os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            return os.open(self.path, flags, _LOCK_FILE_MODE)
        except OSError as e:
            if e.errno != errno.EACCES:
                raise self._unopenable(e) from e
        self._create_lock_file()
        try:
            return os.open(self.path, flags, _LOCK_FILE_MODE)
        except OSError as e:
            raise self._unopenable(e) from e

    def _unopenable(self, e: OSError) -> LockUnavailable:
        return LockUnavailable(
            f"Cannot take the lock for {self.what}: {self.path} could not be "
            f"opened ({e.strerror})."
        )

    def _create_lock_file(self) -> None:
        """Create the lock file as root, without disturbing anything there.

        A file that exists is left exactly as it is — same inode, so a lock
        another run is holding on it stays held. So is a *symlink*, and that
        is the point of testing for one separately: ``test -e`` follows a
        symlink and is false for a dangling one, so without the ``-L`` this
        line would have root create or truncate whatever a local user pointed
        the lock path at. :meth:`_open` already refuses a symlink it can see;
        this is for the one it cannot, in a directory it may not search.

        ``umask 0`` is what makes a new file lockable by the next operator
        rather than only by this one.
        """
        path = quote(self.path)
        script = f"umask 0; test -L {path} || test -e {path} || : > {path}"
        self._runner(
            f"sudo sh -c {quote(script)}",
            what=f"creating the lock file {self.path}",
        )
