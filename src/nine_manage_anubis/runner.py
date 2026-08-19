"""Injectable command runner.

All external commands (nine-manage-vhosts, nine-su, systemctl, ss, curl, etc.)
go through a Runner callable so tests can inject a FakeRunner with canned
outputs. Production uses SubprocessRunner.

A Runner takes one command *string* and runs it through a shell, so anything
interpolated into it must already be a single shell word — see
:mod:`~nine_manage_anubis.shell`. Nothing quotes on the way through here: the
wrappers that build the commands do it, and this module cannot tell a value
from the syntax around it.

Two things a Runner guarantees, because a caller cannot be relied on to ask for
either.

**A failure is diagnosable without being quotable.** :class:`CommandFailed`
names the program, the exit code and stderr, and withholds the command. The
command is the one part that carries secrets: a freshly generated signing key
travels to disk as a heredoc body, so a message quoting the command would put
the private key on a terminal, in a CI log, and in whatever an operator pastes
into a bug report. The program name is safe to print because it is the one word
in a command that is always a literal — every command builder in this package
puts a program word first, and values only ever follow it.

**Nothing runs forever.** ``timeout`` defaults to :data:`DEFAULT_TIMEOUT`
rather than to "no limit", so a command runs under one whether or not its
caller thought about it; overrunning raises :class:`CommandTimeout`, which
names the operation and the limit it passed. The shell is started in its own
process group and the group is killed on timeout: killing the shell alone
leaves its children holding the pipe we still have to read, and reading it to
EOF waits out exactly the command we just gave up on.

Known limitation: while a command runs, its text — heredoc body and all — is an
argument of ``/bin/sh -c``, so a signing key being written is visible to any
local user running ``ps`` for as long as the write takes. Closing that needs the
script to reach ``nine-su`` on stdin instead of as part of the command string,
which is a change to how every command is built rather than to how failures are
reported.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from typing import Protocol

from .shell import strip_delimiter_nonces

# Long enough for the slowest ordinary command (a vhost change that reloads
# Apache), short enough that a wedged one is noticed within a coffee sip.
# Operations that are legitimately slower — a release download, a certificate
# issuance — name their own; nothing gets to name none.
DEFAULT_TIMEOUT = 60.0


class Runner(Protocol):
    """Runs one shell command and returns its stdout.

    ``what`` is a short phrase naming the operation for an error message
    ("downloading Anubis v1.27.0"), for the cases where the program name alone
    is ambiguous — two different curl calls read very differently once one of
    them has hung.
    """

    def __call__(
        self,
        cmd: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        what: str | None = None,
    ) -> str: ...


def program_name(cmd: str) -> str:
    """The program ``cmd`` runs, which is the part of it safe to print.

    Values are quoted into a single word each and always follow the program, so
    the first word of the first line is a literal this package wrote — never a
    domain, a path or a key. ``sudo`` is skipped because it is a wrapper, not
    the program whose exit code we are reporting, and the first line is all we
    look at because everything below it is a heredoc body.
    """
    for word in cmd.split("\n", 1)[0].split():
        if word == "sudo":
            continue
        return word
    return "command"


def _seconds(timeout: float) -> str:
    """``60.0`` as ``60`` and ``0.2`` as ``0.2`` — a limit an operator can read."""
    return f"{timeout:g}"


def _during(what: str | None) -> str:
    return f" while {what}" if what else ""


class CommandFailed(RuntimeError):
    """An external command exited non-zero.

    Carries the program, the exit code and stderr — deliberately not the
    command. Subclasses RuntimeError, so the CLI's handler turns it into a
    one-line error and exit 1.
    """

    def __init__(
        self,
        program: str,
        returncode: int,
        stderr: str,
        what: str | None = None,
    ) -> None:
        self.program = program
        self.returncode = returncode
        self.stderr = stderr
        self.what = what
        detail = stderr.strip() or "(no output on stderr)"
        super().__init__(
            f"{program} failed (exit {returncode}){_during(what)}\nstderr: {detail}"
        )


class CommandTimeout(RuntimeError):
    """An external command outlived its timeout and was killed.

    Distinct from :class:`CommandFailed` because the two ask for different
    things: an exit code and stderr describe something that went wrong, a
    timeout describes something that never answered.
    """

    def __init__(self, program: str, timeout: float, what: str | None = None) -> None:
        self.program = program
        self.timeout = timeout
        self.what = what
        super().__init__(
            f"{program} timed out after {_seconds(timeout)}s{_during(what)}"
        )


class SubprocessRunner:
    """Production runner — shells out via subprocess."""

    def __call__(
        self,
        cmd: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        what: str | None = None,
    ) -> str:
        program = program_name(cmd)
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # Nothing this tool runs reads stdin — a nine-su script arrives as
            # part of the command, in a heredoc the shell itself supplies — so
            # closing it means a command that asks for input fails instead of
            # waiting for input that is never coming.
            stdin=subprocess.DEVNULL,
            text=True,
            # Its own process group, so the whole tree can be killed at once.
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _abandon_process_tree(proc, signal.SIGKILL)
            raise CommandTimeout(program, timeout, what) from None
        except KeyboardInterrupt:
            # Its own process group is also its own Ctrl-C: the terminal's
            # interrupt reached us and not it, so pass it on. Otherwise
            # "Aborted." means "still going", which is worse than not stopping.
            _abandon_process_tree(proc, signal.SIGINT)
            raise
        if proc.returncode != 0:
            raise CommandFailed(program, proc.returncode, stderr, what)
        return stdout


def _abandon_process_tree(proc: subprocess.Popen, sig: int) -> None:
    """Signal a command's whole process tree and stop reading from it.

    The signal goes to the group, not the shell: the shell's children are what
    hold the pipes, and killing only the shell leaves them holding them.

    Delivery is best effort — a command running under ``sudo`` is root by the
    time it hangs, and we are not, so the signal can be refused. That is why
    the pipes are closed rather than drained: waiting for EOF on a process we
    could not kill is exactly the hang this exists to prevent, and being unable
    to reap a child costs nothing in a process that is about to exit anyway.
    """
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except OSError:
        # ProcessLookupError if it has already gone, PermissionError if it is
        # root and we are not. Try the shell alone rather than nothing.
        proc.send_signal(sig)
    for pipe in (proc.stdout, proc.stderr):
        if pipe is not None:
            pipe.close()
    try:
        # A signal that landed has landed by now, so this reaps the child in
        # the ordinary case rather than leaving a zombie behind — a batch
        # `enable` catches a failure per domain and keeps going, so this
        # process may be around for a while yet. Bounded, because the whole
        # point is not to wait for a process we could not kill.
        proc.wait(timeout=0.1)
    except subprocess.TimeoutExpired:
        pass


@dataclass(frozen=True)
class Invocation:
    """One recorded call: the command, and the terms it ran under."""

    cmd: str
    timeout: float
    what: str | None


class FakeRunner:
    """Test runner — returns canned stdout for given commands.

    A response is keyed by the start of the command, matched against it with
    heredoc delimiter nonces folded back to their bare prefix: a delimiter is
    fresh on every invocation (see :func:`~nine_manage_anubis.shell.fresh_delimiter`),
    so a key could not otherwise name a nine-su command at all. ``calls``
    keeps each command as the shell would have seen it, nonce included, and
    ``invocations`` keeps the timeout and operation name alongside it.
    """

    def __init__(self, responses: dict[str, str] | None = None):
        self.responses: dict[str, str] = responses or {}
        self.invocations: list[Invocation] = []

    def __call__(
        self,
        cmd: str,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        what: str | None = None,
    ) -> str:
        self.invocations.append(Invocation(cmd, timeout, what))
        stable = strip_delimiter_nonces(cmd)
        if stable in self.responses:
            return self.responses[stable]
        for key, val in self.responses.items():
            if stable.startswith(key):
                return val
        return ""

    @property
    def calls(self) -> list[str]:
        return [i.cmd for i in self.invocations]

    def invocation(self, needle: str) -> Invocation:
        """The one recorded invocation whose command contains ``needle``.

        For asserting the terms a particular command ran under without
        counting call positions, which shift whenever a step is added.
        """
        found = [i for i in self.invocations if needle in i.cmd]
        if len(found) != 1:
            raise AssertionError(
                f"expected exactly one call containing {needle!r}, got {len(found)}"
            )
        return found[0]
