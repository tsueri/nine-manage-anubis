"""Injectable command runner.

All external commands (nine-manage-vhosts, nine-su, systemctl, ss, curl, etc.)
go through a Runner callable so tests can inject a FakeRunner with canned
outputs. Production uses SubprocessRunner.

A Runner takes one command *string* and runs it through a shell, so anything
interpolated into it must already be a single shell word — see
:mod:`~nine_manage_anubis.shell`. Nothing quotes on the way through here: the
wrappers that build the commands do it, and this module cannot tell a value
from the syntax around it.
"""

from __future__ import annotations

import subprocess
from typing import Callable

from .shell import strip_delimiter_nonces

Runner = Callable[[str], str]


class SubprocessRunner:
    """Production runner — shells out via subprocess."""

    def __call__(self, cmd: str) -> str:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Command failed (exit {result.returncode}): {cmd}\n"
                f"stderr: {result.stderr}"
            )
        return result.stdout


class FakeRunner:
    """Test runner — returns canned stdout for given commands.

    A response is keyed by the start of the command, matched against it with
    heredoc delimiter nonces folded back to their bare prefix: a delimiter is
    fresh on every invocation (see :func:`~nine_manage_anubis.shell.fresh_delimiter`),
    so a key could not otherwise name a nine-su command at all. ``calls``
    keeps each command as the shell would have seen it, nonce included.
    """

    def __init__(self, responses: dict[str, str] | None = None):
        self.responses: dict[str, str] = responses or {}
        self.calls: list[str] = []

    def __call__(self, cmd: str) -> str:
        self.calls.append(cmd)
        stable = strip_delimiter_nonces(cmd)
        if stable in self.responses:
            return self.responses[stable]
        for key, val in self.responses.items():
            if stable.startswith(key):
                return val
        return ""
