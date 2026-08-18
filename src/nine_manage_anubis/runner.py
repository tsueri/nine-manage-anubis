"""Injectable command runner.

All external commands (nine-manage-vhosts, nine-su, systemctl, ss, curl, etc.)
go through a Runner callable so tests can inject a FakeRunner with canned
outputs. Production uses SubprocessRunner.
"""

from __future__ import annotations

import subprocess
from typing import Callable

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
    """Test runner — returns canned stdout for given commands."""

    def __init__(self, responses: dict[str, str] | None = None):
        self.responses: dict[str, str] = responses or {}
        self.calls: list[str] = []

    def __call__(self, cmd: str) -> str:
        self.calls.append(cmd)
        if cmd in self.responses:
            return self.responses[cmd]
        for key, val in self.responses.items():
            if cmd.startswith(key):
                return val
        return ""
