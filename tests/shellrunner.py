"""A Runner that really executes a nine-su command, in a real ``/bin/sh``.

:class:`~nine_manage_anubis.runner.FakeRunner` answers a command with canned
text and never finds out whether it *works*. Some properties only a shell can
settle: that a file lands on disk holding the bytes we asked for, and that
nothing else ran on the way. Those are exactly the properties at stake when a
webroot file we did not write travels through a heredoc.

``sudo nine-su <user>`` is replaced by ``/bin/sh``, which is what nine-su
amounts to once the privilege change is out of the picture: a shell reading the
script from stdin. The heredoc, the quoting and the far-side re-parse are all
still real — that is the point — so a body that could break out of its heredoc
breaks out here, and the test sees it.
"""

import re
import subprocess

# `sudo nine-su <user> ` — the user is one shell word, quoted or not.
_SU = re.compile(r"^sudo nine-su (?:[^\s']+|'(?:[^']|'\\'')*') ")


class ShellRunner:
    """Runs commands for real. ``sudo``/``nine-su`` are dropped, nothing else."""

    def __init__(self) -> None:
        self.stderr: list[str] = []

    def __call__(self, cmd: str) -> str:
        assert _SU.match(cmd), f"not a nine-su command: {cmd!r}"
        proc = subprocess.run(
            _SU.sub("/bin/sh ", cmd, count=1),
            shell=True,
            capture_output=True,
            text=True,
        )
        self.stderr.append(proc.stderr)
        if proc.returncode != 0:
            raise RuntimeError(
                f"Command failed (exit {proc.returncode}): {cmd}\n"
                f"stderr: {proc.stderr}"
            )
        return proc.stdout

    def ran_nothing_unexpected(self) -> bool:
        """Did every script stay inside its heredoc?

        A body that terminates its own heredoc leaves the rest of itself to be
        parsed as commands, which a shell reports on stderr as it stumbles over
        the payload — or, worse, runs silently. Tests pair this with a
        side-effect probe for the silent case.
        """
        return all(text == "" for text in self.stderr)
