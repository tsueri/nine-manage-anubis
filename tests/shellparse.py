"""A shell as the test oracle — what a command *means*, not how it looks.

Quoting has no single correct rendering: ``'/a b'`` and ``/a\\ b`` are the same
argument. So these helpers answer the only question worth asserting — which
words does a shell hand the program, and are they the values we passed?

:func:`argv` and its relatives use :mod:`shlex`, which splits and unquotes but
never expands, so they are safe for any command. :func:`sh_words` runs a real
``/bin/sh``, which also settles ``$( )``, backticks and globs — the questions
shlex cannot answer.
"""

import re
import shlex
import subprocess


def argv(command_line: str) -> list[str]:
    """The words a POSIX shell would split ``command_line`` into.

    An interpolated value is quoted correctly exactly when it comes back out
    as one element of this list, byte-for-byte.
    """
    return shlex.split(command_line)


def sh_words(command: str) -> list[str]:
    """The argument vector a real ``/bin/sh`` builds from ``command``.

    ``command`` is spliced into ``printf`` so the shell does all its own
    splitting, expansion and substitution first — the oracle for anything
    :func:`argv` cannot judge, such as a live ``$( )``. NUL separates the
    words because a value may legitimately contain a newline.
    """
    proc = subprocess.run(
        ["/bin/sh", "-c", f"printf '%s\\0' {command}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.split("\0")[:-1]


def su_script(cmd: str) -> str:
    """The script body a ``sudo nine-su`` command feeds to the far-side shell."""
    first, _, rest = cmd.partition("\n")
    match = re.search(r"<<'([^']+)'", first)
    assert match, f"not a heredoc command: {first!r}"
    lines = rest.splitlines()
    assert lines and lines[-1] == match.group(1), f"unterminated heredoc: {cmd!r}"
    return "\n".join(lines[:-1])


def su_argv(cmd: str) -> list[str]:
    """The words of the ``sudo nine-su <user>`` line itself."""
    first, _, _ = cmd.partition("\n")
    return argv(first.split("<<")[0])


def script_argv(cmd: str) -> list[str]:
    """The command words of a ``nine-su`` script, as the far-side shell sees them.

    Separators (``||``, ``&&``, ``2>/dev/null``) come back as words too, which
    is harmless: what these tests assert is that an interpolated value is one
    word, byte-for-byte. An inner heredoc body is data rather than command
    words — its own quoted delimiter carries it literally — so it is dropped
    before splitting.
    """
    return argv(_drop_heredoc_bodies(su_script(cmd)))


def _drop_heredoc_bodies(script: str) -> str:
    kept: list[str] = []
    delimiter: str | None = None
    for line in script.splitlines():
        if delimiter is not None:
            if line == delimiter:
                delimiter = None
            continue
        kept.append(line)
        match = re.search(r"<<'([^']+)'\s*$", line)
        if match:
            delimiter = match.group(1)
    return "\n".join(kept)


def sh_words_after(command: str, prefix: str) -> list[str]:
    """The argv a real shell hands the program named by ``prefix``.

    ``prefix`` is the fixed head of the command — the program and any literal
    options — so what remains is exactly the interpolated part, and a real
    shell decides what it means.
    """
    assert command.startswith(prefix), f"{command!r} does not start with {prefix!r}"
    return sh_words(command[len(prefix):])
