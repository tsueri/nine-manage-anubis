"""Where a written file lands, and what mode it lands with — asked of a real shell.

Two properties of a write that only a filesystem can settle, and that
:class:`~nine_manage_anubis.runner.FakeRunner` cannot see at all:

*Where.* The parent directory of an env or key file does not exist on a host
that has never run this tool. A ``mkdir -p`` whose argument is single-quoted
around a ``$(dirname ...)`` creates a directory literally named after the
substitution and leaves the real parent missing — a command that looks right,
passes a string assertion, and works on any host where an earlier run already
made the directory. Only a clean directory tree shows the difference.

*What mode.* A signing key is the one secret this tool writes, and the env file
beside it names that key's path and the instance's ports. Neither may be
readable by other users on the box — not after the write, and not during it. So
these tests run under a process umask that restricts nothing (:func:`loose_umask`):
a file that took its mode from the ambient umask lands at 0666 here, and the
only way to land at 0600 is for the code to have decided the mode itself.

That the mode is decided *before* the content, rather than chmodded after, is
the half of the claim a finished file cannot show. It is asserted on the script
in :mod:`test_nine_su`; the two together are the property the ticket asks for.
"""

import os

import pytest
from conftest import USER, mode_of
from shellrunner import ShellRunner

from nine_manage_anubis.runner import CommandFailed
from nine_manage_anubis.systemd import write_env_file, write_key_file

KEY = "6f2c1d9a4b8e0f37a5c1e9d2b7043816f9a2c5d80e1b3746a9c2f5d80b13e746\n"
ENV = "BIND=:7010\nMETRICS_BIND=:7011\n"

# The two files an instance owns, each with content of its own kind. Both are
# written the same way and neither is anyone else's business, so every property
# below is asserted of both.
INSTANCE_FILES = [
    pytest.param(write_key_file, KEY, id="key"),
    pytest.param(write_env_file, ENV, id="env"),
]


@pytest.fixture
def loose_umask():
    """Run with a process umask that restricts nothing.

    The umask a write inherits is the host's, not ours, and on a nine host it is
    whatever the operator's profile happens to set. Pinning it to 0 makes the
    assertions below decisive: an undecided mode lands at 0666, so a file found
    at 0600 was put there deliberately.
    """
    previous = os.umask(0o000)
    yield
    os.umask(previous)


# --- Where the file lands -----------------------------------------------------


@pytest.mark.parametrize("write, content", INSTANCE_FILES)
def test_a_write_creates_the_config_directory_and_nothing_else(tmp_path, write, content):
    # The failure this guards against is silent: the write succeeds, the file
    # lands somewhere, and the config directory the systemd unit reads from is
    # still missing — next to a directory named after the command that was
    # supposed to create it.
    target = tmp_path / ".config" / "anubis" / "example.com"

    write(USER, str(target), content, runner=ShellRunner())

    assert target.read_text() == content
    assert sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")) == [
        ".config",
        ".config/anubis",
        ".config/anubis/example.com",
    ]


# --- What mode it lands with ---------------------------------------------------


@pytest.mark.parametrize("write, content", INSTANCE_FILES)
def test_an_instances_own_files_are_readable_only_by_their_owner(
    tmp_path, loose_umask, write, content
):
    # A first install, which is the case that matters: a directory that does not
    # exist yet and a file that has never been written.
    target = tmp_path / ".config" / "anubis" / "example.com"

    write(USER, str(target), content, runner=ShellRunner())

    assert mode_of(target) == 0o600


@pytest.mark.parametrize("write, content", INSTANCE_FILES)
def test_a_leftover_file_is_replaced_rather_than_written_into(
    tmp_path, loose_umask, write, content
):
    # Truncating a file does not change its permissions, so a file left at 0666
    # by an older version of this tool would still be at 0666 with a fresh key
    # in it.
    target = tmp_path / "example.com"
    target.write_text("stale\n")
    target.chmod(0o666)

    write(USER, str(target), content, runner=ShellRunner())

    assert target.read_text() == content
    assert mode_of(target) == 0o600


@pytest.mark.skipif(os.geteuid() == 0, reason="root can unlink in a directory it cannot write")
def test_a_leftover_that_cannot_be_replaced_stops_the_write(tmp_path, loose_umask):
    # A leftover we cannot remove is one that is not ours to replace. Writing
    # the key into it anyway would leave a fresh signing key in a file with
    # someone else's permissions on it — so the write fails instead, and says
    # so.
    parent = tmp_path / "anubis"
    parent.mkdir()
    target = parent / "example.com.key"
    target.write_text("stale\n")
    target.chmod(0o666)
    parent.chmod(0o555)
    try:
        with pytest.raises(CommandFailed) as excinfo:
            write_key_file(USER, str(target), KEY, runner=ShellRunner())

        assert target.read_text() == "stale\n"
        assert KEY.strip() not in str(excinfo.value)
    finally:
        parent.chmod(0o755)


@pytest.mark.parametrize("write, content", INSTANCE_FILES)
def test_a_restricted_write_leaves_the_parent_directory_alone(
    tmp_path, loose_umask, write, content
):
    # The umask that restricts the file is set after the directory is created,
    # so a config directory shared with an existing instance keeps its mode
    # instead of being narrowed by whoever wrote a key into it last.
    parent = tmp_path / "anubis"
    parent.mkdir(mode=0o755)
    target = parent / "example.com"

    write(USER, str(target), content, runner=ShellRunner())

    assert mode_of(parent) == 0o755
