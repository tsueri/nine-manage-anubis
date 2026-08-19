"""Tests for locking.py — the host-wide exclusive lock.

The lock is what keeps two runs from being handed the same port pair, so what
these pin is the exclusion itself: that a second holder cannot get in, that it
can once the first lets go, and that a holder which is killed rather than
finished leaves nothing behind.
"""

import os
import subprocess
import sys
import threading
import time

import pytest

from nine_manage_anubis.locking import ExclusiveLock, LockUnavailable
from nine_manage_anubis.runner import FakeRunner

WHAT = "allocating a port pair"

# Two tests below turn a directory's permissions into the thing under test.
# Root is not kept out by permissions, so they would prove nothing there.
not_root = pytest.mark.skipif(
    os.geteuid() == 0, reason="root is not stopped by directory permissions"
)

# A second process that takes the lock, says so by creating a file, and then
# waits to be killed. Written as a script because the point is a *process*
# dying — a thread or a closed descriptor would not prove the kernel hands the
# lock back when the holder is gone.
_HOLDER = """
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_CREAT, 0o666)
fcntl.flock(fd, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(60)
"""


def _lock(path, **kwargs) -> ExclusiveLock:
    kwargs.setdefault("timeout", 0.0)
    return ExclusiveLock(str(path), what=WHAT, runner=FakeRunner(), **kwargs)


def test_a_second_holder_cannot_get_in_while_the_first_has_it(tmp_path):
    path = tmp_path / "ports.lock"
    with _lock(path):
        with pytest.raises(LockUnavailable):
            with _lock(path):
                pass


def test_the_lock_is_free_again_once_the_block_exits(tmp_path):
    path = tmp_path / "ports.lock"
    with _lock(path):
        pass
    with _lock(path):
        pass


def test_the_lock_is_free_again_once_the_block_raises(tmp_path):
    path = tmp_path / "ports.lock"
    with pytest.raises(ZeroDivisionError):
        with _lock(path):
            1 / 0
    with _lock(path):
        pass


def test_release_lets_go_early_and_is_idempotent(tmp_path):
    """Releasing inside the block is how a caller says the claim is recorded.

    The block goes on — there is work after the claim that no longer needs the
    exclusion — so the exit has to cope with a lock that is already gone."""
    path = tmp_path / "ports.lock"
    with _lock(path) as lock:
        lock.release()
        lock.release()
        with _lock(path):
            pass


def test_locks_on_different_files_do_not_exclude_each_other(tmp_path):
    with _lock(tmp_path / "a.lock"):
        with _lock(tmp_path / "b.lock"):
            pass


def test_waiting_gives_up_with_an_error_naming_the_operation_and_the_file(tmp_path):
    path = tmp_path / "ports.lock"
    with _lock(path):
        with pytest.raises(LockUnavailable) as exc:
            with _lock(path, timeout=0.05):
                pass
    assert WHAT in str(exc.value)
    assert str(path) in str(exc.value)


def test_a_lock_held_by_a_killed_process_does_not_deadlock_the_next_run(tmp_path):
    """A run that is killed rather than finished must not wedge the host.

    Nothing is cleaned up after a SIGKILL, so the lock cannot be a file whose
    existence means "held" — the kernel has to be the one holding it."""
    path = tmp_path / "ports.lock"
    held = tmp_path / "held"
    holder = subprocess.Popen([sys.executable, "-c", _HOLDER, str(path), str(held)])
    try:
        deadline = time.monotonic() + 10
        while not held.exists() and time.monotonic() < deadline:
            assert holder.poll() is None, "the holder exited before taking the lock"
            time.sleep(0.01)
        assert held.exists(), "the holder never took the lock"

        with pytest.raises(LockUnavailable):
            with _lock(path):
                pass

        holder.kill()
        holder.wait()

        with _lock(path, timeout=5.0):
            pass
    finally:
        holder.kill()
        holder.wait()


def test_a_lock_file_that_is_there_is_not_touched_through_sudo(tmp_path):
    """The ordinary case costs nothing: open the file, take the lock, done."""
    path = tmp_path / "ports.lock"
    path.touch()
    runner = FakeRunner()
    with ExclusiveLock(str(path), what=WHAT, runner=runner, timeout=0.0):
        pass
    assert runner.calls == []


@not_root
def test_a_lock_file_the_operator_cannot_create_is_created_through_sudo(tmp_path):
    """`/run/lock` belongs to root, and the operator running this is not root.

    So a lock file that isn't there yet — every first run after a reboot — is
    created by the one privilege this tool has: sudo."""
    root_only = tmp_path / "run-lock"
    root_only.mkdir(mode=0o555)
    path = root_only / "ports.lock"

    created: list[str] = []

    def runner(cmd, *, timeout=60.0, what=None):
        created.append(cmd)
        # What the real sudo command does. The chmod stands in for the
        # privilege: root can write a directory mode 0555 keeps us out of.
        root_only.chmod(0o755)
        path.touch(mode=0o666)
        return ""

    with ExclusiveLock(str(path), what=WHAT, runner=runner, timeout=0.0):
        pass

    assert len(created) == 1
    assert created[0].startswith("sudo ")
    assert str(path) in created[0]
    assert path.exists()


@not_root
def test_a_lock_file_that_cannot_be_opened_at_all_is_an_error_naming_it(tmp_path):
    root_only = tmp_path / "run-lock"
    root_only.mkdir(mode=0o555)
    path = root_only / "ports.lock"
    with pytest.raises(LockUnavailable) as exc:
        with ExclusiveLock(str(path), what=WHAT, runner=FakeRunner(), timeout=0.0):
            pass
    assert str(path) in str(exc.value)


def test_a_symlink_at_the_lock_path_is_refused_and_nothing_privileged_is_run(
    tmp_path,
):
    """A lock directory a local user can write is a place to plant a symlink.

    Refusing it is half the answer; the other half is not then handing the
    same path to a sudo command, which is the one thing here that could turn
    somebody's symlink into a root-owned write."""
    target = tmp_path / "target"
    target.touch()
    path = tmp_path / "ports.lock"
    path.symlink_to(target)
    runner = FakeRunner()
    with pytest.raises(LockUnavailable):
        with ExclusiveLock(str(path), what=WHAT, runner=runner, timeout=0.0):
            pass
    assert runner.calls == []


@not_root
def test_the_privileged_create_will_not_write_through_a_planted_symlink(tmp_path):
    """The case the check above cannot see: a symlink in a directory we may
    not even search, so opening it fails for permissions rather than for being
    a symlink, and the create runs — as root, which *can* follow it."""
    lock_dir = tmp_path / "run-lock"
    lock_dir.mkdir()
    victim = tmp_path / "victim"  # deliberately does not exist
    path = lock_dir / "ports.lock"
    path.symlink_to(victim)
    lock_dir.chmod(0o644)  # no search permission: the open fails EACCES

    def runner(cmd, *, timeout=60.0, what=None):
        assert cmd.startswith("sudo ")
        # Standing in for root: run the script the tool built, with the search
        # permission root would have had.
        lock_dir.chmod(0o755)
        subprocess.run(cmd[len("sudo ") :], shell=True, check=True)
        return ""

    with pytest.raises(LockUnavailable):
        with ExclusiveLock(str(path), what=WHAT, runner=runner, timeout=0.0):
            pass
    assert not victim.exists(), "the create followed the symlink"


def test_a_run_that_waits_gets_the_lock_when_the_holder_lets_go(tmp_path):
    """Waiting is the ordinary outcome of contention, not the failure one."""
    path = tmp_path / "ports.lock"
    holder = _lock(path)
    holder.__enter__()
    threading.Timer(0.1, holder.release).start()

    started = time.monotonic()
    with _lock(path, timeout=5.0):
        waited = time.monotonic() - started
    assert waited >= 0.1
