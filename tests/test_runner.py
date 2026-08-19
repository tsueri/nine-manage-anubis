"""Tests for runner.py — what a failure says, and what stops a hang.

Three properties live here.

A failure has to be diagnosable without being quotable: the program, the exit
code and stderr are in the message, the command is not. The command is what
carries secrets — a freshly generated signing key travels to disk as a heredoc
body — and an error message ends up on a terminal, in a CI log and in whatever
a user pastes into a bug report.

No command may outlive its timeout, and the timeout has to hold even when the
shell we launched has children of its own: killing the shell alone leaves them
holding the pipe we are reading, which turns "we gave up" back into the hang we
gave up on.

And a canned response has to be recognisable. Every heredoc delimiter carries a
per-invocation nonce, so a nine-su command is textually different on every run;
a response is keyed by the command with those nonces folded away, and a test
elsewhere in the suite writes ``sudo nine-su www-anubis <<'NINE_SU_EOF'`` to
mean "any nine-su call on that user".
"""

import inspect
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from shellrunner import ShellRunner

from nine_manage_anubis.nine_su import nine_su
from nine_manage_anubis.runner import (
    DEFAULT_TIMEOUT,
    CommandFailed,
    CommandTimeout,
    FakeRunner,
    SubprocessRunner,
    program_name,
)
from nine_manage_anubis.shell import heredoc
from nine_manage_anubis.systemd import write_key_file

_SU = "sudo nine-su www-anubis <<'NINE_SU_EOF'\n"

needs_openssl = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="openssl is not installed"
)


# --- What a failure says -------------------------------------------------------


def test_a_failing_command_reports_the_program_the_exit_code_and_stderr():
    with pytest.raises(CommandFailed) as excinfo:
        SubprocessRunner()("cat -- /nonexistent-9f3a2b")

    message = str(excinfo.value)
    assert "cat" in message
    assert "exit 1" in message
    # cat names the missing path on stderr; asserting on that rather than on
    # its wording keeps the test out of the host's locale.
    assert "/nonexistent-9f3a2b" in message


def test_a_failing_command_does_not_report_the_command_that_ran():
    # The marker sits where a signing key sits: in a heredoc body, which no
    # program echoes back. Anything of it in the message came from the command
    # string itself.
    marker = "surely-not-in-any-stderr-8c1d"

    with pytest.raises(CommandFailed) as excinfo:
        SubprocessRunner()(f"false <<'BODY'\n{marker}\nBODY")

    assert marker not in str(excinfo.value)
    assert "false" in str(excinfo.value)


def test_a_failure_with_no_stderr_still_names_the_program_and_the_code():
    with pytest.raises(CommandFailed) as excinfo:
        SubprocessRunner()("sh -c 'exit 7'")

    assert "sh" in str(excinfo.value)
    assert "exit 7" in str(excinfo.value)


def test_a_failure_carries_its_parts_separately_for_a_caller_to_inspect():
    with pytest.raises(CommandFailed) as excinfo:
        SubprocessRunner()("cat -- /nonexistent-9f3a2b")

    assert excinfo.value.program == "cat"
    assert excinfo.value.returncode == 1
    assert "/nonexistent-9f3a2b" in excinfo.value.stderr


def test_a_failure_names_the_operation_it_was_running():
    with pytest.raises(CommandFailed) as excinfo:
        SubprocessRunner()("false", what="probing example.com")

    assert "probing example.com" in str(excinfo.value)


def test_a_failure_and_a_timeout_are_runtime_errors_the_cli_already_handles():
    # main() turns RuntimeError into a one-line error and exit 1; neither of
    # these may reach an operator as a traceback.
    assert issubclass(CommandFailed, RuntimeError)
    assert issubclass(CommandTimeout, RuntimeError)


def test_a_successful_command_returns_its_stdout_and_not_its_stderr():
    assert SubprocessRunner()("printf 'hi\\n'; printf 'noise\\n' >&2") == "hi\n"


# --- The program name is the one word safe to print ---------------------------


def test_the_program_name_is_the_command_word_past_sudo():
    assert program_name("sudo nine-manage-vhosts virtual-host list --json") == (
        "nine-manage-vhosts"
    )
    assert program_name("openssl rand -hex 32") == "openssl"
    assert program_name("ss -tlnp") == "ss"


def test_the_program_name_ignores_everything_after_the_first_line():
    # A nine-su command is a program word and a heredoc opener; the body below
    # it is a script, and often a file we did not write.
    assert program_name(
        "sudo nine-su 'www-anubis' <<'NINE_SU_EOF_dead'\nopenssl rand\nNINE_SU_EOF_dead"
    ) == "nine-su"


def test_a_command_with_no_program_word_still_yields_a_name():
    assert program_name("   ")


# --- Timeouts -----------------------------------------------------------------


def test_a_command_that_outlives_its_timeout_raises_instead_of_blocking():
    start = time.monotonic()

    with pytest.raises(CommandTimeout) as excinfo:
        SubprocessRunner()("sleep 30", timeout=0.2)

    assert time.monotonic() - start < 5
    assert "timed out after 0.2s" in str(excinfo.value)
    assert "sleep" in str(excinfo.value)


def test_a_timeout_names_the_operation_that_hung():
    with pytest.raises(CommandTimeout) as excinfo:
        SubprocessRunner()("sleep 30", timeout=0.2, what="probing example.com")

    assert "probing example.com" in str(excinfo.value)


def test_a_timeout_does_not_wait_for_a_grandchild_holding_the_pipe():
    # Killing only the shell leaves `sleep` with our stdout still open, and
    # reading it to EOF afterwards waits out exactly the command we gave up on.
    start = time.monotonic()

    with pytest.raises(CommandTimeout):
        SubprocessRunner()("sh -c 'sleep 30' & wait", timeout=0.2)

    assert time.monotonic() - start < 5


def test_a_command_killed_by_its_timeout_does_not_go_on_running():
    # Giving up on a command is not the same as stopping it: a probe that only
    # appears after we stopped waiting says the command outlived the run.
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "still-running"

        with pytest.raises(CommandTimeout):
            SubprocessRunner()(f"sleep 0.4; touch {probe}", timeout=0.1)

        time.sleep(0.9)
        assert not probe.exists()


def test_an_interrupted_command_does_not_go_on_running(monkeypatch):
    # The shell runs in its own process group, so the terminal's Ctrl-C reaches
    # this process and not it. Passing the interrupt on is what keeps "Aborted."
    # from meaning "still going".
    def interrupt(self, *args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess.Popen, "communicate", interrupt)

    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "still-running"

        with pytest.raises(KeyboardInterrupt):
            SubprocessRunner()(f"sleep 0.4; touch {probe}")

        time.sleep(0.9)
        assert not probe.exists()


def test_a_command_runs_under_a_timeout_even_when_no_caller_asked_for_one():
    # The default lives in the signature, so there is no way to reach a shell
    # without a limit — not even by forgetting to name one.
    signature = inspect.signature(SubprocessRunner.__call__)
    assert signature.parameters["timeout"].default == DEFAULT_TIMEOUT
    assert 0 < DEFAULT_TIMEOUT < 3600
    r = FakeRunner()

    r("ss -tlnp")

    assert r.invocations[0].timeout == DEFAULT_TIMEOUT


def test_a_caller_supplied_timeout_reaches_the_runner():
    r = FakeRunner()

    r("curl -s http://localhost:7010/", timeout=15, what="probing example.com")

    assert r.invocations[0].timeout == 15
    assert r.invocations[0].what == "probing example.com"


# --- The signing key ----------------------------------------------------------


@needs_openssl
def test_a_failing_command_never_prints_a_generated_signing_key():
    from nine_manage_anubis.systemd import generate_key

    key = generate_key(runner=SubprocessRunner())
    assert len(key) == 64  # 32 bytes, hex — a real key, not a stand-in

    with pytest.raises(CommandFailed) as excinfo:
        SubprocessRunner()(heredoc("cat > /dev/null/key", key, "FILE_EOF"))

    assert key not in str(excinfo.value)


@needs_openssl
def test_a_failing_key_write_never_prints_the_key_it_was_writing():
    # The reachable path, in a real shell: /dev/null is not a directory, so
    # both the mkdir and the redirect fail — for root as well as for us.
    from nine_manage_anubis.systemd import generate_key

    key = generate_key(runner=SubprocessRunner())

    with pytest.raises(CommandFailed) as excinfo:
        write_key_file("www-anubis", "/dev/null/anubis.key", key, runner=ShellRunner())

    assert key not in str(excinfo.value)


# --- Recognising a canned response --------------------------------------------


def test_a_response_keyed_by_the_bare_delimiter_still_matches():
    r = FakeRunner({_SU + "test -f": "yes\n"})
    assert nine_su("www-anubis", "test -f /home/www-anubis/bin/anubis", r) == "yes\n"


def test_the_recorded_call_keeps_its_nonce():
    # calls[] is the command as the shell would have seen it — folding it
    # would hide the very thing the security tests assert on.
    r = FakeRunner()
    nine_su("www-anubis", "echo hi", r)
    assert "<<'NINE_SU_EOF'\n" not in r.calls[0]
    assert r.calls[0].startswith("sudo nine-su www-anubis <<'NINE_SU_EOF_")


def test_a_response_key_that_does_not_match_is_not_used():
    r = FakeRunner({_SU + "test -f": "yes\n"})
    assert nine_su("www-anubis", "cat -- /home/www-anubis/f", r) == ""


def test_an_exact_key_without_a_heredoc_still_matches():
    r = FakeRunner({"openssl rand -hex 32": "deadbeef\n"})
    assert r("openssl rand -hex 32") == "deadbeef\n"
