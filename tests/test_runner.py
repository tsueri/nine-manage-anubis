"""Tests for runner.py — how FakeRunner recognises a command.

Every heredoc delimiter carries a per-invocation nonce, so a nine-su command
is textually different on every run. A canned response is therefore keyed by
the command with those nonces folded away, and these tests pin that: a test
elsewhere in the suite writes ``sudo nine-su www-anubis <<'NINE_SU_EOF'`` and
means "any nine-su call on that user", nonce or no nonce.
"""

from nine_manage_anubis.nine_su import nine_su
from nine_manage_anubis.runner import FakeRunner

_SU = "sudo nine-su www-anubis <<'NINE_SU_EOF'\n"


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
