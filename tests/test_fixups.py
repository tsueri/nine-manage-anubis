"""Tests for fixups.py — origin fixup automation.

Run with: python3 -m pytest tests/test_fixups.py -v
Or:       python3 tests/test_fixups.py
"""

import tempfile
from pathlib import Path

from nine_manage_anubis.fileops import LocalFileOps
from nine_manage_anubis.fixups import (
    UserIniState,
    HtaccessState,
    SHIM_PHP,
    HTACCESS_BLOCK,
    HTACCESS_BLOCK_START,
    detect_state,
    plan,
    apply,
    restore,
    restore_plan,
)


def _webroot(tmp_path: Path) -> str:
    w = tmp_path / "webroot"
    w.mkdir()
    return str(w)


def _ops() -> LocalFileOps:
    return LocalFileOps()


# --- State detection ---------------------------------------------------------


def test_state_empty_webroot(tmp_path):
    w = _webroot(tmp_path)
    s = detect_state(w, _ops())
    assert s.user_ini is UserIniState.ABSENT
    assert s.htaccess is HtaccessState.ABSENT
    assert not s.shim_present
    assert not s.chain_present


def test_state_user_ini_no_prepend(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".user.ini").write_text("memory_limit=256M\n")
    s = detect_state(w, _ops())
    assert s.user_ini is UserIniState.PRESENT_NO_PREPEND


def test_state_user_ini_prepend_other(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".user.ini").write_text(
        "auto_prepend_file = /home/www-example/example.ch/wordfence-waf.php\n"
    )
    s = detect_state(w, _ops())
    assert s.user_ini is UserIniState.PRESENT_PREPEND_OTHER
    assert s.existing_prepend_path.endswith("wordfence-waf.php")


def test_state_user_ini_prepend_shim(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".user.ini").write_text(
        f"auto_prepend_file = {w}/anubis-origin-shim.php\n"
    )
    s = detect_state(w, _ops())
    assert s.user_ini is UserIniState.PRESENT_PREPEND_SHIM


def test_state_user_ini_prepend_chain(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".user.ini").write_text(
        f"auto_prepend_file = {w}/anubis-prepend-chain.php\n"
    )
    (Path(w) / "anubis-prepend-chain.php").write_text(
        "<?php\n"
        "include_once __DIR__ . '/anubis-origin-shim.php';\n"
        "include_once __DIR__ . '/wordfence-waf.php';\n"
    )
    s = detect_state(w, _ops())
    assert s.user_ini is UserIniState.PRESENT_PREPEND_CHAIN
    assert s.chain_chained_path == "wordfence-waf.php"


def test_state_htaccess_with_block(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".htaccess").write_text(HTACCESS_BLOCK + "\n# app rules\nRewriteRule .* index.php\n")
    s = detect_state(w, _ops())
    assert s.htaccess is HtaccessState.PRESENT_WITH_BLOCK


# --- plan() + apply() --------------------------------------------------------


def test_apply_empty_webroot(tmp_path):
    w = _webroot(tmp_path)
    p = apply(w, _ops())
    assert "create .user.ini" in " ".join(p.steps)
    assert "create .htaccess" in " ".join(p.steps)
    assert (Path(w) / "anubis-origin-shim.php").read_text() == SHIM_PHP
    assert (Path(w) / ".user.ini").read_text().strip().endswith("anubis-origin-shim.php")
    assert HTACCESS_BLOCK_START in (Path(w) / ".htaccess").read_text()
    p2 = apply(w, _ops())
    assert not p2.steps
    assert p2.state.is_complete()


def test_apply_no_prepend_adds_line(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".user.ini").write_text("memory_limit=256M\n")
    (Path(w) / ".htaccess").write_text("# app rules\n")
    p = apply(w, _ops())
    text = (Path(w) / ".user.ini").read_text()
    assert "memory_limit=256M" in text
    assert "auto_prepend_file" in text
    assert text.index("memory_limit") < text.index("auto_prepend_file")
    assert list(Path(w).glob(".user.ini.anubis-bak.*"))
    assert list(Path(w).glob(".htaccess.anubis-bak.*"))


def test_apply_wordfence_chain(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".user.ini").write_text(
        "auto_prepend_file = /home/www-example/example.ch/wordfence-waf.php\n"
    )
    (Path(w) / ".htaccess").write_text("# existing rules\n")
    p = apply(w, _ops())
    assert "anubis-prepend-chain.php" in " ".join(p.steps)
    chain_text = (Path(w) / "anubis-prepend-chain.php").read_text()
    assert "anubis-origin-shim.php" in chain_text
    assert "wordfence-waf.php" in chain_text
    assert chain_text.index("anubis-origin-shim.php") < chain_text.index("wordfence-waf.php")
    assert "anubis-prepend-chain.php" in (Path(w) / ".user.ini").read_text()
    assert "wordfence-waf.php" not in (Path(w) / ".user.ini").read_text()


def test_dry_run_does_not_write(tmp_path):
    w = _webroot(tmp_path)
    p = apply(w, _ops(), dry_run=True)
    assert p.steps
    assert not (Path(w) / ".user.ini").exists()
    assert not (Path(w) / "anubis-origin-shim.php").exists()
    assert not (Path(w) / ".htaccess").exists()


def test_apply_preserves_htaccess_content(tmp_path):
    w = _webroot(tmp_path)
    existing = "# my rules\nRewriteRule ^foo$ bar [L]\n"
    (Path(w) / ".htaccess").write_text(existing)
    apply(w, _ops())
    text = (Path(w) / ".htaccess").read_text()
    assert text.startswith(HTACCESS_BLOCK_START)
    assert existing.strip() in text
    assert text.index(HTACCESS_BLOCK_START) < text.index("# my rules")


# --- restore() ---------------------------------------------------------------


def test_restore_after_apply_empty_webroot(tmp_path):
    w = _webroot(tmp_path)
    apply(w, _ops())
    restore(w, _ops())
    assert not (Path(w) / ".user.ini").exists()
    assert not (Path(w) / ".htaccess").exists()
    assert not (Path(w) / "anubis-origin-shim.php").exists()


def test_restore_with_backups(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".user.ini").write_text("memory_limit=256M\n")
    (Path(w) / ".htaccess").write_text("# original rules\n")
    apply(w, _ops())
    restore(w, _ops())
    assert (Path(w) / ".user.ini").read_text() == "memory_limit=256M\n"
    assert (Path(w) / ".htaccess").read_text() == "# original rules\n"
    assert not (Path(w) / "anubis-origin-shim.php").exists()


def test_restore_no_backup_strips_block(tmp_path):
    w = _webroot(tmp_path)
    (Path(w) / ".htaccess").write_text(
        HTACCESS_BLOCK + "\n# app rules\nRewriteRule .* index.php\n"
    )
    restore(w, _ops())
    text = (Path(w) / ".htaccess").read_text()
    assert HTACCESS_BLOCK_START not in text
    assert "# app rules" in text


def test_restore_plan_dry_run(tmp_path):
    w = _webroot(tmp_path)
    apply(w, _ops())
    rp = restore_plan(w, _ops())
    assert rp.steps
    assert (Path(w) / "anubis-origin-shim.php").exists()


# --- Safety ------------------------------------------------------------------


def test_safety_property_holds():
    assert "HTTP_X_FORWARDED_HOST" in SHIM_PHP
    assert "%{HTTP:X-Forwarded-Host}" in HTACCESS_BLOCK


if __name__ == "__main__":
    import inspect

    fns = [v for _, v in inspect.getmembers(sys.modules[__name__], inspect.isfunction)
           if v.__module__ == __name__ and v.__name__.startswith("test_")]
    passed = 0
    for fn in fns:
        with tempfile.TemporaryDirectory() as d:
            try:
                fn(Path(d))
                print(f"  PASS  {fn.__name__}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {fn.__name__}: {e!r}")
                raise
    print(f"\n{passed}/{len(fns)} passed")
