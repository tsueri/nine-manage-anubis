"""Tests for settings.py — config file loading."""

import json

import pytest

from conftest import hostile
from nine_manage_anubis.settings import (
    Settings,
    load_settings,
    default_config_content,
)
from nine_manage_anubis.validate import ValidationError


def settings_from(path) -> Settings:
    """The values one load produced, for the tests that ignore the warning."""
    return load_settings(path).settings


def test_defaults_when_no_file(tmp_path):
    settings = settings_from(tmp_path / "nonexistent.json")
    assert settings.anubis_user == "www-anubis"
    assert settings.anubis_version == "1.27.0"
    assert settings.policy_file is None


def test_loads_from_json(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "anubis_user": "www-data",
        "anubis_version": "1.30.0",
        "policy_file": "/home/www-data/.config/anubis/policy.yaml",
    }))
    settings = settings_from(config)
    assert settings.anubis_user == "www-data"
    assert settings.anubis_version == "1.30.0"
    assert settings.policy_file == "/home/www-data/.config/anubis/policy.yaml"


def test_partial_config_uses_defaults(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-custom"}))
    settings = settings_from(config)
    assert settings.anubis_user == "www-custom"
    assert settings.anubis_version == "1.27.0"
    assert settings.policy_file is None


def test_invalid_json_falls_back_to_defaults(tmp_path):
    config = tmp_path / "config.json"
    config.write_text("not valid json {{{")
    settings = settings_from(config)
    assert settings.anubis_user == "www-anubis"
    assert settings.policy_file is None


# --- A config file that could not be read is never silent ---------------------
#
# Falling back to defaults is the right behaviour — they are good defaults —
# but an operator who wrote a config file believes it is in effect. The run
# proceeds; it just says which file it ignored and why.


def test_malformed_json_warns_naming_the_file_and_the_problem(tmp_path):
    config = tmp_path / "config.json"
    config.write_text("not valid json {{{")
    loaded = load_settings(config)
    assert loaded.warning is not None
    assert str(config) in loaded.warning
    assert "line 1" in loaded.warning
    assert loaded.settings == Settings()


def test_unreadable_file_warns_naming_the_file_and_the_problem(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-data"}))
    config.chmod(0o000)
    try:
        loaded = load_settings(config)
    finally:
        config.chmod(0o600)
    assert loaded.warning is not None
    assert str(config) in loaded.warning
    assert "denied" in loaded.warning.lower()
    assert loaded.settings == Settings()


def test_a_directory_where_the_config_file_should_be_warns(tmp_path):
    config = tmp_path / "config.json"
    config.mkdir()
    loaded = load_settings(config)
    assert loaded.warning is not None
    assert str(config) in loaded.warning


def test_json_that_is_not_an_object_is_rejected_not_warned(tmp_path):
    """A list parses, so it is a config file saying something we cannot use."""
    config = tmp_path / "config.json"
    config.write_text("[1, 2, 3]")
    with pytest.raises(ValidationError):
        load_settings(config)


def test_a_good_file_warns_about_nothing(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-data"}))
    assert load_settings(config).warning is None


def test_a_missing_file_warns_about_nothing(tmp_path):
    """Having no config file is the ordinary case, not a problem."""
    assert load_settings(tmp_path / "nonexistent.json").warning is None


# --- One place declares a default ---------------------------------------------


def test_null_in_the_file_falls_back_to_the_default(tmp_path):
    """`null` means "say nothing", not "use None" — the starter file ships
    policy_file as null, and the same has to hold for every field."""
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "anubis_user": None,
        "anubis_version": None,
        "policy_file": None,
    }))
    assert settings_from(config) == Settings()


def test_the_loader_does_not_restate_the_defaults(tmp_path, monkeypatch):
    """Change a default on the dataclass and the loader follows it."""
    import dataclasses

    from nine_manage_anubis import settings as settings_mod

    patched = dataclasses.make_dataclass(
        "PatchedSettings",
        [
            ("anubis_user", str, dataclasses.field(default="www-other")),
            ("anubis_version", str, dataclasses.field(default="9.9.9")),
            ("policy_file", "str | None", dataclasses.field(default=None)),
        ],
    )
    monkeypatch.setattr(settings_mod, "Settings", patched)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"policy_file": None}))
    loaded = load_settings(config).settings
    assert loaded.anubis_user == "www-other"
    assert loaded.anubis_version == "9.9.9"


def test_the_starter_file_does_not_restate_the_defaults():
    """The file `config --init` writes carries the dataclass's values."""
    data = json.loads(default_config_content())
    assert data["anubis_user"] == Settings.anubis_user
    assert data["anubis_version"] == Settings.anubis_version


def test_default_config_content():
    content = default_config_content("www-anubis")
    data = json.loads(content)
    assert data["anubis_user"] == "www-anubis"
    assert data["anubis_version"] == "1.27.0"
    assert "policy_file" in data
    assert data["policy_file"] is None


# --- Config file values are untrusted -----------------------------------------
#
# The config file is a plain JSON file the operator (or anything that can
# write to their home) controls, and anubis_user / anubis_version /
# policy_file all land in sudo command strings.


@pytest.mark.parametrize("user", hostile("www-anubis"))
def test_rejects_malformed_anubis_user(tmp_path, user):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": user}))
    with pytest.raises(ValidationError) as exc:
        load_settings(config)
    assert repr(user) in str(exc.value)


@pytest.mark.parametrize("version", hostile("1.27.0"))
def test_rejects_malformed_anubis_version(tmp_path, version):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_version": version}))
    with pytest.raises(ValidationError):
        load_settings(config)


@pytest.mark.parametrize("policy_file", [
    "/tmp/policy.yaml; id",
    "/tmp/policy.yaml`id`",
    "relative/policy.yaml",
    "/tmp/../etc/passwd",
    "",
])
def test_rejects_malformed_policy_file(tmp_path, policy_file):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"policy_file": policy_file}))
    with pytest.raises(ValidationError):
        load_settings(config)


def test_accepts_well_formed_config(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "anubis_user": "www-anubis",
        "anubis_version": "1.27.0",
        "policy_file": "/home/www-anubis/.config/anubis/policy.yaml",
    }))
    settings = settings_from(config)
    assert settings.anubis_user == "www-anubis"


def test_default_config_content_is_itself_valid(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(default_config_content("www-anubis"))
    assert settings_from(config).anubis_user == "www-anubis"


def test_a_config_file_in_an_unreadable_directory_warns(tmp_path):
    """`Path.exists()` answers False when it is not allowed to look — which
    reads exactly like having no config file at all."""
    home = tmp_path / "locked"
    home.mkdir()
    config = home / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-data"}))
    home.chmod(0o000)
    try:
        loaded = load_settings(config)
    finally:
        home.chmod(0o700)
    assert loaded.warning is not None
    assert str(config) in loaded.warning
    assert loaded.settings == Settings()


def test_the_starter_file_follows_a_changed_default(tmp_path, monkeypatch):
    """Not just at import time — the starter file reads the default when asked."""
    import dataclasses

    from nine_manage_anubis import settings as settings_mod

    patched = dataclasses.make_dataclass(
        "PatchedSettings",
        [
            ("anubis_user", str, dataclasses.field(default="www-other")),
            ("anubis_version", str, dataclasses.field(default="9.9.9")),
            ("policy_file", "str | None", dataclasses.field(default=None)),
        ],
    )
    monkeypatch.setattr(settings_mod, "Settings", patched)
    data = json.loads(settings_mod.default_config_content())
    assert data["anubis_user"] == "www-other"
    assert data["anubis_version"] == "9.9.9"
