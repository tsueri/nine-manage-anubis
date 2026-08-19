"""Tests for settings.py — config file loading."""

import json
from pathlib import Path

import pytest

from conftest import hostile
from nine_manage_anubis.settings import Settings, load_settings, default_config_content
from nine_manage_anubis.validate import ValidationError


def test_defaults_when_no_file(tmp_path):
    settings = load_settings(tmp_path / "nonexistent.json")
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
    settings = load_settings(config)
    assert settings.anubis_user == "www-data"
    assert settings.anubis_version == "1.30.0"
    assert settings.policy_file == "/home/www-data/.config/anubis/policy.yaml"


def test_partial_config_uses_defaults(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"anubis_user": "www-custom"}))
    settings = load_settings(config)
    assert settings.anubis_user == "www-custom"
    assert settings.anubis_version == "1.27.0"
    assert settings.policy_file is None


def test_invalid_json_falls_back_to_defaults(tmp_path):
    config = tmp_path / "config.json"
    config.write_text("not valid json {{{")
    settings = load_settings(config)
    assert settings.anubis_user == "www-anubis"
    assert settings.policy_file is None


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
    settings = load_settings(config)
    assert settings.anubis_user == "www-anubis"


def test_default_config_content_is_itself_valid(tmp_path):
    config = tmp_path / "config.json"
    config.write_text(default_config_content("www-anubis"))
    assert load_settings(config).anubis_user == "www-anubis"
