"""Tests for settings.py — config file loading."""

import json
from pathlib import Path

from nine_manage_anubis.settings import Settings, load_settings, default_config_content


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
