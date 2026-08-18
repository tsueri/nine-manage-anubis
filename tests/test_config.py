"""Tests for config.py — env file generation."""

from nine_manage_anubis.config import (
    AnubisConfig,
    generate_env_file,
    SYSTEMD_TEMPLATE,
    key_path_for,
    env_path_for,
    systemd_template_path,
)
from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.systemd import generate_key

def test_anubis_config_properties():
    c = AnubisConfig(
        domain="example.com",
        app_port=7010,
        metrics_port=7011,
        anubis_user="www-anubis",
        key_path="/home/www-anubis/.config/anubis/example.com.key",
    )
    assert c.origin_domain == "origin-example.com"
    assert c.env_path == "/home/www-anubis/.config/anubis/example.com.env"


def test_generate_env_file():
    c = AnubisConfig(
        domain="example.com",
        app_port=7010,
        metrics_port=7011,
        anubis_user="www-anubis",
        key_path="/home/www-anubis/.config/anubis/example.com.key",
    )
    env = generate_env_file(c)
    assert "BIND=:7010" in env
    assert "METRICS_BIND=:7011" in env
    assert "TARGET_HOST=origin-example.com" in env
    assert "TARGET_SNI=origin-example.com" in env
    assert "TARGET_INSECURE_SKIP_VERIFY=true" in env
    assert "COOKIE_SAME_SITE=Lax" in env
    assert "COOKIE_PARTITIONED=false" in env
    assert "ED25519_PRIVATE_KEY_HEX_FILE=/home/www-anubis/.config/anubis/example.com.key" in env
    assert "example.com" in env


def test_generate_env_file_different_domain():
    c = AnubisConfig(
        domain="example.ch",
        app_port=7014,
        metrics_port=7015,
        anubis_user="www-anubis",
        key_path="/home/www-anubis/.config/anubis/example.ch.key",
    )
    env = generate_env_file(c)
    assert "BIND=:7014" in env
    assert "TARGET_HOST=origin-example.ch" in env


def test_systemd_template():
    assert "Description=Anubis bot protection for %i" in SYSTEMD_TEMPLATE
    assert "EnvironmentFile=%h/.config/anubis/%i.env" in SYSTEMD_TEMPLATE
    assert "ExecStart=%h/bin/anubis" in SYSTEMD_TEMPLATE
    assert "WantedBy=default.target" in SYSTEMD_TEMPLATE
    assert "multi-user.target" not in SYSTEMD_TEMPLATE


def test_path_helpers():
    assert key_path_for("www-anubis", "example.com") == "/home/www-anubis/.config/anubis/example.com.key"
    assert env_path_for("www-anubis", "example.com") == "/home/www-anubis/.config/anubis/example.com.env"
    assert systemd_template_path("www-anubis") == "/home/www-anubis/.config/systemd/user/anubis@.service"


def test_generate_key():
    r = FakeRunner({"openssl rand -hex 32": "abc123def456\n"})
    key = generate_key(r)
    assert key == "abc123def456"
