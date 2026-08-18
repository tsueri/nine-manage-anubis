"""Anubis env file generation.

Generates the minimal env file for an Anubis instance, based on the
tested runbook configuration. The env file lives at
~/.config/anubis/<primary-domain>.env and is read by the systemd
template unit anubis@<primary-domain>.service.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AnubisConfig:
    """Configuration for a single Anubis instance."""

    domain: str
    app_port: int
    metrics_port: int
    anubis_user: str
    key_path: str

    @property
    def origin_domain(self) -> str:
        return f"origin-{self.domain}"

    @property
    def env_path(self) -> str:
        return f"/home/{self.anubis_user}/.config/anubis/{self.domain}.env"


def generate_env_file(config: AnubisConfig) -> str:
    """Generate the env file content for an Anubis instance."""
    return (
        f"# --- Anubis instance for {config.domain} ---\n"
        f"# public vhost  : {config.domain}\n"
        f"# origin vhost  : {config.origin_domain}\n"
        f"BIND=:{config.app_port}\n"
        f"METRICS_BIND=:{config.metrics_port}\n"
        f"\n"
        f"# Backend: Apache on loopback, selected by the Host header we rewrite to.\n"
        f"TARGET=https://127.0.0.1:443\n"
        f"TARGET_HOST={config.origin_domain}\n"
        f"TARGET_SNI={config.origin_domain}\n"
        f"TARGET_INSECURE_SKIP_VERIFY=true\n"
        f"\n"
        f"# First-party cookie semantics (shipped default None/Partitioned breaks Safari).\n"
        f"COOKIE_SAME_SITE=Lax\n"
        f"COOKIE_PARTITIONED=false\n"
        f"\n"
        f"# JWT signing key.\n"
        f"ED25519_PRIVATE_KEY_HEX_FILE={config.key_path}\n"
    )


SYSTEMD_TEMPLATE = """\
[Unit]
Description=Anubis bot protection for %i
Documentation=https://github.com/TecharoHQ/anubis
After=network.target

[Service]
Type=simple
WorkingDirectory=%h
EnvironmentFile=%h/.config/anubis/%i.env
ExecStart=%h/bin/anubis
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
"""


def key_path_for(anubis_user: str, domain: str) -> str:
    return f"/home/{anubis_user}/.config/anubis/{domain}.key"


def env_path_for(anubis_user: str, domain: str) -> str:
    return f"/home/{anubis_user}/.config/anubis/{domain}.env"


def systemd_template_path(anubis_user: str) -> str:
    return f"/home/{anubis_user}/.config/systemd/user/anubis@.service"
