"""Settings loading from JSON config file.

Config file location: ~/.config/nine-manage-anubis/config.json
All fields optional — missing fields use hardcoded defaults.

Example:
{
    "anubis_user": "www-anubis",
    "anubis_version": "1.27.0",
    "policy_file": "/home/www-anubis/.config/anubis/shared-policy.yaml"
}

When policy_file is set, every instance's env file includes
POLICY_FNAME=<path>, so all instances share one bot policy.
Edit the file once, restart instances, done.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    anubis_user: str = "www-anubis"
    anubis_version: str = "1.27.0"
    policy_file: str | None = None


def default_config_path() -> Path:
    return Path.home() / ".config" / "nine-manage-anubis" / "config.json"


def load_settings(path: Path | None = None) -> Settings:
    """Load settings from config file, falling back to defaults."""
    if path is None:
        path = default_config_path()
    if not path.exists():
        return Settings()
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return Settings()
    return Settings(
        anubis_user=data.get("anubis_user", "www-anubis"),
        anubis_version=data.get("anubis_version", "1.27.0"),
        policy_file=data.get("policy_file"),
    )


def default_config_content(anubis_user: str = "www-anubis") -> str:
    """Generate a starter config file with defaults written out."""
    policy_path = f"/home/{anubis_user}/.config/anubis/shared-policy.yaml"
    return json.dumps(
        {
            "_comment": "nine-manage-anubis configuration. All fields optional.",
            "anubis_user": anubis_user,
            "anubis_version": "1.27.0",
            "policy_file": policy_path,
        },
        indent=4,
    ) + "\n"
