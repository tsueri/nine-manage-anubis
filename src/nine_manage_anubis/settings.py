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
from typing import TypeVar

from .validate import (
    ValidationError,
    validate_path,
    validate_system_user,
    validate_version,
)

_T = TypeVar("_T")


def _ignoring(path: Path, problem: str) -> str:
    """The warning for a config file this run could not use."""
    return f"Ignoring config file {path}: {problem}. Continuing with defaults."


@dataclass
class Settings:
    """The values a run uses, and the only place their defaults are written.

    Everything that needs a default — the loader below, the starter file,
    the command entry points in :mod:`~nine_manage_anubis.commands` — reads
    it off this dataclass. A default stated twice is a default that drifts.
    """

    anubis_user: str = "www-anubis"
    anubis_version: str = "1.27.0"
    policy_file: str | None = None


@dataclass
class LoadedSettings:
    """What one attempt at the config file produced.

    ``settings`` is what the run uses either way, so nothing downstream has
    to know a fallback happened. ``warning`` is how it says so when one did:
    a file that could not be read or parsed is not fatal — the defaults are
    good ones — but an operator who wrote a config file believes it is in
    effect, and a run that quietly ignores it lets them keep believing that.
    """

    settings: Settings
    warning: str | None = None


def default_config_path() -> Path:
    return Path.home() / ".config" / "nine-manage-anubis" / "config.json"


def load_settings(path: Path | None = None) -> LoadedSettings:
    """Load settings from config file, falling back to defaults.

    A file that cannot be read or parsed falls back to defaults and returns a
    warning naming it. A file that *does* parse and supplies a malformed value
    raises ValidationError instead: those values are interpolated into sudo
    command strings, and silently swapping an attacker's value for a default
    would hide the tampering.
    """
    if path is None:
        path = default_config_path()
    try:
        text = path.read_text()
    except FileNotFoundError:
        # Having no config file is the ordinary case, not a problem. Asked
        # with `exists()` instead, a file in a directory this user may not
        # look into would answer "no file" and be just as silent as one that
        # really is not there.
        return LoadedSettings(Settings())
    except OSError as e:
        return LoadedSettings(Settings(), _ignoring(path, e.strerror or str(e)))
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return LoadedSettings(Settings(), _ignoring(path, e.args[0]))
    if not isinstance(data, dict):
        raise ValidationError(
            f"Invalid config file {path}: expected a JSON object, got "
            f"{type(data).__name__}."
        )
    defaults = Settings()
    settings = Settings(
        anubis_user=_or_default(data.get("anubis_user"), defaults.anubis_user),
        anubis_version=_or_default(
            data.get("anubis_version"), defaults.anubis_version
        ),
        policy_file=_or_default(data.get("policy_file"), defaults.policy_file),
    )
    validate_system_user(settings.anubis_user, field="anubis_user in config file")
    validate_version(settings.anubis_version, field="anubis_version in config file")
    if settings.policy_file is not None:
        validate_path(settings.policy_file, field="policy_file in config file")
    return LoadedSettings(settings)


def _or_default(value: object, default: _T) -> _T:
    """``value``, unless it is absent — in which case the default.

    ``null`` in the file reads the same as leaving the key out: it is the
    file declining to say, not the file saying ``None``. The starter file
    ships ``policy_file`` as ``null`` for exactly that reason.
    """
    if value is None:
        return default
    return value  # type: ignore[return-value]


def default_config_content(anubis_user: str | None = None) -> str:
    """Generate a starter config file with the defaults written out.

    The values come off :class:`Settings` when the file is written, not when
    this module is imported, so the file always states what the tool would
    have done without it.
    """
    defaults = Settings()
    return json.dumps(
        {
            "_comment": "nine-manage-anubis configuration. All fields optional. Uncomment policy_file after running 'install --init-policy'.",
            "anubis_user": anubis_user or defaults.anubis_user,
            "anubis_version": defaults.anubis_version,
            "_policy_file_comment": "Set this to share one bot policy across all instances. Run 'install --init-policy' first to extract the default policy.",
            "policy_file": defaults.policy_file,
        },
        indent=4,
    ) + "\n"
