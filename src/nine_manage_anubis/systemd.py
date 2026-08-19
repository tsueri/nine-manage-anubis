"""Systemd user service management for Anubis instances.

All operations go through nine-su heredoc with XDG_RUNTIME_DIR set,
which is the working pattern for non-interactive systemctl --user.

Every value spliced into one of these scripts — instance name, path, version —
is quoted here, at construction. The far-side shell re-parses the script, so an
unquoted value could end the command it sits in; file *contents* need no
quoting because they travel as heredoc bodies.

Reading, writing and removing a file is the nine-su wrapper's job. The functions
here name the *instance's* files — unit template, env file, signing key — and
hand the work to :mod:`~nine_manage_anubis.nine_su`, so each file operation has
one script and one place its quoting has to be right.
"""

from __future__ import annotations

from .runner import Runner, SubprocessRunner
from .nine_su import (
    mkdir_parent,
    nine_su,
    nine_su_file_exists,
    nine_su_systemd,
    nine_su_unlink,
    nine_su_write_file,
)
from .shell import quote
from .validate import validate_version


def _unit(instance: str) -> str:
    """The systemd unit name for an instance, as a single shell word."""
    return quote(f"anubis@{instance}.service")


def daemon_reload(user: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(user, "systemctl --user daemon-reload", runner)


def enable_service(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(
        user,
        f"systemctl --user enable --now {_unit(instance)}",
        runner,
    )


def disable_service(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(
        user,
        f"systemctl --user disable --now {_unit(instance)}",
        runner,
    )


def restart_service(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(
        user,
        f"systemctl --user restart {_unit(instance)}",
        runner,
    )


def is_active(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    # `systemctl is-active` exits 3 for anything that isn't active, but still
    # prints the state on stdout. `|| true` keeps the Runner from treating a
    # perfectly informative answer ("inactive", "failed") as a command failure.
    result = nine_su_systemd(
        user,
        f"systemctl --user is-active {_unit(instance)} || true",
        runner,
    )
    return result.strip()


def write_systemd_template(user: str, content: str, runner: Runner = SubprocessRunner()) -> None:
    from .config import systemd_template_path
    nine_su_write_file(user, systemd_template_path(user), content, runner)


def template_exists(user: str, runner: Runner = SubprocessRunner()) -> bool:
    from .config import systemd_template_path
    return nine_su_file_exists(user, systemd_template_path(user), runner)


def remove_systemd_template(user: str, runner: Runner = SubprocessRunner()) -> None:
    from .config import systemd_template_path
    nine_su_unlink(user, systemd_template_path(user), runner)


def write_env_file(user: str, path: str, content: str, runner: Runner = SubprocessRunner()) -> None:
    nine_su_write_file(user, path, content, runner)


def write_key_file(user: str, path: str, key_content: str, runner: Runner = SubprocessRunner()) -> None:
    # 600 in the same round trip: a signing key must not sit at the default
    # mode between two nine-su calls.
    nine_su_write_file(user, path, key_content, runner, mode="600")


def remove_file(user: str, path: str, runner: Runner = SubprocessRunner()) -> None:
    nine_su_unlink(user, path, runner)


def file_exists(user: str, path: str, runner: Runner = SubprocessRunner()) -> bool:
    return nine_su_file_exists(user, path, runner)


def generate_key(runner: Runner = SubprocessRunner()) -> str:
    """Generate a JWT signing key via openssl."""
    return runner("openssl rand -hex 32").strip()


def binary_exists(user: str, runner: Runner = SubprocessRunner()) -> bool:
    script = f"test -f {quote(f'/home/{user}/bin/anubis')} && echo yes || echo no"
    return nine_su(user, script, runner).strip() == "yes"


def binary_version(user: str, runner: Runner = SubprocessRunner()) -> str:
    script = f"{quote(f'/home/{user}/bin/anubis')} --version 2>&1 || true"
    return nine_su(user, script, runner).strip()


def download_binary(user: str, version: str, runner: Runner = SubprocessRunner()) -> str:
    """Download and install the Anubis binary for the given version."""
    tarball = f"anubis-{version}-linux-amd64.tar.gz"
    url = f"https://github.com/TecharoHQ/anubis/releases/download/v{version}/{tarball}"
    unpacked = f"anubis-{version}-linux-amd64"
    script = "\n".join(
        [
            "cd /tmp",
            f"curl -sLO {quote(url)}",
            f"tar xzf {quote(tarball)}",
            "mkdir -p ~/bin",
            f"cp {quote(f'{unpacked}/bin/anubis')} ~/bin/",
            "chmod +x ~/bin/anubis",
            f"rm -f -- {quote(tarball)}",
            f"rm -rf -- {quote(unpacked)}",
            "~/bin/anubis --version",
        ]
    )
    return nine_su(user, script, runner)


def get_latest_version(runner: Runner = SubprocessRunner()) -> str:
    """Fetch the latest Anubis release version from GitHub API."""
    raw = runner(
        "curl -sL https://api.github.com/repos/TecharoHQ/anubis/releases/latest "
        "| grep -m1 '\"tag_name\"'"
    )
    # Parse "tag_name": "v1.27.0" from the grep output. The response is
    # untrusted network data and the version lands in a download URL and a
    # tar path, so it has to clear the whitelist like any other input.
    import re
    m = re.search(r'"tag_name"\s*:\s*"v?([^"]+)"', raw)
    if m:
        return validate_version(m.group(1), field="latest Anubis version")
    raise RuntimeError(f"Could not determine latest Anubis version from: {raw}")


def extract_policy(user: str, dest_path: str, runner: Runner = SubprocessRunner()) -> str:
    """Extract default bot policy from Anubis binary to dest_path."""
    scratch = f"/tmp/anubis-extract-{user}"
    script = "\n".join(
        [
            mkdir_parent(dest_path),
            "cd /tmp",
            f"~/bin/anubis -extract-resources {quote(scratch)}",
            f"cp {quote(f'{scratch}/data/botPolicies.yaml')} {quote(dest_path)}",
            f"rm -rf -- {quote(scratch)}",
        ]
    )
    return nine_su(user, script, runner)
