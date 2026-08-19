"""Systemd user service management for Anubis instances.

All operations go through nine-su heredoc with XDG_RUNTIME_DIR set,
which is the working pattern for non-interactive systemctl --user.
"""

from __future__ import annotations

from .runner import Runner, SubprocessRunner
from .nine_su import nine_su, nine_su_systemd
from .validate import validate_version


def daemon_reload(user: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(user, "systemctl --user daemon-reload", runner)


def enable_service(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(
        user,
        f"systemctl --user enable --now anubis@{instance}.service",
        runner,
    )


def disable_service(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(
        user,
        f"systemctl --user disable --now anubis@{instance}.service",
        runner,
    )


def restart_service(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    return nine_su_systemd(
        user,
        f"systemctl --user restart anubis@{instance}.service",
        runner,
    )


def is_active(user: str, instance: str, runner: Runner = SubprocessRunner()) -> str:
    # `systemctl is-active` exits 3 for anything that isn't active, but still
    # prints the state on stdout. `|| true` keeps the Runner from treating a
    # perfectly informative answer ("inactive", "failed") as a command failure.
    result = nine_su_systemd(
        user,
        f"systemctl --user is-active anubis@{instance}.service || true",
        runner,
    )
    return result.strip()


def write_systemd_template(user: str, content: str, runner: Runner = SubprocessRunner()) -> str:
    from .config import systemd_template_path
    path = systemd_template_path(user)
    inner = "FILE_EOF"
    script = (
        f"mkdir -p '$(dirname \"{path}\")'\n"
        f"cat > '{path}' <<'{inner}'\n"
        f"{content}\n"
        f"{inner}"
    )
    return nine_su(user, script, runner)


def template_exists(user: str, runner: Runner = SubprocessRunner()) -> bool:
    from .config import systemd_template_path
    path = systemd_template_path(user)
    script = f"test -f '{path}' && echo yes || echo no"
    return nine_su(user, script, runner).strip() == "yes"


def remove_systemd_template(user: str, runner: Runner = SubprocessRunner()) -> str:
    from .config import systemd_template_path
    path = systemd_template_path(user)
    script = f"rm -f '{path}'"
    return nine_su(user, script, runner)


def write_env_file(user: str, path: str, content: str, runner: Runner = SubprocessRunner()) -> str:
    inner = "FILE_EOF"
    script = (
        f"mkdir -p '$(dirname \"{path}\")'\n"
        f"cat > '{path}' <<'{inner}'\n"
        f"{content}\n"
        f"{inner}"
    )
    return nine_su(user, script, runner)


def write_key_file(user: str, path: str, key_content: str, runner: Runner = SubprocessRunner()) -> str:
    inner = "KEY_EOF"
    script = (
        f"mkdir -p '$(dirname \"{path}\")'\n"
        f"cat > '{path}' <<'{inner}'\n"
        f"{key_content}\n"
        f"{inner}\n"
        f"chmod 600 '{path}'"
    )
    return nine_su(user, script, runner)


def remove_file(user: str, path: str, runner: Runner = SubprocessRunner()) -> str:
    script = f"rm -f '{path}'"
    return nine_su(user, script, runner)


def file_exists(user: str, path: str, runner: Runner = SubprocessRunner()) -> bool:
    script = f"test -f '{path}' && echo yes || echo no"
    return nine_su(user, script, runner).strip() == "yes"


def generate_key(runner: Runner = SubprocessRunner()) -> str:
    """Generate a JWT signing key via openssl."""
    return runner("openssl rand -hex 32").strip()


def binary_exists(user: str, runner: Runner = SubprocessRunner()) -> bool:
    script = f"test -f '/home/{user}/bin/anubis' && echo yes || echo no"
    return nine_su(user, script, runner).strip() == "yes"


def binary_version(user: str, runner: Runner = SubprocessRunner()) -> str:
    script = f"/home/{user}/bin/anubis --version 2>&1 || true"
    return nine_su(user, script, runner).strip()


def download_binary(user: str, version: str, runner: Runner = SubprocessRunner()) -> str:
    """Download and install the Anubis binary for the given version."""
    tarball = f"anubis-{version}-linux-amd64.tar.gz"
    url = f"https://github.com/TecharoHQ/anubis/releases/download/v{version}/{tarball}"
    script = (
        f"cd /tmp\n"
        f"curl -sLO '{url}'\n"
        f"tar xzf '{tarball}'\n"
        f"mkdir -p ~/bin\n"
        f"cp anubis-{version}-linux-amd64/bin/anubis ~/bin/\n"
        f"chmod +x ~/bin/anubis\n"
        f"rm -f '{tarball}'\n"
        f"rm -rf anubis-{version}-linux-amd64\n"
        f"~/bin/anubis --version"
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
    script = (
        f"mkdir -p '$(dirname \"{dest_path}\")'\n"
        f"cd /tmp\n"
        f"~/bin/anubis -extract-resources /tmp/anubis-extract-{user}\n"
        f"cp /tmp/anubis-extract-{user}/data/botPolicies.yaml '{dest_path}'\n"
        f"rm -rf /tmp/anubis-extract-{user}\n"
    )
    return nine_su(user, script, runner)
