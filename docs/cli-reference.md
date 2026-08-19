# nine-manage-anubis — CLI Reference

Detailed reference for every command and flag in `nine-manage-anubis`. Intended for server administrators managing Anubis bot protection on nine.ch Managed Servers.

For the manual runbook explaining the architecture and the origin dance, see [runbook.md](runbook.md). For a quick-start overview, see the [README](../README.md).

---

## Table of contents

- [Synopsis](#synopsis)
- [Global flags](#global-flags)
- [Configuration file](#configuration-file)
- [Input validation](#input-validation)
- [Commands](#commands)
  - [install](#install)
  - [uninstall](#uninstall)
  - [enable](#enable)
  - [disable](#disable)
  - [upgrade](#upgrade)
  - [restart](#restart)
  - [status](#status)
  - [self-test](#self-test)
  - [config](#config)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Port allocation](#port-allocation)
- [Multisite detection](#multisite-detection)
- [Rollback behavior](#rollback-behavior)
- [Common workflows](#common-workflows)

---

## Synopsis

```
nine-manage-anubis [--dry-run] [--json] [--anubis-user USER] <command> [command-flags]
```

Global flags go **before** the subcommand. Command-specific flags go **after**.

```sh
nine-manage-anubis --dry-run enable example.com --prepare-only
```

---

## Global flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--dry-run` | boolean | off | Print what would be done without making any changes. Safe to run against production. |
| `--json` | boolean | off | Output results as JSON instead of human-readable text. Warnings and errors are included in the JSON object. |
| `--anubis-user` | string | from config (`www-anubis`) | The system user that runs the Anubis binary and owns its config/key files. Override when running Anubis as a different user (e.g., `www-data`). |

### `--dry-run`

Shows every step the command would take, prefixed with `[DRY RUN]`. No files are written, no services are restarted, no vhosts are changed. Always use this before batch operations.

```sh
nine-manage-anubis --dry-run enable --all --user www-example
nine-manage-anubis --dry-run upgrade
nine-manage-anubis --dry-run disable example.com
```

### `--json`

Outputs a JSON object with `steps`, `warnings`, and `error` keys. Useful for scripts, monitoring, and CI pipelines.

```sh
nine-manage-anubis --json status --health | jq '.[] | {domain, state, health}'
```

Example output (status command):

```json
[
  {
    "domain": "example.com",
    "port": 7010,
    "metrics_port": 7011,
    "user": "www-anubis",
    "state": "active",
    "version": "Anubis version 1.27.0",
    "vhosts": ["example.com", "www.example.com"],
    "vhost_count": 2,
    "health": "HTTP 200"
  }
]
```

For other commands (install, enable, disable, etc.), the JSON shape is:

```json
{
  "steps": ["Step 1", "Step 2"],
  "warnings": ["optional warning"],
  "error": "optional error message (omitted on success)"
}
```

### `--anubis-user`

Overrides the Anubis system user for this invocation. The default comes from the config file (`anubis_user` field, typically `www-anubis`). Use this when you have multiple Anubis users on the same server, or when running Anubis as `www-data`.

```sh
nine-manage-anubis --anubis-user www-data install
nine-manage-anubis --anubis-user www-data enable example.com
```

The Anubis user is the user that runs the binary and owns `~/.config/anubis/` — it is **not** the website user (e.g., `www-example`) that owns the webroot.

---

## Configuration file

Location: `~/.config/nine-manage-anubis/config.json`

All fields are optional. Missing fields use hardcoded defaults. CLI flags override config file values.

```json
{
    "anubis_user": "www-anubis",
    "anubis_version": "1.27.0",
    "policy_file": "/home/www-anubis/.config/anubis/shared-policy.yaml"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `anubis_user` | string | `www-anubis` | System user that runs the Anubis binary. Used as the default for `--anubis-user`. |
| `anubis_version` | string | `1.27.0` | Default version for `install --version`. |
| `policy_file` | string\|null | `null` | Path to a shared bot policy file. When set, every `enable` writes `POLICY_FNAME=<path>` into the instance's env file. All instances share one policy — edit the file once, run `restart`, done. When `null`, instances use Anubis's embedded default policy. |

To create a starter config:

```sh
nine-manage-anubis config --init
```

To inspect current settings:

```sh
nine-manage-anubis config
```

---

## Input validation

Every domain, system user, version and path reaches a `sudo` command, so each
one must first match a whitelist. Anything that doesn't match is rejected with
a message naming the value and the expected form, and the CLI exits `1`
**before any command is built**.

| Value | Accepted form | Examples |
|-------|---------------|----------|
| Domain | Lowercase letters, digits, dots and hyphens, as dot-separated DNS labels; max 253 chars | `example.com`, `forum.example.ch` |
| System user | `[a-z_][a-z0-9_-]*`, max 32 chars | `www-anubis`, `www-example` |
| Anubis version | Three-part version, no leading `v` | `1.27.0` |
| PHP version | Two-part version | `8.2` |
| Anubis port | Integer in 7010–7999 | `7014` |
| Other `PROXYPORT` | Any TCP port 1–65535 — a vhost may proxy to something that isn't Anubis | `3000` |
| Path (`policy_file`, webroots) | Absolute, letters/digits/`._-/` only, no `..` segment | `/home/www-anubis/policy.yaml` |
| File name (chained `auto_prepend_file`) | One path component, no separator, no `..` | `wordfence-waf.php` |

```sh
$ nine-manage-anubis enable 'example.com; id'
Error: Invalid domain 'example.com; id': expected lowercase letters, digits,
dots and hyphens, as dot-separated DNS labels (e.g. example.com).
$ echo $?
1
```

The same whitelist is applied to values the CLI *reads back* rather than
receives — `nine-manage-vhosts` JSON (domains, users, webroots, `PROXYPORT`,
`PHP_VERSION`), env-file scans (instance domains and `BIND` ports), webroot
files (the chained `auto_prepend_file` name in `.user.ini` and
`anubis-prepend-chain.php`), the config file (`anubis_user`, `anubis_version`,
`policy_file`) and the version parsed out of the GitHub releases API. A
malformed value from any of those is treated as tampering and aborts the run.

A well-formed value that simply isn't Anubis's is skipped rather than fatal: a
vhost or env file on a port outside 7010–7999, a `/home/*` directory whose name
can't be a system user, a `.anubis-bak.*` file this tool didn't write.

If the config file itself is rejected, `config` still runs — it prints the
rejection and the repair command — so a bad file can't lock you out of the
tool that fixes it:

```sh
$ nine-manage-anubis config
Config file: /home/you/.config/nine-manage-anubis/config.json (rejected)

  Invalid anubis_user in config file 'www-anubis; id': expected a system user
  name: lowercase letters, digits, underscores and hyphens, starting with a
  letter or underscore (e.g. www-anubis).

Fix the file by hand, or overwrite it with:
  nine-manage-anubis config --init
```

Validation also runs inside the command functions themselves, so the package
is safe when driven as a library rather than through the CLI:

```python
from nine_manage_anubis.commands import cmd_enable
from nine_manage_anubis.validate import ValidationError

try:
    cmd_enable("example.com; id")
except ValidationError as e:
    ...  # nothing was executed
```

---

## Commands

### install

Set up Anubis infrastructure on the server. Creates the system user, downloads the binary, and installs the systemd template. Does **not** protect any domains — use `enable` for that.

#### Synopsis

```
nine-manage-anubis install [--version VERSION] [--init-policy]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--version` | string | from config (`1.27.0`) | Anubis version to download. Must match a release tag from [github.com/TecharoHQ/anubis/releases](https://github.com/TecharoHQ/anubis/releases). |
| `--init-policy` | boolean | off | Extract the default bot policy from the binary to the path configured in `policy_file`. Requires `policy_file` to be set in the config. |

#### What it does

1. **Create the Anubis user** (e.g., `www-anubis`) if it doesn't exist, using `nine-manage-vhosts user create --no-password`. If the user already exists, this step is skipped.
2. **Download the Anubis binary** to `~/bin/anubis` (as the Anubis user) from the GitHub release. If the binary already exists, this step is skipped.
3. **Install the systemd template** `anubis@.service` at `~/.config/systemd/user/anubis@.service` (as the Anubis user), then run `systemctl --user daemon-reload`. If the template already exists, this step is skipped.
4. **Extract the default policy** (only if `--init-policy` is set and `policy_file` is configured): runs `anubis -extract-resources` and copies `botPolicies.yaml` to the configured path.

This command is **idempotent** — running it twice is safe. Each step checks for existence before acting.

#### Examples

```sh
# Basic install with defaults from config
nine-manage-anubis install

# Install a specific version
nine-manage-anubis install --version 1.28.0

# Install + extract default policy for shared customization
nine-manage-anubis install --init-policy

# Dry run — see what would be installed
nine-manage-anubis --dry-run install

# Install as www-data instead of www-anubis
nine-manage-anubis --anubis-user www-data install
```

#### Warnings

- `--init-policy` without `policy_file` in config: warning "`--init-policy ignored: no policy_file in config`". The rest of the install proceeds normally.

---

### uninstall

Remove Anubis infrastructure from the server: the systemd template, the binary, and the system user. **Refuses** if any Anubis instances still exist — you must `disable` all domains first.

#### Synopsis

```
nine-manage-anubis uninstall
```

#### Flags

None.

#### What it does

1. **Discover all instances** by scanning vhost configs, env files, and systemd services. If any are found, the command aborts with an error listing the `disable` commands to run.
2. **Remove the systemd template** `anubis@.service`.
3. **Remove the Anubis binary** at `~/bin/anubis`.
4. **Remove the Anubis user** via `nine-manage-vhosts user remove`.

#### Safety gate

The instance check is the refcounting safety gate at the binary level. It prevents removing the infrastructure while domains are still protected. The error message lists every instance and the exact `disable` command to run:

```
Error: Cannot uninstall: 3 Anubis instance(s) still exist. Disable all domains first:
  nine-manage-anubis disable example.com
  nine-manage-anubis disable other.com
  nine-manage-anubis disable third.com
```

#### Examples

```sh
# Uninstall (will refuse if instances exist)
nine-manage-anubis uninstall

# Dry run
nine-manage-anubis --dry-run uninstall
```

---

### enable

Put a vhost behind Anubis. This is the main operation — it creates or reuses an Anubis instance, installs origin fixups in the webroot, and switches the public vhost to the proxy template.

#### Synopsis

```
nine-manage-anubis enable <domain> [domain ...] [OPTIONS]
nine-manage-anubis enable --all --user <user> [OPTIONS]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `domains` | positional (0+) | — | One or more domain names to enable. Required unless `--all` is used. |
| `--all` | boolean | off | Enable all vhosts for the given `--user` that are not yet behind Anubis. Requires `--user`. |
| `--user` | string | — | Website user to filter `--all` by (e.g., `www-example`). Only vhosts owned by this user are selected. |
| `--prepare-only` | boolean | off | Do everything except the cutover: generate key, write env file, install fixups, create origin vhost, start the Anubis service. The public vhost keeps serving directly — no traffic impact. |
| `--cutover-only` | boolean | off | Only do the cutover: switch the public vhost to the proxy template. Assumes `--prepare-only` was already run. |

#### What it does (full flow)

For each domain, in order:

1. **Validate** the vhost exists and is not already behind Anubis (template is not `proxy_letsencrypt_https_redirect`).
2. **Allocate a port pair** (7010–7999 range). If the domain's webroot already has an Anubis instance (another vhost on the same webroot is behind Anubis), **reuse** that port — no new instance is created. Otherwise, find the next free pair.
3. **Generate a JWT signing key** via `openssl rand -hex 32`.
4. **Write the env file** at `~/.config/anubis/<domain>.env` with `BIND`, `METRICS_BIND`, `TARGET`, `TARGET_HOST`, cookie settings, key path, and optionally `POLICY_FNAME`.
5. **Install the systemd template** `anubis@.service` if not already installed, then `daemon-reload`.
6. **Install origin fixups** in the webroot:
   - `anubis-origin-shim.php` — restores `HTTP_HOST` from `X-Forwarded-Host`
   - `.user.ini` — sets `auto_prepend_file` to the shim (or creates a chain wrapper if an `auto_prepend_file` already exists, e.g., Wordfence WAF)
   - `.htaccess` — prepends a trailing-slash fixup block (conditional on `X-Forwarded-Host`)
   - Existing files are backed up before modification (`.anubis-bak.<timestamp>`)
7. **Create the origin vhost** `origin-<domain>` using `default_snakeoil_https`, sharing the public vhost's webroot and PHP version.
8. **Start the Anubis service** `anubis@<domain>.service` (enable + start).
9. **Create a Let's Encrypt certificate** for the domain if one doesn't exist (required by the proxy template).
10. **Cut over** the public vhost to `proxy_letsencrypt_https_redirect` with `PROXYPORT=<port>`.

If any step fails after changes have been made, the CLI **automatically rolls back** all changes in reverse order. See [Rollback behavior](#rollback-behavior).

#### Prepare/cutover split

PHP-FPM caches `.user.ini` for 300 seconds (`user_ini.cache_ttl`). If you prepare and cutover in one step, the origin shim won't take effect for ~5 minutes — during which the site may break (PHP sees `HTTP_HOST=origin-<domain>` instead of the public domain).

The `--prepare-only` / `--cutover-only` flags split the flow so you can wait for the cache to expire between prepare and cutover:

- `--prepare-only`: steps 1–8 (no traffic impact)
- Wait 5 minutes for PHP-FPM to pick up the `.user.ini` shim. Verify the shim is loaded:
  ```sh
  curl -sA Googlebot https://<domain>/ | grep -ioE '<title>[^<]*</title>'
  ```
  Should show the site title, not a redirect to `wp-signup.php?new=origin-*`.
- `--cutover-only`: steps 9–10 (brief Apache reload)

#### Multisite reuse

When `enable` detects that a domain's webroot already has an Anubis instance, it takes the **reuse path**:

- No new key, env file, origin vhost, or service instance is created.
- The domain's public vhost is simply switched to the proxy template with the existing port.
- A warning is issued: "`<domain> shares webroot with <primary> — fixups should already be installed`"

This handles WordPress multisite and other multi-domain setups where several domains share one webroot. See [Multisite detection](#multisite-detection).

#### Examples

```sh
# Enable a single domain (full flow)
nine-manage-anubis enable example.com

# Enable multiple domains at once (each gets its own instance unless they share a webroot)
nine-manage-anubis enable site1.ch site2.ch site3.ch

# Enable all vhosts for a website user that aren't behind Anubis yet
nine-manage-anubis enable --all --user www-example

# Prepare only — no cutover, no traffic impact
nine-manage-anubis enable --all --user www-example --prepare-only --no-notify-services

# Cutover later (after PHP-FPM .user.ini cache expires, ~5 min)
nine-manage-anubis enable --all --user www-example --cutover-only --no-notify-services --skip "vorlage*"

# Dry run — see every step without changes
nine-manage-anubis --dry-run enable example.com

# Dry run for batch
nine-manage-anubis --dry-run enable --all --user www-example --prepare-only --no-notify-services
```

#### Errors

- `Vhost <domain> not found` — the domain doesn't exist in `nine-manage-vhosts virtual-host list`.
- `<domain> is already behind Anubis` — the vhost is already using the proxy template.
- `Enable failed: <exception>. Rolled back N step(s).` — a step failed and rollback was executed. Check the steps output for what was undone.
- `No domains to enable.` (exit code 1) — `--all` found no matching vhosts, or no domains were given.

---

### disable

Remove Anubis protection from a vhost. Switches the public vhost back to `default_letsencrypt_https`. If this was the last vhost on the instance's port, tears down the instance entirely. If other vhosts still share the instance, the instance stays running.

#### Synopsis

```
nine-manage-anubis disable <domain> [domain ...]
nine-manage-anubis disable --all --user <user>
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `domains` | positional (0+) | — | One or more domain names to disable. Required unless `--all` is used. |
| `--all` | boolean | off | Disable all Anubis-protected vhosts for the given `--user`. Requires `--user`. |
| `--user` | string | — | Website user to filter `--all` by. |

#### What it does

For each domain, in order:

1. **Validate** the vhost exists and is behind Anubis (template is `proxy_letsencrypt_https_redirect`).
2. **Determine if this is the last vhost** on the instance's port by checking all vhosts with the same `PROXYPORT`.
3. **Switch the public vhost** back to `default_letsencrypt_https`.
4. **If this is the last vhost** on the port, tear down the instance:
   - Stop + disable `anubis@<domain>.service`
   - Remove the origin vhost `origin-<domain>`
   - Restore fixup files in the webroot (restore `.user.ini` and `.htaccess` from backups, or remove them if no backup exists; remove `anubis-origin-shim.php` and `anubis-prepend-chain.php`)
   - Remove the env file and JWT key
5. **If other vhosts still share the port**, the instance stays running. The output names the remaining vhosts: "`Instance still serving: other.com, third.com — left running`"

#### Examples

```sh
# Disable a single domain
nine-manage-anubis disable example.com

# Disable multiple domains
nine-manage-anubis disable site1.ch site2.ch

# Disable all Anubis-protected vhosts for a user
nine-manage-anubis disable --all --user www-customer

# Dry run — see whether instances will be torn down or left running
nine-manage-anubis --dry-run disable example.com
```

#### Errors

- `Vhost <domain> not found` — the domain doesn't exist.
- `<domain> is not behind Anubis (template is <template>)` — the vhost isn't using the proxy template.
- `Cannot determine PROXYPORT for <domain>` — the vhost is on the proxy template but has no `PROXYPORT` variable (malformed config).
- `No domains to disable.` (exit code 1) — `--all` found no Anubis-protected vhosts for the user, or no domains were given.

---

### upgrade

Download a new Anubis binary and restart all instances. By default, restarts one instance at a time with a health check after each — stops on the first failure.

#### Synopsis

```
nine-manage-anubis upgrade [--version VERSION] [--no-rolling]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--version` | string | latest from GitHub API | Target Anubis version to download. Must match a release tag (without the `v` prefix, e.g., `1.28.0`). |
| `--no-rolling` | boolean | off | Restart all instances at once instead of one-by-one. No health checks between restarts. |

#### What it does

1. **Resolve the target version** — use `--version` if given, otherwise query the GitHub API for the latest release.
2. **Report current version** — reads the installed binary's `--version` output.
3. **Download the new binary** to `~/bin/anubis` (replaces the existing one).
4. **daemon-reload** to pick up any template changes.
5. **Discover all instances**.
6. **Restart instances**:
   - **Rolling (default)**: restart one instance, then check `systemctl --user is-active`. If active, HTTP-probe `localhost:<port>` and expect a 2xx/3xx response. If either check fails, stop the upgrade and report the error — remaining instances keep running on the old binary until you re-run `upgrade`.
   - **`--no-rolling`**: restart all instances without health checks between them.

#### Rolling restart health check

After each restart, the CLI:

1. Checks `systemctl --user is-active anubis@<domain>.service` is `active`.
2. Sends an HTTP probe: `curl -H 'X-Real-Ip: 127.0.0.1' -H 'Host: <domain>' http://localhost:<port>/`
3. Expects an HTTP 2xx or 3xx status code.

If the service is not active or the HTTP probe fails, the upgrade stops immediately. Instances already restarted are on the new binary; unrestarted ones are still on the old binary (the old binary is gone from disk, but the running process keeps it in memory).

If `curl` itself fails (e.g., curl not installed), the health check falls back to "service is active" and reports "`Health check: active (service, HTTP probe skipped)`".

#### Examples

```sh
# Upgrade to latest version
nine-manage-anubis upgrade

# Upgrade to a specific version
nine-manage-anubis upgrade --version 1.28.0

# Restart all at once (faster, but no health gate)
nine-manage-anubis upgrade --no-rolling

# Dry run
nine-manage-anubis --dry-run upgrade
```

#### Errors

- `Health check failed for <domain> (service not active)` — the service didn't come back up after restart. Remaining instances are not restarted.
- `Health check failed for <domain> (HTTP <code>)` — the service is active but the HTTP probe returned an unexpected status code.
- `Could not determine latest Anubis version from: <raw>` — the GitHub API query failed (network issue, rate limit).

---

### restart

Restart all Anubis instances **without** downloading a new binary. Use this after changing the shared policy file, editing an env file, or any other config-only update.

#### Synopsis

```
nine-manage-anubis restart [--no-rolling]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--no-rolling` | boolean | off | Restart all instances at once instead of one-by-one. No health checks between restarts. |

#### What it does

1. **Discover all instances**.
2. If no instances exist, report "`No instances to restart`" and exit.
3. **Restart instances**:
   - **Rolling (default)**: restart one instance, then check `systemctl --user is-active`. If active, HTTP-probe `localhost:<port>`. If either check fails, stop and report the error.
   - **`--no-rolling`**: restart all instances without health checks.

The health check behavior is identical to `upgrade` — see [upgrade health check](#rolling-restart-health-check).

#### When to use

- After editing the shared policy file (`~/.config/anubis/shared-policy.yaml`)
- After manually editing an instance's env file
- After any config change that requires Anubis to re-read its environment

For binary updates, use `upgrade` instead — it downloads the new binary before restarting.

#### Examples

```sh
# Rolling restart (default) — one at a time with health check
nine-manage-anubis restart

# Restart all at once
nine-manage-anubis restart --no-rolling

# Dry run
nine-manage-anubis --dry-run restart
```

#### Errors

- `Health check failed for <domain> (service not active)` — the service didn't come back up after restart.
- `Health check failed for <domain> (HTTP <code>)` — the service is active but the HTTP probe returned an unexpected status code.

---

### status

List all Anubis instances on the host. Discovers instances by combining three sources: vhost config (which ports are assigned), env files (which ports are claimed), and systemd (which services are running).

#### Synopsis

```
nine-manage-anubis status [--domain DOMAIN] [--health]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--domain` | string | — | Filter by domain. Matches the instance's primary domain or any vhost proxying to the instance's port. |
| `--health` | boolean | off | Active health check: curl each running instance and report its HTTP status. Inactive instances report `inactive`. |

#### What it shows

The table output has these columns:

| Column | Description |
|--------|-------------|
| `DOMAIN` | The instance's primary domain (from the env file name — the first domain configured for this webroot) |
| `PORT` | The app port (`BIND`) |
| `METRICS` | The metrics port (`METRICS_BIND`) |
| `USER` | The Anubis system user running the instance |
| `STATE` | systemd service state: `active`, `inactive`, `failed`, `not-found` |
| `VERSION` | The Anubis binary version string |
| `VHOSTS` | All domains proxying to this instance's port (comma-separated) |
| `HEALTH` | (only with `--health`) HTTP status code from the health probe, or `inactive` |

Example output:

```
DOMAIN              PORT   METRICS   USER         STATE    VERSION                   VHOSTS
------------------  -----  --------  -----------  -------  ------------------------  --------------------------------
example.com         7010   7011      www-anubis   active   Anubis version 1.27.0     example.com, www.example.com
other.com           7012   7013      www-anubis   active   Anubis version 1.27.0     other.com
```

> **Note:** The `DOMAIN` column shows the instance name — the first domain that was configured for the webroot. This may not be the most important domain. The `VHOSTS` column lists **all** domains protected by the instance.

#### Examples

```sh
# List all instances
nine-manage-anubis status

# Filter by domain
nine-manage-anubis status --domain example.com

# With health check
nine-manage-anubis status --health

# JSON output for scripts/monitoring
nine-manage-anubis --json status --health

# Combine with jq for monitoring
nine-manage-anubis --json status --health | jq '.[] | select(.state != "active") | .domain'
```

---

### self-test

Verify Anubis infrastructure health. Checks the user exists, the binary runs, the systemd template is installed, and every instance is active and HTTP-responding.

#### Synopsis

```
nine-manage-anubis self-test
```

#### Flags

None.

#### What it checks

1. **User exists** — the Anubis user (e.g., `www-anubis`) exists in `nine-manage-vhosts user list`.
2. **Binary runs** — `~/bin/anubis --version` succeeds and returns a version string.
3. **Systemd template installed** — `~/.config/systemd/user/anubis@.service` exists.
4. **Each instance is active** — `systemctl --user is-active anubis@<domain>.service` returns `active`.
5. **Each instance HTTP-responds** — an HTTP probe to `localhost:<port>` returns any HTTP status code > 0. Any response (200, 403, 503, etc.) counts as a pass — the instance is running and responding.

If any check fails, the command reports a warning for that check and sets the error to "`N check(s) failed`". The exit code is 0 regardless (the CLI always returns 0 for self-test), so check stderr or the JSON `error` field for failures.

#### Examples

```sh
# Run self-test
nine-manage-anubis self-test

# Dry run
nine-manage-anubis --dry-run self-test

# JSON output (for monitoring)
nine-manage-anubis --json self-test | jq '.error // "all checks passed"'
```

Example output (all passing):

```
Self-test:

  1. User www-anubis exists
  2. Binary: Anubis version 1.27.0
  3. Systemd template installed
  4. anubis@example.com.service: active
  5.   HTTP probe: 200
```

Example output (with failures):

```
Self-test:

  1. User www-anubis exists
  2. Binary: Anubis version 1.27.0
  3. Systemd template installed
  4. anubis@example.com.service: active
  5.   HTTP probe: 200

  WARNING: anubis@other.com.service is not active (state: failed)
Error: 1 check(s) failed
```

---

### config

Show current settings and config file location, or create a starter config file.

#### Synopsis

```
nine-manage-anubis config [--init]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--init` | boolean | off | Create a default config file at `~/.config/nine-manage-anubis/config.json` with all fields written out. If the file already exists, it is overwritten. |

#### What it does

Without `--init`, prints the config file path, whether it exists, and the current values of `anubis_user`, `anubis_version`, and `policy_file`:

```
Config file: /home/www-data/.config/nine-manage-anubis/config.json (exists)

  anubis_user:    www-anubis
  anubis_version: 1.27.0
  policy_file:    /home/www-anubis/.config/anubis/shared-policy.yaml
```

With `--init`, creates the config file with default values:

```
Created config file: /home/www-data/.config/nine-manage-anubis/config.json
```

The generated file:

```json
{
    "_comment": "nine-manage-anubis configuration. All fields optional. Uncomment policy_file after running 'install --init-policy'.",
    "anubis_user": "www-anubis",
    "anubis_version": "1.27.0",
    "_policy_file_comment": "Set this to share one bot policy across all instances. Run 'install --init-policy' first to extract the default policy.",
    "policy_file": null
}
```

#### Examples

```sh
# Show current settings
nine-manage-anubis config

# Create a starter config file
nine-manage-anubis config --init
```

---

## Output formats

### Human-readable (default)

Each command prints a numbered list of steps, prefixed with a title:

```
Enable example.com:

  1. Generated JWT key
  2. Prepared env file (/home/www-anubis/.config/anubis/example.com.env)
  3. Systemd template already installed
  4. Fixup: write anubis-origin-shim.php
  5. Fixup: create .user.ini pointing at anubis-origin-shim.php
  6. Fixup: create .htaccess with the Anubis fixup block
  7. Create origin vhost origin-example.com
  8. Start anubis@example.com.service
  9. Cut over example.com to proxy template (PROXYPORT=7010)
```

Warnings are printed to stderr:

```
  WARNING: example.com shares webroot with other.com — fixups should already be installed
```

Errors are printed to stderr:

```
Error: Enable failed: cutover failed. Rolled back 5 step(s).
```

### JSON (`--json`)

```json
{
  "steps": [
    "Generated JWT key",
    "Prepared env file (/home/www-anubis/.config/anubis/example.com.env)",
    "Cut over example.com to proxy template (PROXYPORT=7010)"
  ],
  "warnings": [
    "example.com shares webroot with other.com — fixups should already be installed"
  ],
  "error": "Enable failed: cutover failed. Rolled back 5 step(s)."
}
```

The `warnings` and `error` keys are omitted when empty/absent (warnings is only present if there are warnings; error is only present if there is an error).

### Dry run (`--dry-run`)

Steps are prefixed with `[DRY RUN]` and the title:

```
[DRY RUN] Enable example.com:

  1. Would create user www-anubis (if not exists)
  2. Would download Anubis binary v1.27.0
  3. Would install systemd template anubis@.service (if not exists)
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, or self-test completed (even with warnings) |
| 1 | Input rejected by [validation](#input-validation), a command failed, `enable`/`disable` found no domains to process, or at least one domain in a batch failed |
| 2 | Argument parsing failed (argparse) |
| 130 | Interrupted (Ctrl-C) |

Most commands return 0 even on a reported error — the error is in stderr and the JSON `error` field. The exceptions: `enable` and `disable` in batch mode return 1 if any domain fails, and any rejected input or unhandled command failure returns 1.

---

## Port allocation

Anubis instances use the **7010–7999** port range. Each instance gets a pair:

- **App port** (`BIND`): the port Anubis listens on for HTTP traffic
- **Metrics port** (`METRICS_BIND`): the port Anubis exposes Prometheus metrics on

Pairs are allocated with a stride of 2: 7010/7011, 7012/7013, 7014/7015, etc.

The CLI finds the next free pair by checking three sources:

1. **Listening ports** — `ss -tlnp` output for ports in the 7010–7999 range
2. **Claimed ports** — env files on disk (`BIND=:<port>` lines)
3. **Assigned ports** — vhost configs with `PROXYPORT` template variables

A port is considered free only if it's not in any of these three sources. This prevents collisions between running instances, configured-but-stopped instances, and vhost assignments.

---

## Multisite detection

When `enable` is called for a domain, it checks whether another vhost sharing the same **webroot** is already behind Anubis. If so, the new domain **reuses** the existing instance — no new port, key, env file, origin vhost, or service instance is created.

This handles:

- **WordPress multisite** — multiple domains serving different sites from the same webroot, where WordPress reads `HTTP_HOST` to decide which site to serve
- **Alias domains** — `example.com` and `www.example.com` as separate vhosts pointing at the same webroot

The detection works by scanning `nine-manage-vhosts virtual-host list --json` for vhosts with the same `webroot` value that are already using the `proxy_letsencrypt_https_redirect` template. The first match's `PROXYPORT` is reused.

The origin fixup files (`.user.ini`, `anubis-origin-shim.php`, `.htaccess` block) are installed once in the shared webroot and apply to all vhosts — but they're **conditional on `X-Forwarded-Host`**, which is only set when proxying through Anubis. Vhosts serving directly (not behind Anubis) are unaffected.

---

## Rollback behavior

If `enable` fails after making changes, the CLI executes an **undo stack** in reverse order. Each step that made a change registered an undo action when it succeeded:

| Step | Undo action |
|------|-------------|
| Write JWT key | Remove key file |
| Write env file | Remove env file |
| Install origin fixups | Restore fixup files from backups |
| Create origin vhost | Remove origin vhost |
| Start service | Disable + stop service |
| Cut over vhost | Switch vhost back to `default_letsencrypt_https` |

Rollback is **best-effort**: if an undo action itself fails, a warning is added ("`A rollback step failed — manual cleanup may be needed`") and the next undo action is attempted.

The error message reports how many steps were rolled back:

```
Error: Enable failed: cutover failed. Rolled back 5 step(s).
```

For the **reuse path** (multisite), the only step that can fail is the cutover itself — rollback simply switches the vhost back to the default template.

---

## Common workflows

### First-time setup on a new server

```sh
# 1. Install Anubis infrastructure
nine-manage-anubis install

# 2. (Optional) Set up shared policy
nine-manage-anubis install --init-policy
nine-manage-anubis config --init
# Edit ~/.config/nine-manage-anubis/config.json to set policy_file

# 3. Enable a domain
nine-manage-anubis enable example.com

# 4. Verify
nine-manage-anubis status --health
nine-manage-anubis self-test
```

### Enable a single vhost

```sh
nine-manage-anubis --dry-run enable example.com
nine-manage-anubis enable example.com
nine-manage-anubis status --domain example.com
```

### Enable multiple vhosts with different webroots

Each domain gets its own Anubis instance with a unique port pair:

```sh
nine-manage-anubis enable site-a.ch site-b.ch
nine-manage-anubis status
```

### Enable a WordPress multisite (shared webroot)

The first domain creates the instance; subsequent domains reuse it:

```sh
nine-manage-anubis enable example.ch           # creates instance on port 7010
nine-manage-anubis enable blog.example.ch      # reuses port 7010 (same webroot)
nine-manage-anubis enable forum.example.ch        # reuses port 7010 (same webroot)
nine-manage-anubis status                   # all three on one instance
```

### Batch enable all vhosts for a user (zero-downtime)

```sh
# 1. Preview
nine-manage-anubis --dry-run enable --all --user www-example

# 2. Prepare (no traffic impact)
nine-manage-anubis enable --all --user www-example --prepare-only --no-notify-services

# 3. Wait 5 minutes for PHP-FPM .user.ini cache to expire
#    Verify the shim is loaded:
#    curl -sA Googlebot https://<domain>/ | grep -ioE '<title>[^<]*</title>'

# 4. Cut over (single Apache reload at end of batch)
nine-manage-anubis enable --all --user www-example --cutover-only --no-notify-services --skip "vorlage*"

# 5. Verify
nine-manage-anubis self-test
nine-manage-anubis status --health
```

### Batch disable all vhosts for a user

```sh
# Preview
nine-manage-anubis --dry-run disable --all --user www-customer

# Disable
nine-manage-anubis disable --all --user www-customer

# Verify instances are gone
nine-manage-anubis status
```

### Change the shared bot policy

```sh
# Edit the policy file
sudo nine-su www-anubis
vi ~/.config/anubis/shared-policy.yaml
exit

# Restart all instances to pick up the change
nine-manage-anubis restart

# Verify
nine-manage-anubis status --health
```

### Upgrade Anubis

```sh
# Preview
nine-manage-anubis --dry-run upgrade

# Upgrade (rolling restart with health checks)
nine-manage-anubis upgrade

# Or upgrade to a specific version
nine-manage-anubis upgrade --version 1.28.0

# Verify
nine-manage-anubis self-test
nine-manage-anubis status --health
```

### Full teardown

```sh
# 1. Disable all domains
nine-manage-anubis disable --all --user www-example

# 2. Verify no instances remain
nine-manage-anubis status

# 3. Uninstall infrastructure
nine-manage-anubis uninstall
```

### Monitoring (JSON output for scripts)

```sh
# Check all instances are healthy
nine-manage-anubis --json status --health | \
  jq '.[] | select(.state != "active" or .health == "inactive") | .domain'

# Self-test with JSON
nine-manage-anubis --json self-test | jq '.error // "all checks passed"'

# Count protected vhosts
nine-manage-anubis --json status | jq '[.[].vhost_count] | add'
```
