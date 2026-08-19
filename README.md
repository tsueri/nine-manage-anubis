# nine-manage-anubis

> **Not affiliated with or supported by nine.ch.** This is a third-party tool
> that automates the Anubis runbook on nine.ch Managed Servers. It is not
> developed, endorsed, or supported by nine.ch GmbH. For issues, use the
> [issue tracker](https://github.com/tsueri/nine-manage-anubis/issues).

CLI for managing [Anubis](https://github.com/TecharoHQ/anubis) bot protection on [nine.ch Managed Servers](https://docs.nine.ch/docs/managed-server-services/).

Automates the full Anubis lifecycle: installation, enabling/disabling protection for vhosts (with multisite detection, automated origin fixups, dynamic port discovery), batch operations, upgrades with rolling restart, status reporting, and self-test with automatic rollback on failure.

For detailed documentation of every command and flag, see [docs/cli-reference.md](docs/cli-reference.md).

## About Anubis

[Anubis](https://github.com/TecharoHQ/anubis) is an open-source project that
protects websites from AI scrapers and bots. It is developed by
[TecharoHQ](https://github.com/TecharoHQ) and licensed under the MIT License.

If Anubis helps protect your sites, please consider supporting the developer
via [GitHub Sponsors](https://github.com/sponsors/TecharoHQ).

## Requirements

- Python 3.10+ (stdlib only — no pip dependencies)
- Runs as `www-data` on a nine.ch Managed Server
- `sudo nine-manage-vhosts` and `sudo nine-su` available (passwordless, scoped)

## Installation

```sh
# Clone and install
git clone git@github.com:tsueri/nine-manage-anubis.git
cd nine-manage-anubis
pip install --user -e .

# Or deploy without installing (copy the package + wrapper):
mkdir -p ~/bin
cp -r src/nine_manage_anubis ~/bin/
cat > ~/bin/nine-manage-anubis << 'EOF'
#!/bin/sh
exec python3 -m nine_manage_anubis "$@"
EOF
chmod +x ~/bin/nine-manage-anubis
```

## Configuration

The CLI reads defaults from a JSON config file at `~/.config/nine-manage-anubis/config.json`. All fields are optional — a missing field, or one set to `null`, uses the default. A file that cannot be read or parsed is reported and the run continues on defaults; a file that parses but carries a malformed value is rejected and the run stops.

```json
{
    "anubis_user": "www-anubis",
    "anubis_version": "1.27.0",
    "policy_file": null
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `anubis_user` | `www-anubis` | System user that runs the Anubis binary |
| `anubis_version` | `1.27.0` | Version tag for `install` and `upgrade` |
| `policy_file` | `null` | Shared bot policy path. When set, every instance gets `POLICY_FNAME=<path>` in its env file — edit one file to update all instances |

CLI flags override config file values. To create a starter config:

```sh
nine-manage-anubis config --init
```

To inspect current settings:

```sh
nine-manage-anubis config
```

## Commands

### `install`

Set up Anubis infrastructure: create the system user, download the binary, install the systemd template. Does not protect any domains.

```
nine-manage-anubis install [--version VERSION] [--init-policy]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--version` | from config (`1.27.0`) | Anubis version to download |
| `--init-policy` | off | Extract the default bot policy to the configured `policy_file` path |

```sh
# Basic install
nine-manage-anubis install

# Install a specific version
nine-manage-anubis install --version 1.28.0

# Install + extract default policy for shared customization
nine-manage-anubis install --init-policy
```

### `uninstall`

Remove Anubis infrastructure (binary, systemd template, user). Refuses if any Anubis instances still exist — disable all domains first.

```
nine-manage-anubis uninstall
```

```sh
nine-manage-anubis uninstall

# Dry run — see what it would remove
nine-manage-anubis --dry-run uninstall
```

### `enable`

Put a vhost behind Anubis. This is the main operation — it creates or reuses an Anubis instance, installs origin fixups, and switches the vhost to the proxy template.

```
nine-manage-anubis enable <domain> [domain ...] [OPTIONS]
nine-manage-anubis enable --all --user <user>
```

| Flag | Description |
|------|-------------|
| `--prepare-only` | Do everything except the cutover (key, env, fixups, origin vhost, start service). Leaves the public vhost serving directly. |
| `--cutover-only` | Only do the cutover step (switch the public vhost to proxy template). Assumes prepare was already run. |
| `--all` | Enable all vhosts for the given `--user` that are not yet behind Anubis |
| `--user <user>` | Website user to filter `--all` by (e.g., `www-example`) |

**What `enable` does (full flow):**

1. Check the vhost isn't already behind Anubis
2. Allocate a port pair (7010–7999), reusing an existing instance if the webroot already has one (multisite detection). A fresh pair is decided under a host-wide lock and held until step 4 writes it down, so two concurrent runs cannot be handed the same one
3. Generate a JWT signing key
4. Write the env file (`~/.config/anubis/<domain>.env`)
5. Install the systemd template (if not already installed)
6. Install origin fixups in the webroot (`.user.ini`, `anubis-origin-shim.php`, `.htaccess` block — handles existing `auto_prepend_file` by creating a chain wrapper)
7. Create the origin vhost (`origin-<domain>`, shares the public vhost's webroot)
8. Start the Anubis service
9. Create a Let's Encrypt certificate (if one doesn't exist)
10. Cut over the public vhost to `proxy_letsencrypt_https_redirect` with `PROXYPORT`

If any step fails after the cutover begins, the CLI automatically rolls back all changes made so far (undo stack).

**Prepare/cutover split** — for batch operations on production sites, split the flow to avoid downtime. `--prepare-only` does steps 1–8 (no traffic impact). `--cutover-only` does step 10 (brief Apache reload). See [Examples](#examples) below.

```sh
# Enable a single domain
nine-manage-anubis enable example.com

# Enable multiple domains (each gets its own instance unless they share a webroot)
nine-manage-anubis enable site1.ch site2.ch

# Enable all vhosts for a user
nine-manage-anubis enable --all --user www-example

# Prepare only (no cutover) — safe for production
nine-manage-anubis enable --all --user www-example --prepare-only --no-notify-services

# Cutover later (after PHP-FPM .user.ini cache expires, ~5 min)
nine-manage-anubis enable --all --user www-example --cutover-only --no-notify-services --skip "vorlage*"

# Dry run — see what would happen
nine-manage-anubis --dry-run enable example.com
```

### `disable`

Remove Anubis protection from a vhost. Switches the public vhost back to `default_letsencrypt_https`, then re-reads which vhosts are still on the instance's port. If this was the last one, tears down the instance (stop service, remove origin vhost, restore fixup files, remove env + key); if other vhosts still share it, the instance stays running and nothing else is touched. A teardown that fails part-way is rolled back — see [Architecture](#architecture).

```
nine-manage-anubis disable <domain> [domain ...]
nine-manage-anubis disable --all --user <user>
```

| Flag | Description |
|------|-------------|
| `--all` | Disable all Anubis-protected vhosts for the given `--user` |
| `--user <user>` | Website user to filter `--all` by |

```sh
# Disable a single domain
nine-manage-anubis disable example.com

# Disable all Anubis-protected vhosts for a user
nine-manage-anubis disable --all --user www-customer

# Dry run
nine-manage-anubis --dry-run disable example.com
```

### `upgrade`

Download a new Anubis binary and restart instances. By default, restarts one instance at a time with a health check after each — stops on failure.

```
nine-manage-anubis upgrade [--version VERSION] [--no-rolling]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--version` | latest from GitHub API | Target version to download |
| `--no-rolling` | off | Restart all instances at once instead of one-by-one |

```sh
# Upgrade to latest
nine-manage-anubis upgrade

# Upgrade to a specific version
nine-manage-anubis upgrade --version 1.28.0

# Restart all at once (faster, but no health gate)
nine-manage-anubis upgrade --no-rolling

# Dry run
nine-manage-anubis --dry-run upgrade
```

### `restart`

Restart all Anubis instances without downloading a new binary. Use this after changing the shared policy file or any env file. By default, restarts one instance at a time with a health check after each — stops on failure.

```
nine-manage-anubis restart [--no-rolling]
```

| Flag | Description |
|------|-------------|
| `--no-rolling` | Restart all instances at once instead of one-by-one |

```sh
# Rolling restart (default) — one at a time with health check
nine-manage-anubis restart

# Restart all at once
nine-manage-anubis restart --no-rolling

# Dry run
nine-manage-anubis --dry-run restart
```

### `status`

List all Anubis instances on the host. Discovers instances by combining vhost config (which ports are assigned), env files (which ports are claimed), and systemd (which services are running).

```
nine-manage-anubis status [--domain DOMAIN] [--health]
```

| Flag | Description |
|------|-------------|
| `--domain <domain>` | Filter by domain (matches primary domain or any vhost on the instance) |
| `--health` | Active health check: curl each running instance and report HTTP status |

```sh
# List all instances
nine-manage-anubis status

# Filter by domain
nine-manage-anubis status --domain example.com

# With health check
nine-manage-anubis status --health

# JSON output (for scripts/monitoring)
nine-manage-anubis --json status --health
```

### `self-test`

Verify Anubis infrastructure health: checks the user exists, binary runs, systemd template is installed, and every instance is active + HTTP-responding. Any HTTP response (200, 403, 503, etc.) counts as a pass — the instance is running and responding.

```
nine-manage-anubis self-test
```

```sh
nine-manage-anubis self-test

# Dry run
nine-manage-anubis --dry-run self-test
```

### `config`

Show current settings and config file location, or create a starter config file.

```
nine-manage-anubis config [--init]
```

| Flag | Description |
|------|-------------|
| `--init` | Create a default config file at `~/.config/nine-manage-anubis/config.json` |

```sh
# Show current settings
nine-manage-anubis config

# Create a starter config
nine-manage-anubis config --init
```

## Global flags

These go **before** the subcommand:

```
nine-manage-anubis [--dry-run] [--json] [--anubis-user USER] <command> ...
```

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be done without making changes |
| `--json` | Output results as JSON (for scripts and monitoring) |
| `--anubis-user <user>` | Anubis system user (default from config, or `www-anubis`) |

```sh
# Dry run any command
nine-manage-anubis --dry-run enable example.com

# JSON output for scripts
nine-manage-anubis --json status --health

# Use a different Anubis user
nine-manage-anubis --anubis-user www-data install
```

## Examples

### Single vhost

```sh
# Install Anubis infrastructure (one-time per server)
nine-manage-anubis install

# Enable protection for one domain
nine-manage-anubis enable example.com

# Verify
nine-manage-anubis status --domain example.com
nine-manage-anubis self-test

# Later: disable
nine-manage-anubis disable example.com
```

### Multiple vhosts (separate webroots)

Each domain gets its own Anubis instance with a unique port pair:

```sh
# Enable two domains with different webroots
nine-manage-anubis enable site-a.ch site-b.ch

# Each gets its own port (7010/7011, 7012/7013), env file, key, origin vhost
nine-manage-anubis status
```

### Multiple vhosts (shared webroot — WordPress multisite)

When domains share a webroot, the CLI detects it and reuses a single Anubis instance:

```sh
# Enable the first domain — creates instance on port 7010
nine-manage-anubis enable example.ch

# Enable a second domain with the same webroot — reuses port 7010
nine-manage-anubis enable blog.example.ch
# Output: "Reusing existing Anubis instance for example.ch (port 7010)"

# Both domains proxy to the same Anubis instance
nine-manage-anubis status
```

### All vhosts for a user (batch)

```sh
# See what would be enabled
nine-manage-anubis --dry-run enable --all --user www-example

# Enable all vhosts for www-example that aren't behind Anubis yet
nine-manage-anubis enable --all --user www-example

# Disable all Anubis-protected vhosts for a user
nine-manage-anubis disable --all --user www-customer
```

### Prepare then cutover (zero-downtime batch)

PHP-FPM caches `.user.ini` for 300 seconds. If you prepare and cutover in one step, the origin shim won't take effect for ~5 minutes — during which the site may break. Split the flow:

```sh
# Step 1: Prepare everything except the cutover
# Creates key, env, fixups, origin vhost, starts Anubis service.
# Public vhost still serves directly — no traffic impact.
nine-manage-anubis enable --all --user www-example --prepare-only --no-notify-services

# Step 2: Wait 5 minutes for PHP-FPM to pick up the .user.ini shim.
# You can verify the shim is loaded during this window:
#   curl -sA Googlebot https://example.com/ | grep -ioE '<title>[^<]*</title>'
# (should show the site title, not a redirect to wp-signup.php?new=origin-*)

# Step 3: Cut over all domains (single Apache reload at end of batch)
nine-manage-anubis enable --all --user www-example --cutover-only --no-notify-services --skip "vorlage*"

# Step 4: Verify
nine-manage-anubis self-test
nine-manage-anubis status --health
```

### Dry run

Always dry-run before batch operations:

```sh
# See what enable would do
nine-manage-anubis --dry-run enable --all --user www-example

# See what disable would do
nine-manage-anubis --dry-run disable --all --user www-example

# See what upgrade would do
nine-manage-anubis --dry-run upgrade
```

### JSON output for scripts

```sh
# Status as JSON
nine-manage-anubis --json status --health | jq .

# Enable result as JSON
nine-manage-anubis --json enable example.com | jq '.steps'
```

## Architecture

```
Visitor ──HTTPS──> Apache :443 (public vhost, proxy_letsencrypt_https_redirect)
                        │  ProxyPass / http://localhost:7010/
                        │  ProxyPreserveHost On
                        ▼
                    Anubis :7010 (systemd user service, embedded default policy)
                        │  TARGET=https://127.0.0.1:443
                        │  TARGET_HOST=origin-<domain>  (Host rewrite)
                        ▼
                    Apache :443 (origin vhost, default_snakeoil_https, same webroot)
                        │  .user.ini → anubis-origin-shim.php (restores public Host)
                        │  .htaccess (trailing-slash fixup)
                        ▼
                    PHP / static content
```

Anubis sits between two Apache vhosts. The public vhost proxies to Anubis; Anubis proxies back to a private origin vhost. The origin dance (separate origin vhost + PHP shim + `.htaccess`) is unavoidable on nine for Apache/PHP backends.

**Port allocation**: Anubis instances use the 7010–7999 port range. Each instance gets a pair (app + metrics): 7010/7011, 7012/7013, etc. The CLI auto-discovers the next free pair and reuses existing instances when vhosts share a webroot. What counts as taken is read from three places — listening sockets, the ports named in env files, and the `PROXYPORT` of every proxy vhost — and the chosen pair is checked against a fresh listing of listening sockets once more before it is handed out.

**Two runs cannot allocate the same pair**: allocating is read-decide-claim, and nothing on the host says a port is taken until the env file naming it exists. Two `enable` runs started close together would otherwise read the same answer, pick the same pair and both write it — the second instance then fails to bind, and its vhost points at a port serving someone else's site. So the whole sequence runs under an exclusive `flock` on `/run/lock/nine-manage-anubis-ports.lock`, held from the first read until the env file records the pair and released there — not across the certificate request and service start that follow. A run that reuses an existing instance takes no new port and holds nothing, which is what a 95-domain multisite batch mostly consists of. The lock is a kernel lock rather than a file whose existence means "held", so a run that is killed rather than finished leaves nothing behind to reap; a run that waits more than two minutes for it gives up and says which file to look at rather than hanging. `/run/lock` belongs to root and is emptied on reboot, so the first run after one creates the lock file through `sudo`.

**Multisite reuse**: when `enable` detects that a domain's webroot already has an Anubis instance, it reuses that port — no new env file, key, or service instance. All domains sharing a webroot proxy to the same Anubis port.

**Instance files**: an instance's env file and signing key are created 0600, in a `~/.config/anubis` the CLI creates if it isn't there. The mode is decided before the content is written rather than chmodded afterwards, so the key is never on disk readable by another user, not even for the length of a write. A file already sitting at either path is replaced; one that can't be replaced — owned by another user, say — fails the write instead of being written into. Webroot files (`.htaccess`, `.user.ini`, the PHP shim) keep the permissions their owner gave them.

**Rollback**: `enable` and `disable` both either complete or put the host back as they found it. Each step carries its undo, and a failure runs the undos in reverse order — `enable` unwinds what it created (switch vhost back, remove origin vhost, restore fixup files, remove env/key, disable service), `disable` puts back what it removed (rewrite env/key, reinstall fixups, recreate the origin vhost with its PHP version, restart the service, switch the vhost back to Anubis). The report names each artifact that went back; an undo that itself fails becomes a warning naming what needs manual cleanup, and does not stop the remaining undos.

**Refcounting**: several vhosts sharing a webroot share one Anubis instance, so `disable` only tears one down when nothing else is using it. That decision is re-read from a fresh vhost listing immediately before the first destructive step, after the public vhost has already been switched away — a listing taken any earlier still counts the vhost being disabled and predates any concurrent `enable`, and acting on it takes the other sites down. The window is narrowed rather than closed: a sibling becomes visible when its public vhost reaches the port, so an `enable` that has claimed the instance but not yet cut over is still missed.

**Failures and timeouts**: a failing external command is reported as the program, its exit code and its stderr — never as the command string, which can carry a freshly generated signing key. Every command runs under a timeout (60s by default; longer for a binary download, a certificate request or a service change), and overrunning it produces a `timed out after Ns` error naming the operation instead of a run that hangs with no output.

For the full manual runbook, see [docs/runbook.md](docs/runbook.md).

## Known limitations

**A signing key is visible to `ps` while it is being written.** Every command runs as an argument of `/bin/sh -c`, and a new instance's signing key travels to disk as a heredoc body inside that command — so for as long as that one write takes, a local user running `ps` can see it. Error messages never quote a command, so the key does not reach terminals, CI logs or bug reports; closing the `ps` window as well needs the script to reach `nine-su` on stdin rather than as part of the command string, which changes how every command is built.

**A timeout cannot always kill what it gave up on.** The timeout is enforced locally, and most commands run through `sudo` — by the time one hangs it is root, and the signal to stop it can be refused. The CLI stops waiting and reports the timeout rather than blocking, but the abandoned command may still be running on the host. `nine-manage-anubis status` shows what actually happened before you retry.

## Development

```sh
# Run the test suite (stdlib only)
python -m pytest -q

# Install in development mode
pip install -e .

# Run the CLI directly
python -m nine_manage_anubis --help
```

## License

MIT
