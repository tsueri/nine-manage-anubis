# Anubis on Nine — Runbook

Run [Anubis](https://github.com/TecharoHQ/anubis) in front of a nine.ch Managed Server vhost to block AI/bot traffic.

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

Anubis sits between two Apache vhosts. The public vhost proxies to Anubis; Anubis proxies back to a private origin vhost. The origin dance (separate origin vhost + PHP shim + `.htaccess`) is **unavoidable** on nine for Apache/PHP backends — see `docs/research/origin-dance-necessity.md` for why.

## Users and isolation

Two concerns are separate:

- **Website user** (`www-<organisation>`) — owns the webroot and the PHP-FPM pool. Both vhosts are created with `--user=www-<organisation>` so the origin vhost can share the public vhost's webroot (nine requires the webroot to be inside the user's home).
- **Anubis user** — runs the Anubis binary and owns its config/key files. Anubis is an HTTP reverse proxy; it doesn't touch PHP-FPM or the webroot, so its user is independent of the website user.

Two options:

- **Run Anubis as `www-data`** (simplest — no new user). `www-data` already has a systemd user instance and lingering enabled on nine. Put the binary in `/home/www-data/bin/` and config in `/home/www-data/.config/anubis/`.
- **Run Anubis as a dedicated user** (e.g., `www-anubis` — isolated, recommended). A dedicated user limits blast radius: if Anubis is compromised, the attacker doesn't get `www-data`'s passwordless sudo to `nine-manage-vhosts`. Create it with `sudo nine-manage-vhosts user create www-anubis --no-password` — lingering is enabled automatically.

The recipe below uses `www-<anubis-user>` for the Anubis user and `www-<organisation>` for the website user. Substitute `www-data` for `www-<anubis-user>` if you choose the simple option.

## Prerequisites

- **SSH access** as `www-data` on the managed server.
- **A website user** `www-<organisation>` for the vhosts and webroot (create with `sudo nine-manage-vhosts user create www-<organisation> --no-password` if it doesn't exist).
- **An Anubis user** — either `www-data` (already exists) or a dedicated user (see above).
- **The Anubis binary**, downloaded to the Anubis user's `~/bin/`:
  ```sh
  sudo nine-su www-<anubis-user>
  cd ~
  # Check the latest version at https://github.com/TecharoHQ/anubis/releases
  curl -LO https://github.com/TecharoHQ/anubis/releases/latest/download/anubis-<version>-linux-amd64.tar.gz
  tar xzf anubis-<version>-linux-amd64.tar.gz
  mkdir -p ~/bin
  cp anubis-<version>-linux-amd64/bin/anubis ~/bin/
  chmod +x ~/bin/anubis
  ~/bin/anubis --version  # verify
  ```

## Recipe

Parameterize by `<domain>` (e.g., `example.com`), `<organisation>` (the website user), and `<anubis-user>` (the Anubis user — `www-data` or a dedicated user).

Commands run as `www-data` unless noted. `nine-manage-vhosts` requires sudo — `www-data` has passwordless sudo scoped to it.

### Port allocation

Anubis's default port is `8923` and its default metrics port is `9090`. On a nine-manage-vhosts host with many vhosts and user-installed apps, the `8000–9400` neighborhood is crowded: `8000`, `8080`, `8443`, `8888` are commonly grabbed by Node.js/Python/Java apps; `9090`, `9100`, `9104` etc. are used by Prometheus exporters and other monitoring.

This recipe reserves the **7010–7999** block for Anubis. The legacy AFS ports `7000–7007` and X11 font service `7100` are skipped — everything else in the 7000 range is effectively unused on modern nine hosts (verified by scanning 7010–7999: zero collisions). The block holds 495 instance pairs:

- Instance 1: app `7010`, metrics `7011`
- Instance 2: app `7012`, metrics `7013`
- Instance N: app `7010 + 2(N-1)`, metrics `app + 1`

Always confirm the pair is free before creating the vhost:

```sh
ss -tlnp | grep -E ':(7010|7011) ' || echo "ports 7010/7011 are free"
```

The rest of this recipe uses `7010`/`7011` for the first instance. Substitute your allocated pair for subsequent instances.

### 1. Create the public vhost (in front of Anubis)

Confirm the allocated port pair is free (here `7010`/`7011`):

```sh
ss -tlnp | grep -E ':(7010|7011) ' || echo "ports 7010/7011 are free"
```

The `proxy_letsencrypt_https_redirect` template requires a Let's Encrypt certificate to exist *before* the vhost is created — but the certificate requires a vhost to exist first (chicken-and-egg). The workaround is to create the vhost with the `default` template, create the cert, then update the vhost to the proxy template:

```sh
# Create with a plain template first
sudo nine-manage-vhosts virtual-host create <domain> \
  --user=www-<organisation> \
  --template=default

# Create the Let's Encrypt certificate (requires DNS A record pointing at the server)
sudo nine-manage-vhosts certificate create --virtual-host=<domain>

# Switch to the proxy template
sudo nine-manage-vhosts virtual-host update <domain> \
  --template=proxy_letsencrypt_https_redirect \
  --template-variable=PROXYPORT=7010
```

`nine-manage-vhosts` creates the webroot at `/home/www-<organisation>/<domain>/` automatically, configures the HTTP→HTTPS redirect, and the reverse proxy to `localhost:7010`. It also reloads Apache.

`PROXYPORT` is the only required template variable — it has no default. `TIMEOUT` defaults to 300 seconds. The ACME challenge path (`/.well-known/acme-challenge/`) is excluded from the proxy by the template, so validation works through the public vhost directly. Certificates renew automatically via cron.

> **First-time setup**: if no Let's Encrypt client is registered on this server yet, register one (one-time per server):
> ```sh
> sudo nine-manage-vhosts certificate register-client
> ```
> See the [nine Let's Encrypt docs](https://docs.nine.ch/docs/managed-server-services/webserver/nine-manage-vhosts/nine-manage-vhosts-with-lets-encrypt/) for details.

### 2. Create the origin vhost (backend Anubis proxies to)

```sh
sudo nine-manage-vhosts virtual-host create origin-<domain> \
  --user=www-<organisation> \
  --template=default_snakeoil_https \
  --webroot=/home/www-<organisation>/<domain>
```

Key points:
- **`--webroot` shares the public vhost's webroot** — the origin serves the same content. Without this, the origin would get its own `/home/www-<organisation>/origin-<domain>/`.
- **Same `--user` as the public vhost** — the webroot must lie inside the user's home directory.
- **`origin-<domain>` has no DNS** — it's only reachable via the `Host: origin-<domain>` header that Anubis rewrites to. The snakeoil cert is fine because Anubis skips TLS verification.
- **Template variables use defaults**: `PHP_VERSION` (system default), `MODSEC=Off`, `TIMEOUT=300`. Override only if your app needs a different PHP version: `--template-variable=PHP_VERSION=8.1`.

### 3. Install origin fixups

Three files in the webroot undo the Host-rewrite side effects. They are domain-agnostic — only the webroot path in `.user.ini` is parameterized.

**`/home/www-<organisation>/<domain>/.user.ini`**:
```ini
auto_prepend_file = /home/www-<organisation>/<domain>/anubis-origin-shim.php
```

**`/home/www-<organisation>/<domain>/anubis-origin-shim.php`**:
```php
<?php
// Behind Anubis: the origin vhost is reached under a private hostname.
// Restore the public hostname the visitor actually used.
if (!empty($_SERVER['HTTP_X_FORWARDED_HOST'])) {
    $h = explode(',', $_SERVER['HTTP_X_FORWARDED_HOST'])[0];
    $_SERVER['HTTP_HOST'] = $_SERVER['SERVER_NAME'] = trim($h);
}
```

**`/home/www-<organisation>/<domain>/.htaccess`**:
```apache
# --- Anubis origin fixups (keep above any app rules) ---------------------
# This vhost is only reached through Anubis, which rewrites the Host header to
# the private origin name. Apache would therefore emit its own redirects (e.g.
# mod_dir's missing-trailing-slash 301) pointing at that private name, which
# does not resolve for visitors. Emit them against the public host instead.
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP:X-Forwarded-Host} ^(.+)$
  RewriteCond %{REQUEST_FILENAME} -d
  RewriteCond %{REQUEST_URI} !/$
  RewriteRule ^(.*)$ https://%{HTTP:X-Forwarded-Host}/$1/ [R=301,L]
</IfModule>
# ------------------------------------------------------------------------
```

> **Non-PHP backends**: if your origin serves only static files (no PHP), you can skip `.user.ini` and `anubis-origin-shim.php` — but the `.htaccess` trailing-slash fixup is still needed. Alternatively, replace Apache as the origin entirely with a static file server (e.g., `python3 -m http.server` as a systemd user service); see `docs/research/origin-dance-necessity.md` for that simplification.

### 4. Generate the JWT signing key

```sh
sudo nine-su www-<anubis-user>
mkdir -p ~/.config/anubis
openssl rand -hex 32 > ~/.config/anubis/<domain>.key
chmod 600 ~/.config/anubis/<domain>.key
```

This key signs Anubis's authorization cookies. Generate it once; don't regenerate on restart (that would invalidate all cookies).

### 5. Write the Anubis env file

**`~/.config/anubis/<domain>.env`** (as `www-<anubis-user>`):
```sh
# --- Anubis instance for <domain> ---
# public vhost  : <domain>        (proxy_letsencrypt_https_redirect, PROXYPORT=7010)
# origin vhost  : origin-<domain>  (default_snakeoil_https, same webroot)
BIND=:7010
METRICS_BIND=:7011

# Backend: Apache on loopback, selected by the Host header we rewrite to.
TARGET=https://127.0.0.1:443
TARGET_HOST=origin-<domain>
TARGET_SNI=origin-<domain>
TARGET_INSECURE_SKIP_VERIFY=true

# First-party cookie semantics (shipped default None/Partitioned breaks Safari).
COOKIE_SAME_SITE=Lax
COOKIE_PARTITIONED=false

# JWT signing key (generated in step 4).
ED25519_PRIVATE_KEY_HEX_FILE=/home/www-<anubis-user>/.config/anubis/<domain>.key
```

**That's the entire config — 9 environment variables.** The bot policy is Anubis's shipped embedded default (`ai-block-aggressive`, honeypot enabled, geoip/asn rules inert without Thoth). No policy file on disk.

#### What's deliberately NOT in the env file

| Var | Why omitted |
|-----|-------------|
| `DIFFICULTY` | Inert — the shipped policy's `thresholds` block pins per-band difficulties (1, 2, 4, 6) that take precedence over the env var. |
| `SERVE_ROBOTS_TXT` | Defaults to `false`. Anubis's built-in robots.txt disallows ALL crawlers (including Google); leaving it off lets the origin serve robots.txt. |
| `POLICY_FNAME` | Defaults to the embedded policy. Pointing at a file is the escape hatch for customization (see "Customizing" below). |

### 6. Install the systemd user service

Follow the [nine docs for systemd user daemons](https://docs.nine.ch/docs/managed-server-services/applications/manage-daemons-as-a-user-with-systemd/). The unit file is a **template** (`@.service`) — one file serves all domains.

**`~/.config/systemd/user/anubis@.service`** (as `www-<anubis-user>`):
```ini
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
```

> **`WantedBy=default.target`** — not `multi-user.target`. The nine docs are explicit: `multi-user.target` is not available in the user systemd instance. Using it triggers misconfiguration alerts.

### 7. Start the service

As the Anubis user, reload systemd (to pick up the new unit file) and enable + start the service:

```sh
sudo nine-su www-<anubis-user>
export XDG_RUNTIME_DIR=/run/user/$(id -u)
systemctl --user daemon-reload
systemctl --user enable --now anubis@<domain>.service
systemctl --user status anubis@<domain>.service
```

> **`XDG_RUNTIME_DIR`** is needed when running `systemctl --user` from a non-interactive shell (like `nine-su`). The nine docs note this for scripts/cron; it applies here too. If running as `www-data` from an interactive SSH session, it's already set.

### 8. Verify

```sh
# Service running? (as www-<anubis-user>)
systemctl --user is-active anubis@<domain>.service  # → active

# Listening on :7010?
ss -tlnp | grep 7010

# AI bot denied? (should return Anubis "Oh noes!" page, not your content)
curl -A GPTBot https://<domain>/ | head -5

# Googlebot passes? (should return your content)
curl -A Googlebot https://<domain>/ | head -5

# Browser: open https://<domain>/ — challenge solves, site loads.
```

## Migrating an existing domain

The recipe above assumes a greenfield vhost. In practice you're more likely to slot Anubis in front of a domain that already has a vhost, a cert, content, and `.htaccess` rules. The migration differs from the new-domain recipe in three ways:

1. **No public-vhost creation** — the vhost and cert already exist. You only `update` the template at cutover.
2. **Origin fixups must merge with existing files** — `.user.ini` and `.htaccess` may already have app rules.
3. **Order matters for zero downtime** — Anubis and the origin vhost must be ready *before* you flip the public vhost to proxy mode.

### Migration steps

1. **Audit the existing vhost for leftover Anubis artifacts** — a previous Anubis install (or a failed migration) may have left config behind. Check before merging:

   ```sh
   # Vhost template — is it already proxying to an old Anubis port?
   sudo nine-manage-vhosts virtual-host show <domain> | grep -i 'proxy\|PROXYPORT'

   # Origin vhost — does one already exist?
   sudo nine-manage-vhosts virtual-host list | grep origin-<domain>

   # Webroot fixup files — already present from a previous install?
   ls -la /home/www-<organisation>/<domain>/{.user.ini,.htaccess,anubis-origin-shim.php} 2>/dev/null

   # .user.ini — does it already reference the shim?
   grep auto_prepend_file /home/www-<organisation>/<domain>/.user.ini 2>/dev/null

   # .htaccess — does it already have the Anubis fixup block?
   grep -A2 'X-Forwarded-Host' /home/www-<organisation>/<domain>/.htaccess 2>/dev/null

   # Old Anubis env/key files?
   ls -la /home/www-<anubis-user>/.config/anubis/<domain>.* 2>/dev/null

   # Old systemd service instance still running?
   sudo nine-su www-<anubis-user> -c 'XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user status anubis@<domain>.service' 2>&1

   # Old port still listening? (e.g., 8923 from a previous install)
   ss -tlnp | grep -E ':8923|:7010'
   ```

   If any artifacts are found, decide whether to reuse or clean them up (see "Removing a domain" below for the teardown flow). A half-installed state from a failed previous migration is the most common cause of breakage.

2. **Check the current vhost state** — note the template, user, and whether an LE cert exists:
   ```sh
   sudo nine-manage-vhosts virtual-host show <domain>
   sudo nine-manage-vhosts certificate list | grep <domain>
   ```

3. **Check the port pair is free** (same as the new-domain recipe):
   ```sh
   ss -tlnp | grep -E ':(7010|7011) ' || echo "ports 7010/7011 are free"
   ```

4. **Generate the JWT key** (as the Anubis user — same as step 4 above):
   ```sh
   sudo nine-su www-<anubis-user>
   mkdir -p ~/.config/anubis
   openssl rand -hex 32 > ~/.config/anubis/<domain>.key
   chmod 600 ~/.config/anubis/<domain>.key
   ```

5. **Write the env file** (same as step 5 above — adjust port, `TARGET_HOST`, key path).

6. **Install the systemd template** (if not already installed — same as step 6). Skip if the `anubis@.service` template already exists for this Anubis user.

7. **Create the origin vhost** (same as step 2 above — it shares the *existing* webroot). **Match the PHP version** of the existing vhost — check with `virtual-host show <domain>` and look for the PHP-FPM socket version. If it's not the system default (8.3), pass it explicitly:
   ```sh
   sudo nine-manage-vhosts virtual-host create origin-<domain> \
     --user=www-<organisation> \
     --template=default_snakeoil_https \
     --webroot=/home/www-<organisation>/<domain> \
     --template-variable=PHP_VERSION=8.0
   ```

8. **Install origin fixups** — the files are the same as step 3, but they may need to merge with existing content:

   - **`anubis-origin-shim.php`** — new file, no conflict. Copy as-is.
   - **`.user.ini`** — if one already exists with an `auto_prepend_file` (e.g., Wordfence WAF, or other security middleware), you can't just add a second one — PHP only honors the last value. Create a **chain wrapper** that includes both files in order, then point `.user.ini` at it:
     ```php
     <?php
     // anubis-prepend-chain.php — chains Anubis shim + existing auto_prepend
     include_once __DIR__ . '/anubis-origin-shim.php';
     include_once __DIR__ . '/wordfence-waf.php';  // or whatever was there before
     ```
     ```ini
     ; .user.ini
     auto_prepend_file = '/home/www-<organisation>/<domain>/anubis-prepend-chain.php'
     ```
     The Anubis shim must run **first** so it restores `HTTP_HOST` before the WAF or app sees it. Back up the original `.user.ini` before modifying.
   - **`.htaccess`** — if one already exists, **prepend** the Anubis fixup block above any existing `RewriteEngine`/`RewriteRule` lines. The fixup must run before app rules so trailing-slash redirects use the public host. Duplicate `RewriteEngine On` directives are harmless (idempotent). Back up the original `.htaccess` before modifying.

9. **Start the Anubis service** (before cutover, so the proxy target is live):
   ```sh
   sudo nine-su www-<anubis-user>
   export XDG_RUNTIME_DIR=/run/user/$(id -u)
   systemctl --user daemon-reload
   systemctl --user enable --now anubis@<domain>.service
   systemctl --user status anubis@<domain>.service
   ```

10. **Verify Anubis is reachable directly** (before flipping the public vhost):
    ```sh
    curl -sH "X-Real-Ip: 127.0.0.1" -H "Host: <domain>" http://localhost:7010/ | head -5
    ```

11. **Cut over the public vhost to proxy mode** — this is the only step that causes a brief interruption (Apache reload). If the vhost already has an LE cert, it's a single command:
    ```sh
    sudo nine-manage-vhosts virtual-host update <domain> \
      --template=proxy_letsencrypt_https_redirect \
      --template-variable=PROXYPORT=7010
    ```

    If the vhost currently uses snakeoil (no LE cert), create the cert first — the vhost already exists, so there's no chicken-and-egg:
    ```sh
    sudo nine-manage-vhosts certificate create --virtual-host=<domain>
    sudo nine-manage-vhosts virtual-host update <domain> \
      --template=proxy_letsencrypt_https_redirect \
      --template-variable=PROXYPORT=7010
    ```

12. **Verify** — run the full check suite:

    ```sh
    # Service running?
    sudo nine-su www-<anubis-user> -c 'XDG_RUNTIME_DIR=/run/user/$(id -u) systemctl --user is-active anubis@<domain>.service'

    # Ports listening?
    ss -tlnp | grep -E ':(7010|7011) '

    # AI bot denied?
    curl -A GPTBot https://<domain>/ | grep -o '<title>[^<]*</title>'

    # Googlebot passes?
    curl -A Googlebot https://<domain>/ | grep -o '<title>[^<]*</title>'

    # Origin shim working? (should show the site title, not a redirect to wp-signup.php?new=origin-*)
    curl -sA Googlebot https://<domain>/ | grep -ioE '<title>[^<]*</title>'

    # Trailing-slash redirect uses public domain? (should show https://<domain>/, not https://origin-<domain>/)
    curl -sI -A Googlebot https://<domain>/somedir | grep -i location

    # .user.ini points at the shim?
    grep auto_prepend_file /home/www-<organisation>/<domain>/.user.ini

    # .htaccess has the fixup block?
    grep X-Forwarded-Host /home/www-<organisation>/<domain>/.htaccess

    # Env file has the right port + target?
    grep -E 'BIND|TARGET_HOST|METRICS_BIND' /home/www-<anubis-user>/.config/anubis/<domain>.env

    # Browser: open https://<domain>/ — challenge solves, site loads.
    ```

    If the title shows a redirect to `wp-signup.php?new=origin-<domain>` or URLs in the HTML point to `origin-<domain>`, the shim isn't loaded — check `.user.ini` path and permissions. If the trailing-slash redirect points at `origin-<domain>`, the `.htaccess` fixup block is missing or below app rules.

### Rollback

If something goes wrong after cutover, switch the public vhost back to its original template to bypass Anubis immediately:

```sh
sudo nine-manage-vhosts virtual-host update <domain> --template=default_letsencrypt_https
```

Apache serves the webroot directly again. The origin fixup files remain in the webroot but are no-ops without `X-Forwarded-Host` (which only the proxy template sets), so the site works normally without restoring backups. For a full teardown (removing fixup files, origin vhost, and Anubis service), see "Removing a domain" below.

### What doesn't change during migration

- **The webroot and all content** — untouched. The origin vhost serves the same files.
- **The LE cert** — stays in place. The proxy template uses the same cert as the previous template.
- **Existing aliases** — remain on the public vhost. The origin vhost doesn't need them.
- **PHP-FPM pool** — still owned by `www-<organisation>`. Anubis doesn't touch it.

## What the shipped default policy does

The embedded `botPolicies.yaml` (no file needed — it's compiled into the binary) ships:

- **`ai-block-aggressive`** — DENYs all AI agents (GPTBot, ClaudeBot, Bytespider, OAI-SearchBot, PerplexityBot, etc.)
- **`_allow-good` crawlers** — ALLOWs Googlebot, Bingbot, and other legitimate search engines from their published IP ranges
- **Pathological bots** — DENYs known-bad scrapers
- **Honeypot** — injects an invisible link into challenge/error pages; scrapers that follow it get trapped in a maze and rate-limited
- **GeoIP/ASN weight rules** — for Brazil/China traffic and Cloudflare/Huawei/Alibaba ASNs (inert without a Thoth subscription; harmless)
- **Proof-of-work challenges** — difficulty tuned per suspicion band: mild=1, moderate=2, extreme=6
- **HTTP 200 for challenges/denies** — aggressive scrapers stop hammering when they get a 200 (a 4xx makes them retry harder)

## Adding more domains

The Anubis binary, the `anubis@.service` template, and the Anubis user are installed once. Adding a domain is configuration, not reinstallation.

### Alias domains (same content, another name)

An alias (e.g., `www.<domain>` alongside `<domain>`) points at the same vhost and the same content. Only the *public* vhost gets the alias — the origin vhost does not.

```sh
sudo nine-manage-vhosts alias create www.<domain> --virtual-host=<domain>
```

The public vhost now serves both hosts, both proxying to Anubis on the same port. Anubis receives the visitor's actual `Host` (e.g., `www.<domain>`), rewrites it to `origin-<domain>` for the backend, and the shim restores the original from `X-Forwarded-Host`. The origin vhost needs no change — it's only reached via `Host: origin-<domain>`.

**Cookie handling**: a cookie set on `<domain>` is not sent to `www.<domain>` (different host). Two options:

1. **Redirect www→apex** (simplest, no Anubis config change). Add to the public vhost's `.htaccess` or use nine's HTTP→HTTPS redirect template. Visitors only use one host, so one cookie.
2. **Set `COOKIE_DOMAIN=<domain>`** in the env file. The cookie is then valid for `<domain>` and all subdomains. Add this line:
   ```sh
   COOKIE_DOMAIN=<domain>
   ```
   Restart the service: `systemctl --user restart anubis@<domain>.service`.

### Multiple domains, same webroot (WordPress multisite)

Several domains serving different content from the **same webroot** — e.g., a WordPress multisite where `example.ch` is the main domain and `blog.example.ch` is a separate vhost pointing at the same `DocumentRoot`. The application (WordPress) reads `HTTP_HOST` to decide which site to serve.

This case needs only **one Anubis instance** — all domains proxy to the same port, and the origin shim ensures WordPress sees the correct `HTTP_HOST` for each domain. No per-domain Anubis config, no separate ports.

There are two ways the additional domains may be configured on nine:

#### Case A: Separate vhosts (each domain is its own vhost with its own cert)

This is the common case on nine — e.g., `example.ch` and `blog.example.ch` are both separate vhosts under the same user, both with `DocumentRoot /home/www-<organisation>/<primary-domain>/`, each with its own LE cert. Each vhost is independently switched to the proxy template, but both point at the **same** Anubis port:

1. **Set up Anubis for the primary domain** following the recipe (or migration steps) above. One port pair (e.g., 7010/7011), one env file, one origin vhost (`origin-<primary-domain>`), one service instance.

2. **Switch each additional domain's vhost to proxy mode** — same port as the primary:
   ```sh
   # The additional domain already has a vhost + cert — just update the template
   sudo nine-manage-vhosts virtual-host update <domain2> \
     --template=proxy_letsencrypt_https_redirect \
     --template-variable=PROXYPORT=7010
   ```
   No new Anubis env file, no new key, no new origin vhost, no new service instance. The additional domain's vhost simply proxies to the same Anubis port as the primary domain.

3. **No changes to the env file** — `TARGET_HOST` stays as `origin-<primary-domain>`. All domains reach Anubis on the same port; Anubis proxies them all to the same origin vhost. The origin shim restores each visitor's actual `Host` (e.g., `<domain2>`) from `X-Forwarded-Host`, so WordPress serves the correct site.

#### Case B: Aliases (additional domains are `ServerAlias` on the primary vhost)

If the additional domain is an alias (not its own vhost), just add it — no template change needed since the alias inherits the vhost's proxy config:

```sh
sudo nine-manage-vhosts alias create <domain2> --virtual-host=<domain>
```

If the additional domain needs its own LE cert, create it first:
```sh
sudo nine-manage-vhosts certificate create --virtual-host=<domain2>
sudo nine-manage-vhosts alias create <domain2> --virtual-host=<domain>
```

#### Cookie handling

Each domain gets its own Anubis challenge cookie. If you want a single cookie across all domains (so a visitor who solves the challenge on `domain1` doesn't have to solve it again on `domain2`), set `COOKIE_DOMAIN` to the parent domain if they share one (e.g., `COOKIE_DOMAIN=example.com` for `site1.example.com` and `site2.example.com`). For unrelated domains (e.g., `domainA.ch` and `domainB.ch`), there's no shared cookie domain — each domain issues its own cookie.

#### Why one instance works

Anubis doesn't care which domain the visitor used — it always proxies to the same origin. The origin vhost serves the same webroot regardless of `Host` (it only matches `Host: origin-<primary-domain>`). WordPress, not Anubis, decides which site to serve based on `HTTP_HOST` — and the shim ensures that's the public domain, not the origin name.

#### Unaffected vhosts sharing the webroot

The origin fixup files (`.user.ini`, `anubis-origin-shim.php`, `.htaccess` block) are installed in the shared webroot, so they're loaded by **all** vhosts pointing at it — not just the ones behind Anubis. This is safe because both fixups are **conditional on `X-Forwarded-Host`**, which is only set by the public vhost's `mod_proxy` when proxying to Anubis:

- **`anubis-origin-shim.php`** — the `if (!empty($_SERVER['HTTP_X_FORWARDED_HOST']))` guard is a no-op without the header. Vhosts serving directly (not through Anubis) don't have `X-Forwarded-Host`, so `HTTP_HOST` is untouched.
- **`.htaccess` fixup block** — the `RewriteCond %{HTTP:X-Forwarded-Host} ^(.+)$` condition fails without the header, so the rewrite rule doesn't fire.

Tested with a 95-domain WordPress multisite: installing fixups in the shared webroot and cutting over only 2 domains had zero impact on the other 93.

### Multiple domains (different content, different webroot)

Each domain needs its own Anubis *instance* — a separate port, env file, JWT key, and systemd service instance — because each domain has its own `TARGET_HOST=origin-<domain>` and its own webroot. The `anubis@.service` template already supports this: `%i` is the domain. The domain can run under the same website user or a different one.

To add a second domain `<domain2>` alongside `<domain>`:

1. **Check the port pair is free** (instance 2 uses `7012`/`7013` per the pairing formula):
   ```sh
   ss -tlnp | grep -E ':(7012|7013) ' || echo "ports 7012/7013 are free"
   ```

2. **Create the public vhost** using the create-cert-update flow from step 1 (the `proxy_letsencrypt_https_redirect` template needs a cert first):
   ```sh
   sudo nine-manage-vhosts virtual-host create <domain2> \
     --user=www-<organisation2> \
     --template=default
   sudo nine-manage-vhosts certificate create --virtual-host=<domain2>
   sudo nine-manage-vhosts virtual-host update <domain2> \
     --template=proxy_letsencrypt_https_redirect \
     --template-variable=PROXYPORT=7012
   ```

3. **Create the origin vhost** (sharing `<domain2>`'s webroot):
   ```sh
   sudo nine-manage-vhosts virtual-host create origin-<domain2> \
     --user=www-<organisation2> \
     --template=default_snakeoil_https \
     --webroot=/home/www-<organisation2>/<domain2>
   ```

4. **Install origin fixups** in `/home/www-<organisation2>/<domain2>/` (`.user.ini`, `anubis-origin-shim.php`, `.htaccess` — same content as step 3 above, with the webroot path adjusted in `.user.ini`).

5. **Generate a JWT key** for the new domain (as the Anubis user — same user as the first domain, or a different one):
   ```sh
   sudo nine-su www-<anubis-user>
   openssl rand -hex 32 > ~/.config/anubis/<domain2>.key
   chmod 600 ~/.config/anubis/<domain2>.key
   ```

6. **Write the env file** `~/.config/anubis/<domain2>.env` (same shape as step 5, with `BIND=:7012`, `METRICS_BIND=:7013`, `TARGET_HOST=origin-<domain2>`, `TARGET_SNI=origin-<domain2>`, and the new key path).

7. **Enable + start** the new instance:
   ```sh
   export XDG_RUNTIME_DIR=/run/user/$(id -u)
   systemctl --user enable --now anubis@<domain2>.service
   ```

No reinstallation, no new binary, no new systemd template — just a new env file, new vhosts, new key, and a new instance of the template service.

## Customizing

### Allow some AI bots (SEO / cooperative AI)

Copy the embedded default to a file, switch the AI block import, and point `POLICY_FNAME` at it:

```sh
# Extract the shipped policy
~/bin/anubis -extract-resources /tmp/anubis-data
cp /tmp/anubis-data/data/botPolicies.yaml ~/.config/anubis/<domain>-policies.yaml

# Edit: replace
#   - import: (data)/meta/ai-block-aggressive.yaml
# with one of:
#   - import: (data)/meta/ai-block-moderate.yaml     # allows OpenAI-search, Mistral
#   - import: (data)/meta/ai-block-permissive.yaml    # also allows GPTBot from OpenAI IPs

# Add to ~/.config/anubis/<domain>.env:
#   POLICY_FNAME=/home/www-<anubis-user>/.config/anubis/<domain>-policies.yaml
```

Restart the service after editing: `systemctl --user restart anubis@<domain>.service`.

### Enable Thoth (IP reputation)

If you have a [Thoth](https://anubis.techaro.lol/docs/admin/thoth/) subscription, add to the env file:
```
THOTH_URL=<your-thoth-url>
THOTH_TOKEN=<your-thoth-token>
```
This activates the geoip/ASN weight rules.

### Change cookie settings

The recipe overrides the shipped defaults (`SameSite=None, Partitioned=true`) to `Lax`/`false` because Anubis runs as a first-party reverse proxy on nine. If your deployment is third-party (Anubis on a different domain than the origin), revert to the shipped defaults by removing `COOKIE_SAME_SITE` and `COOKIE_PARTITIONED` from the env file.

### Disable the honeypot

The honeypot ships enabled and has no downside for real users. To disable, you'd need a custom policy file with `honeypot: enabled: false` — see "Customizing" above for extracting the policy.

## Removing a domain

To tear down an Anubis-protected domain (e.g., after migration or decommission):

1. **Switch the public vhost back to a non-proxy template** (so Apache serves the webroot directly, bypassing Anubis):
   ```sh
   sudo nine-manage-vhosts virtual-host update <domain> --template=default_letsencrypt_https
   ```
   For multisite setups, repeat for each vhost that was switched to the proxy template.

2. **Restore the original `.htaccess` and `.user.ini`** from the backups created during migration (as the website user):
   ```sh
   sudo nine-su www-<organisation>
   cd /home/www-<organisation>/<domain>/
   cp .htaccess.anubis-bak.* .htaccess    # restore BEFORE deleting backups
   cp .user.ini.anubis-bak.* .user.ini    # if a backup exists
   rm -f .htaccess.anubis-bak.* .user.ini.anubis-bak.*
   rm -f anubis-origin-shim.php anubis-prepend-chain.php
   ```
   If no backup exists (e.g., the domain had no `.htaccess` before Anubis), just remove the fixup files and the `.user.ini` if it was created by Anubis. For the `.htaccess`, manually remove the Anubis fixup block (between the `# --- Anubis origin fixups` and `# ---` marker lines).

   > **Note:** PHP-FPM caches `.user.ini` for 300 seconds. The restored `.user.ini` (or the removal of it) won't take effect until the cache expires. Wait 5 minutes before verifying.

3. **Stop + disable the Anubis service** (as the Anubis user):
   ```sh
   sudo nine-su www-<anubis-user>
   export XDG_RUNTIME_DIR=/run/user/$(id -u)
   systemctl --user disable --now anubis@<domain>.service
   ```

4. **Remove the origin vhost**:
   ```sh
   sudo nine-manage-vhosts virtual-host remove origin-<domain>
   ```

5. **Remove Anubis config + key** (as the Anubis user):
   ```sh
   sudo nine-su www-<anubis-user>
   rm ~/.config/anubis/<domain>.env
   rm ~/.config/anubis/<domain>.key
   ```

If you're also removing the public vhost entirely (not just rolling back from Anubis), switch it to `default` first, then remove the cert and vhost:
```sh
sudo nine-manage-vhosts virtual-host update <domain> --template=default
sudo nine-manage-vhosts certificate remove --virtual-host=<domain>
sudo nine-manage-vhosts virtual-host remove <domain>
```

The Anubis binary, systemd template, and Anubis user remain — they're shared across all domains.

## Troubleshooting

- **`curl localhost:7010` returns 500** — expected. Anubis requires the `X-Real-Ip` header (set by the public vhost's proxy). A bare localhost curl lacks it. Test through the public vhost instead: `curl https://<domain>/`.
- **WARN logs about Thoth/geoip at startup** — expected. The embedded policy has geoip/ASN rules that no-op without a Thoth client. Harmless.
- **Trailing-slash redirects point to `origin-<domain>`** — the `.htaccess` fixup isn't loaded. Check that `mod_rewrite` is enabled and the `.htaccess` is in the webroot.
- **PHP sees `HTTP_HOST=origin-<domain>`** — the shim isn't loaded. Check that `.user.ini` points at `anubis-origin-shim.php` with the correct absolute path, and that PHP-FPM reads `.user.ini` (it does by default). **Note:** PHP-FPM caches `.user.ini` for 300 seconds (`user_ini.cache_ttl`) — if you just created or modified `.user.ini`, the shim won't take effect until the cache expires. Wait 5 minutes, or contact nine support to reload PHP-FPM if you need it immediately.
- **WordPress multisite redirects to `wp-signup.php?new=origin-<domain>`** — the shim isn't restoring `HTTP_HOST`. WordPress multisite uses `HTTP_HOST` to select the site; if it sees `origin-<domain>`, it doesn't recognize it and redirects to signup. Verify the shim is loaded (see above) and that `X-Forwarded-Host` is present (set by the public vhost's `mod_proxy`, passed through by Anubis).
- **Cookies invalidated on every restart** — the JWT key file is missing or unreadable. Check `ED25519_PRIVATE_KEY_HEX_FILE` points to a 65-byte file (64 hex chars + newline) with mode 0600.
- **Service doesn't start after a reboot** — the user's systemd manager may not be running (lingering not enabled). `www-data` has lingering by default; a dedicated user created with `nine-manage-vhosts user create` also gets lingering enabled automatically. If lingering is missing, contact nine support to enable it for the user.
- **WARN log about `REDIRECT_DOMAINS` not set** — expected. Anubis warns at startup if `REDIRECT_DOMAINS` is unset (it will accept redirects to any domain). For a single-domain setup this is harmless; set it to lock down which domains Anubis will redirect to (e.g., `REDIRECT_DOMAINS=example.com,www.example.com`).
- **Domain is behind Cloudflare or another CDN** — fine. The CDN proxies to the nine server, which proxies to Anubis. Anubis sees the CDN's IP as `X-Real-Ip` (set by the public vhost). The CDN may also do its own bot filtering — both layers operate independently. If you see a "Just a moment..." page instead of Anubis's challenge, that's Cloudflare's challenge, not Anubis's.
- **WordPress behind Anubis** — WordPress works behind Anubis with the origin fixups in place. The shim restores `HTTP_HOST` so WordPress, Yoast SEO, and other plugins generate correct canonical URLs. If URLs in the HTML point to `origin-<domain>` instead of the public domain, the shim isn't loaded — check `.user.ini`. If Wordfence WAF is installed, its `auto_prepend_file` must be chained (see "Migrating an existing domain" step 8).

## References

- [Anubis docs](https://anubis.techaro.lol/docs/admin/) (note: the docs site is itself Anubis-protected)
- [Anubis GitHub](https://github.com/TecharoHQ/anubis)
- [nine-manage-vhosts docs](https://docs.nine.ch/docs/managed-server-services/webserver/nine-manage-vhosts/manage-virtualhosts-with-nine-manage-vhosts/)
- [nine systemd user daemons](https://docs.nine.ch/docs/managed-server-services/applications/manage-daemons-as-a-user-with-systemd/)
- [nine bot blocking (pre-Anubis `.htaccess` approach)](https://docs.nine.ch/docs/managed-server-services/webserver/blocking-bot-requests/)
- Origin dance necessity research: `docs/research/origin-dance-necessity.md`
- Policy defaults fact report: `docs/research/policy-defaults-facts.md`
- Minimal config prototype: `docs/prototype/minimal-config-draft.md`
