# Dokploy Deployment Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Kickflip deploy cleanly on a Dokploy server where Dokploy/Traefik already owns subdomain routing and host ports 80/443.

**Architecture:** Keep Kickflip's internal nginx and daemon unchanged for the first pass, but run them behind Dokploy's Traefik edge. Traefik terminates public HTTPS for `tunnels.example.com` and `*.tunnels.example.com`, forwards all HTTP traffic to Kickflip's internal nginx on port 80, and the Kickflip SSH tunnel endpoint remains directly published on host port 2222.

**Tech Stack:** Rust CLI/server, Docker Compose, Dokploy, Traefik v3 Docker labels, Let's Encrypt wildcard certificates via DNS-01.

---

## Research Conclusions To Preserve

- Kickflip's current Docker Compose publishes `80:80`, `443:443`, `2222:2222`, and `8080:8080`; this conflicts with Dokploy because Traefik already owns host `80/443`.
- Kickflip's server image already runs internal nginx, sshd on `2222`, and the daemon on `8080`; Dokploy should route to the internal nginx port `80`, not directly to the daemon.
- For Dokploy mode, Kickflip should use `auto_cert = false`, `tls_enable = false`, and `http_redirect = false`; Traefik owns TLS and redirects at the edge.
- Use client protocol `http` even though the public URL is HTTPS, because public HTTPS is terminated by Traefik before traffic reaches Kickflip's internal nginx.
- A wildcard tunnel domain such as `*.tunnels.example.com` needs a wildcard TLS certificate. Let's Encrypt wildcard certs require DNS-01 validation, so Dokploy/Traefik must already have a DNS challenge resolver or a manually installed wildcard certificate.
- Use a dedicated tunnel base domain such as `tunnels.example.com` to avoid stealing app subdomains already managed by Dokploy.

## File Structure

- Create `docker-compose.dokploy.yml`: Dokploy-ready Compose template that avoids host `80/443/8080`, publishes only `2222/tcp`, joins `dokploy-network`, and includes Traefik labels for root and wildcard tunnel hostnames.
- Create `docs/deploy-dokploy.md`: Operator guide covering DNS, wildcard certificate resolver, Dokploy setup, config file, client setup, validation, and troubleshooting.
- Modify `README.md`: Add a short Dokploy deployment pointer near Docker/manual setup.
- Modify `crates/server/src/main.rs`: Make client-management commands resolve the clients directory from `--clients-dir`, `KICKFLIP_CLIENTS_DIR`, or `KICKFLIP_SERVER_CONFIG` so `add-client`, `list-clients`, `remove-client`, and `tui` work inside the Dokploy container without repeating flags.
- Test in `crates/server/src/main.rs`: Add unit tests for clients directory resolution precedence.

---

### Task 1: Add Dokploy Compose Template

**Files:**
- Create: `docker-compose.dokploy.yml`

- [ ] **Step 1: Add the Dokploy Compose file**

Create `docker-compose.dokploy.yml` with this exact content:

```yaml
# Kickflip on Dokploy
#
# Required Dokploy environment variables:
#   KICKFLIP_DOMAIN=tunnels.example.com
#   KICKFLIP_ACME_RESOLVER=letsencrypt
#
# DNS:
#   tunnels.example.com   -> Dokploy server IP
#   *.tunnels.example.com -> Dokploy server IP

services:
  kickflip:
    image: ghcr.io/jb-san/kickflip-server:latest
    restart: unless-stopped

    environment:
      KICKFLIP_SERVER_CONFIG: /etc/kickflip/kickflip-server.toml
      KICKFLIP_CLIENTS_DIR: /etc/kickflip/clients.d

    volumes:
      - ./config:/etc/kickflip
      - kickflip-letsencrypt:/etc/letsencrypt
      - kickflip-nginx-sites:/etc/nginx/sites-available
      - kickflip-nginx-enabled:/etc/nginx/sites-enabled
      - kickflip-acme-webroot:/var/www/letsencrypt

    expose:
      - "80"
      - "8080"

    ports:
      - "2222:2222/tcp"

    networks:
      - dokploy-network

    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=dokploy-network"
      - "traefik.http.routers.kickflip.rule=Host(`${KICKFLIP_DOMAIN:-tunnels.example.com}`) || Host(`*.${KICKFLIP_DOMAIN:-tunnels.example.com}`)"
      - "traefik.http.routers.kickflip.entrypoints=websecure"
      - "traefik.http.routers.kickflip.tls=true"
      - "traefik.http.routers.kickflip.tls.certresolver=${KICKFLIP_ACME_RESOLVER:-letsencrypt}"
      - "traefik.http.routers.kickflip.tls.domains[0].main=${KICKFLIP_DOMAIN:-tunnels.example.com}"
      - "traefik.http.routers.kickflip.tls.domains[0].sans=*.${KICKFLIP_DOMAIN:-tunnels.example.com}"
      - "traefik.http.services.kickflip.loadbalancer.server.port=80"

    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s

networks:
  dokploy-network:
    external: true

volumes:
  kickflip-letsencrypt:
  kickflip-nginx-sites:
  kickflip-nginx-enabled:
  kickflip-acme-webroot:
```

- [ ] **Step 2: Validate Compose syntax**

Run:

```bash
KICKFLIP_DOMAIN=tunnels.example.com \
KICKFLIP_ACME_RESOLVER=letsencrypt \
docker compose -f docker-compose.dokploy.yml config >/tmp/kickflip-dokploy-compose.yml
```

Expected: command exits `0` and `/tmp/kickflip-dokploy-compose.yml` contains no published `80`, `443`, or `8080` ports.

- [ ] **Step 3: Verify only SSH is host-published**

Run:

```bash
KICKFLIP_DOMAIN=tunnels.example.com \
KICKFLIP_ACME_RESOLVER=letsencrypt \
docker compose -f docker-compose.dokploy.yml config | rg -n 'published:|target:'
```

Expected output includes `published: "2222"` and `target: 2222`, and does not include `published: "80"`, `published: "443"`, or `published: "8080"`.

- [ ] **Step 4: Commit the Compose template**

```bash
git add docker-compose.dokploy.yml
git commit -m "feat: add Dokploy compose template"
```

---

### Task 2: Add Dokploy Deployment Documentation

**Files:**
- Create: `docs/deploy-dokploy.md`
- Modify: `README.md`

- [ ] **Step 1: Create the Dokploy deployment guide**

Create `docs/deploy-dokploy.md` with this exact structure and content:

````markdown
# Deploy Kickflip on Dokploy

This guide is for a Dokploy server where Dokploy's Traefik already owns public ports `80` and `443`.

## Architecture

```text
Internet HTTPS
  -> Dokploy Traefik :443
  -> kickflip internal nginx :80
  -> SSH reverse tunnel ports inside the kickflip container

Client SSH tunnel
  -> tunnels.example.com:2222
  -> kickflip sshd :2222
```

Kickflip does not publish host `80`, `443`, or `8080` in this mode. Dokploy routes HTTP/S traffic to Kickflip over the `dokploy-network` Docker network.

## DNS

Use a dedicated tunnel base domain:

```text
tunnels.example.com      A/AAAA  203.0.113.10
*.tunnels.example.com    A/AAAA  203.0.113.10
```

Replace `203.0.113.10` with the public IP address of the Dokploy server. Do not use `*.example.com` if Dokploy is already routing application subdomains under `example.com`.

## TLS

Traefik terminates TLS. Configure Dokploy/Traefik with a wildcard-capable certificate for:

```text
tunnels.example.com
*.tunnels.example.com
```

Let's Encrypt wildcard certificates require DNS-01 validation. HTTP-01 validation is not enough for `*.tunnels.example.com`.

## Kickflip Config

Create `config/kickflip-server.toml` in the Dokploy compose project:

```toml
rp_id = "tunnels.example.com"
clients_dir = "/etc/kickflip/clients.d"
socket = "/tmp/kickflip.sock"

nginx_available = "/etc/nginx/sites-available"
nginx_enabled = "/etc/nginx/sites-enabled"

acme_webroot = "/var/www/letsencrypt"
acme_email = ""
auto_cert = false

tls_enable = false
tls_cert = ""
tls_key = ""
http_redirect = false
hsts_enable = false
hsts_max_age = 31536000

ssh_user = "kickflip"
authorized_keys = "/home/kickflip/.ssh/authorized_keys"
```

## Dokploy Compose

Use `docker-compose.dokploy.yml`.

Set these environment variables in Dokploy:

```text
KICKFLIP_DOMAIN=tunnels.example.com
KICKFLIP_ACME_RESOLVER=letsencrypt
```

If your Traefik resolver has a different name, set `KICKFLIP_ACME_RESOLVER` to that resolver name.

## Firewall

Open TCP port `2222` on the Dokploy host. Keep Dokploy/Traefik on ports `80` and `443`.

## Add A Client

On the client:

```bash
kickflip-client setup
kickflip-client get-pub-key
```

Use these setup values:

```text
Server URL: https://tunnels.example.com
SSH user: kickflip
SSH port: 2222
```

On the Dokploy server:

```bash
docker compose exec kickflip kickflip-server add-client \
  --pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host" \
  --name "my-laptop"
```

## Connect

On the client:

```bash
kickflip-client connect http --subdomain myapp -p 3000
```

Open:

```text
https://myapp.tunnels.example.com
```

Use `http` in the client command. Public HTTPS is handled by Traefik; Kickflip receives plain HTTP inside the Docker network.

## Validate

From the Dokploy host:

```bash
docker compose exec kickflip curl -sf http://localhost:8080/health
docker compose exec kickflip nginx -t
ssh -p 2222 kickflip@tunnels.example.com
```

The SSH command should authenticate only for registered client keys and should not open a shell.

From a public network:

```bash
curl -I https://tunnels.example.com/health
curl -I https://myapp.tunnels.example.com
```

## Troubleshooting

- `bind: address already in use` for `80` or `443`: the regular `docker-compose.yml` was deployed instead of `docker-compose.dokploy.yml`.
- Browser certificate warning for tunnel subdomains: Traefik does not have a wildcard certificate for `*.tunnels.example.com`.
- Client connects to API but SSH fails: TCP `2222` is blocked by the firewall, DNS provider proxy, or cloud security group.
- `add-client` writes to `clients.d` instead of `/etc/kickflip/clients.d`: update to a build that includes config-aware client-management commands, or pass `--clients-dir /etc/kickflip/clients.d`.
- `https` protocol in `kickflip-client connect` fails: use `http`; Traefik owns public HTTPS in Dokploy mode.
````

- [ ] **Step 2: Add a README pointer**

In `README.md`, after the Docker-ready bullet or before Manual Setup, add:

```markdown
### Deploy on Dokploy

Dokploy already owns host ports `80` and `443` through Traefik. Use the dedicated Dokploy guide instead of the default Compose file:

- [Deploy Kickflip on Dokploy](docs/deploy-dokploy.md)
```

- [ ] **Step 3: Verify Markdown links**

Run:

```bash
rg -n "deploy-dokploy|Dokploy" README.md docs/deploy-dokploy.md
```

Expected: output shows the README link and the guide headings.

- [ ] **Step 4: Commit the docs**

```bash
git add README.md docs/deploy-dokploy.md
git commit -m "docs: add Dokploy deployment guide"
```

---

### Task 3: Make Server Client Commands Config-Aware

**Files:**
- Modify: `crates/server/src/main.rs`

- [ ] **Step 1: Align config and clients_dir CLI defaults**

In `crates/server/src/main.rs`, change the `config` field default from `config.toml` to the filename used by the README and Docker image:

```rust
    /// Configuration file path
    #[arg(short, long, default_value = "kickflip-server.toml")]
    config: String,
```

Then change the `clients_dir` field in `Cli` from a defaulted `PathBuf` to an optional CLI override:

```rust
    /// Clients directory (allow-list)
    #[arg(long)]
    clients_dir: Option<PathBuf>,
```

- [ ] **Step 2: Add helper functions after `main` or before `main`**

Add these helpers:

```rust
fn config_path(cli: &Cli) -> String {
    std::env::var("KICKFLIP_SERVER_CONFIG").unwrap_or_else(|_| cli.config.clone())
}

fn default_clients_dir() -> PathBuf {
    PathBuf::from("clients.d")
}

fn resolve_clients_dir(cli_clients_dir: Option<&PathBuf>, cli_config: &str) -> PathBuf {
    resolve_clients_dir_from_env(
        cli_clients_dir,
        cli_config,
        std::env::var("KICKFLIP_CLIENTS_DIR").ok(),
        std::env::var("KICKFLIP_SERVER_CONFIG").ok(),
    )
}

fn resolve_clients_dir_from_env(
    cli_clients_dir: Option<&PathBuf>,
    cli_config: &str,
    env_clients_dir: Option<String>,
    env_config_path: Option<String>,
) -> PathBuf {
    if let Some(path) = cli_clients_dir {
        return path.clone();
    }

    if let Some(path) = env_clients_dir {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    let config_path = env_config_path.unwrap_or_else(|| cli_config.into());
    if let Ok(cfg) = ServerConfig::load_path(config_path) {
        return cfg.clients_dir;
    }

    default_clients_dir()
}
```

- [ ] **Step 3: Use `config_path` for configure/start**

Replace both manual config path lookups:

```rust
let path = std::env::var("KICKFLIP_SERVER_CONFIG")
    .unwrap_or_else(|_| "kickflip-server.toml".into());
```

with:

```rust
let path = config_path(&cli);
```

- [ ] **Step 4: Use resolved clients dir in `Start` fallback**

In the `Start` branch where no config file is loaded, replace:

```rust
clients_dir = cli.clients_dir.to_string_lossy().to_string();
```

with:

```rust
clients_dir = resolve_clients_dir(cli.clients_dir.as_ref(), &cli.config)
    .to_string_lossy()
    .to_string();
```

- [ ] **Step 5: Use resolved clients dir in management commands**

At the top of each management command branch that needs client files, add:

```rust
let clients_dir = resolve_clients_dir(cli.clients_dir.as_ref(), &cli.config);
```

Then update:

```rust
ensure_dir(&cli.clients_dir).expect("create clients dir");
let out_path = cli.clients_dir.join(filename);
```

to:

```rust
ensure_dir(&clients_dir).expect("create clients dir");
let out_path = clients_dir.join(filename);
```

Update `RemoveClient`, `ListClients`, and `Tui` the same way:

```rust
let path = clients_dir.join(fname);
match fs::read_dir(&clients_dir) {
    Ok(entries) => { /* existing body */ }
    Err(_) => println!("(empty) {}", clients_dir.display()),
}
if let Err(e) = tui::run(&cli.socket, &clients_dir) {
    eprintln!("tui error: {}", e);
}
```

- [ ] **Step 6: Run formatting**

Run:

```bash
cargo fmt
```

Expected: command exits `0`.

---

### Task 4: Add Tests For Client Directory Resolution

**Files:**
- Modify: `crates/server/src/main.rs`

- [ ] **Step 1: Add unit tests at the bottom of `crates/server/src/main.rs`**

Add this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_clients_dir_prefers_cli_value() {
        let cli_value = PathBuf::from("/cli/clients");
        let resolved = resolve_clients_dir_from_env(
            Some(&cli_value),
            "missing.toml",
            Some("/env/clients".into()),
            None,
        );

        assert_eq!(resolved, PathBuf::from("/cli/clients"));
    }

    #[test]
    fn resolve_clients_dir_uses_env_value() {
        let resolved =
            resolve_clients_dir_from_env(None, "missing.toml", Some("/env/clients".into()), None);

        assert_eq!(resolved, PathBuf::from("/env/clients"));
    }

    #[test]
    fn resolve_clients_dir_uses_config_value() {
        let dir = tempdir().expect("tempdir");
        let config_path = dir.path().join("kickflip-server.toml");
        let clients_dir = dir.path().join("clients.d");
        let cfg = ServerConfig {
            clients_dir: clients_dir.clone(),
            ..ServerConfig::default()
        };
        cfg.save_path(&config_path).expect("save config");

        let resolved = resolve_clients_dir_from_env(
            None,
            "missing.toml",
            None,
            Some(config_path.to_str().expect("utf8 path").into()),
        );

        assert_eq!(resolved, clients_dir);
    }

    #[test]
    fn resolve_clients_dir_falls_back_to_default() {
        let resolved = resolve_clients_dir_from_env(None, "missing.toml", None, None);

        assert_eq!(resolved, PathBuf::from("clients.d"));
    }
}
```

- [ ] **Step 2: Run the new tests**

Run:

```bash
cargo test -p kickflip-server resolve_clients_dir -- --test-threads=1
```

Expected: all four `resolve_clients_dir_*` tests pass.

- [ ] **Step 3: Run server tests**

Run:

```bash
cargo test -p kickflip-server
```

Expected: all server tests pass.

- [ ] **Step 4: Commit the CLI fix**

```bash
git add crates/server/src/main.rs
git commit -m "fix: resolve client directory from server config"
```

---

### Task 5: Validate End-To-End Dokploy Mode Locally

**Files:**
- No source edits expected unless validation finds a bug.

- [ ] **Step 1: Build the server image**

Run:

```bash
docker build -f Dockerfile.server -t kickflip-server:dokploy-test .
```

Expected: image builds successfully.

- [ ] **Step 2: Run Compose config validation against local image**

Temporarily override the image in a generated config, without editing the repo file:

```bash
KICKFLIP_DOMAIN=tunnels.example.com \
KICKFLIP_ACME_RESOLVER=letsencrypt \
docker compose -f docker-compose.dokploy.yml config >/tmp/kickflip-dokploy-compose.yml
```

Expected: command exits `0`.

- [ ] **Step 3: Verify HTTP/S ports are not published**

Run:

```bash
rg -n 'published: "(80|443|8080)"' /tmp/kickflip-dokploy-compose.yml
```

Expected: no matches.

- [ ] **Step 4: Verify SSH port is published**

Run:

```bash
rg -n 'published: "2222"|target: 2222' /tmp/kickflip-dokploy-compose.yml
```

Expected: both `published: "2222"` and `target: 2222` are present.

- [ ] **Step 5: Run the full Rust test suite**

Run:

```bash
cargo test --all
```

Expected: all workspace tests pass.

- [ ] **Step 6: Confirm no validation-only edits remain**

Run:

```bash
git status --short
```

Expected: no uncommitted changes from Task 5. If validation revealed a bug, return to the task that owns the affected file, update that task's implementation, rerun verification, and commit under that task's commit message.

---

## Implementation Notes

- Do not replace Kickflip's nginx routing in this pass. The internal nginx remains useful because Kickflip already generates per-subdomain nginx configs pointing to the allocated reverse SSH ports.
- Do not expose Kickflip's daemon port `8080` publicly in Dokploy. The root domain reaches it through internal nginx.
- Do not enable Kickflip `auto_cert` in Dokploy mode. Dynamic certbot inside the Kickflip container competes with Traefik and cannot solve wildcard TLS for every tunnel subdomain.
- If a Dokploy install uses a non-default network name, the operator must change both `dokploy-network` references in `docker-compose.dokploy.yml`.

## Self-Review

- Spec coverage: The plan covers Dokploy coexistence with existing subdomain routing, edge TLS, wildcard routing, direct SSH tunnel access, operator docs, and repo hardening for client management.
- Placeholder scan: The plan uses concrete sample domain `tunnels.example.com`, documentation IP `203.0.113.10`, concrete filenames, concrete commands, and concrete expected outcomes. There are no `TBD` or deferred implementation steps.
- Type consistency: The Rust helper signatures use `PathBuf`, `Option<&PathBuf>`, and existing `ServerConfig::load_path` consistently across tasks.
