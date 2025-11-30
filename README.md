# kickflip

Selfhosted ngrok alternative with **automatic SSL certificates**.

Based on [Roll your own Ngrok with Nginx, Letsencrypt, and SSH reverse tunnelling](https://jerrington.me/posts/2019-01-29-self-hosted-ngrok.html)

## Features

- **Automatic SSL** - Certificates obtained via Let's Encrypt when clients connect
- **Zero-config subdomains** - Just connect and your subdomain is live
- **SSH key authentication** - Secure client verification with ed25519 keys
- **Terminal UI** - Monitor connections and clients in real-time
- **Docker-ready** - Easy deployment with docker-compose

## Quick Install

### Install Client (macOS/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/jb-san/kickflip/main/scripts/install-client.sh | bash
```

This will:

- Download the correct binary for your platform
- Install to `/usr/local/bin/kickflip-client`
- Optionally add a `kf` alias

### Install Server (Docker)

```bash
curl -fsSL https://raw.githubusercontent.com/jb-san/kickflip/main/scripts/install-server.sh | bash
```

This will:

- Download docker-compose.yml to `/opt/kickflip`
- Create config in `/etc/kickflip`
- Guide you through configuration
- Optionally add a `kfs` alias for server management

## Manual Setup

### Prerequisites

- A server with ports 80, 443, and 2222 open
- A domain with wildcard DNS pointing to your server:
  - `tunnels.yourdomain.com` → your server IP (A record)
  - `*.tunnels.yourdomain.com` → your server IP (A record or CNAME to above)

### 1. On the server

```bash
# Download docker-compose file
curl -O https://raw.githubusercontent.com/jb-san/kickflip/main/docker-compose.yml

# Create config directory
mkdir -p config/clients.d

# Create config file (edit values for your domain)
cat > config/kickflip-server.toml << 'EOF'
rp_id = "tunnels.yourdomain.com"
clients_dir = "/etc/kickflip/clients.d"
acme_email = "you@example.com"
auto_cert = true
tls_enable = true
EOF

# Start the server
docker compose up -d

# Check status
docker compose exec kickflip kickflip-server status
```

### 2. On the client

```bash
# Install (or download binary from releases)
curl -fsSL https://raw.githubusercontent.com/jb-san/kickflip/main/scripts/install-client.sh | bash

# Setup client (generates SSH key)
kickflip-client setup
# Enter server URL: https://tunnels.yourdomain.com

# Show your public key
kickflip-client get-pub-key
```

### 3. On the server - add the client

```bash
docker compose exec kickflip kickflip-server add-client \
  --pubkey "ssh-ed25519 AAAAC3NzaC1lZ..." \
  --name "my-laptop"
```

### 4. On the client - connect!

```bash
# Expose local port 3000 at myapp.tunnels.yourdomain.com
kickflip-client connect http --subdomain myapp -p 3000
```

The server will **automatically obtain an SSL certificate** for `myapp.tunnels.yourdomain.com` on first connection.

---

## Quickstart (Docker - Manual)

<details>
<summary>Click to expand manual Docker commands</summary>

1. On the server:

```bash
docker run --rm -it \
  -v /etc/kickflip:/etc/kickflip \
  -v /etc/nginx:/etc/nginx \
  -v /var/www/letsencrypt:/var/www/letsencrypt \
  -v /etc/letsencrypt:/etc/letsencrypt \
  --name kickflip-setup \
  kickflip-server:local configure

# Start the server
docker run -d \
  --name kickflip-server \
  -v /etc/kickflip:/etc/kickflip \
  -v /etc/nginx:/etc/nginx \
  -v /var/www/letsencrypt:/var/www/letsencrypt \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -e KICKFLIP_SERVER_CONFIG=/etc/kickflip/kickflip-server.toml \
  --network host \
  kickflip-server:local start
```

2. On the client:

```bash
docker run --rm -it \
  -v $HOME/.ssh:/root/.ssh:ro \
  kickflip-client:local setup

docker run --rm -it \
  -v $HOME/.ssh:/root/.ssh:ro \
  kickflip-client:local get-pub-key
```

3. On the server:

```bash
docker exec kickflip-server kickflip-server add-client \
  --pubkey "ssh-ed25519 AAAA... user@host" \
  --name "dev-laptop"
```

4. On the client:

```bash
docker run --rm -it \
  -v $HOME/.ssh:/root/.ssh:ro \
  kickflip-client:local connect http --subdomain app -p 3000
```

</details>

## Server

- Configure (interactive):
  - Checks for nginx/sshd/certbot, prompts for domain (rpId), ACME webroot and HTTPS/redirect.
  - Creates ACME webroot, prints DNS guidance, can optionally run certbot for a test subdomain.

```bash
kickflip-server configure
```

- Start daemon (spawns `daemon` with flags):

```bash
kickflip-server start \
  --rp-id example.com \
  --clients-dir ./clients.d \
  --nginx-available /etc/nginx/sites-available \
  --nginx-enabled /etc/nginx/sites-enabled \
  --acme-webroot /var/www/letsencrypt \
  --tls-enable true \
  --http-redirect true \
  --hsts-enable false
```

Note: after running `kickflip-server configure`, settings are saved to `kickflip-server.toml`. Then you can simply run:

```bash
kickflip-server start
```

You can override the config path with the `KICKFLIP_SERVER_CONFIG` environment variable.

- Manage clients (allow-list in `clients.d`):

```bash
# Add a client (OpenSSH pubkey line)
kickflip-server add-client --pubkey "ssh-ed25519 AAAA... user@host" --name "dev-laptop"

# List clients
kickflip-server list-clients

# Remove by fingerprint (key_id)
kickflip-server remove-client --key-id SHA256:abcdef...
```

- Daemon control via Unix socket:

```bash
kickflip-server status
kickflip-server stop
```

- Terminal UI for monitoring and management:

```bash
kickflip-server tui
```

The TUI provides:

- **Dashboard**: Live view of active connections with auto-refresh
- **Clients**: List of registered client public keys
- **Help**: Keyboard shortcuts and CLI command reference

Keyboard shortcuts:

- `Tab` / `→` / `←` - Switch tabs
- `↑` / `↓` / `j` / `k` - Navigate rows
- `1` / `2` / `3` - Jump to Dashboard / Clients / Help
- `r` - Refresh data
- `q` / `Esc` - Quit

- Environment:
  - `KICKFLIP_SKIP_NGINX_RELOAD=1` to skip `nginx -s reload` (useful in tests/local dev).

## Client

- Setup (generates `~/.ssh/kickflip` if missing, stores server URL):

```bash
kickflip-client setup
```

- Show your public key to add on the server:

```bash
kickflip-client get-pub-key
```

- Connect:
  - Performs JSON challenge flow, derives `key_id` from `~/.ssh/kickflip.pub`, signs the canonical challenge, then opens the reverse tunnel with `ssh -N -R` automatically.

```bash
kickflip-client connect http --subdomain app -p 3000
```

## Docker

### Build images

```bash
scripts/docker.sh             # tags images as :local
# or
scripts/docker.sh v0.1.0
```

### Run server container

The server image contains both `kickflip-server` and `daemon`.

First run configure (interactive) and persist config and nginx dirs:

```bash
docker run --rm -it \
  -v /etc/kickflip:/etc/kickflip \
  -v /etc/nginx:/etc/nginx \
  -v /var/www/letsencrypt:/var/www/letsencrypt \
  --name kickflip-setup \
  kickflip-server:local configure

# Copy config to /etc/kickflip/kickflip-server.toml inside the mount
```

Then start the daemon:

```bash
docker run -d \
  --name kickflip-server \
  -v /etc/kickflip:/etc/kickflip \
  -v /etc/nginx:/etc/nginx \
  -v /var/www/letsencrypt:/var/www/letsencrypt \
  -e KICKFLIP_SERVER_CONFIG=/etc/kickflip/kickflip-server.toml \
  --network host \
  kickflip-server:local start
```

Notes:

- `--network host` is recommended so the daemon binds to host ports and can reach sshd/nginx on localhost.
- Alternatively, publish ports and adjust nginx/upstreams accordingly (advanced).

### Run client container

Mount your SSH key directory so the client can sign and open tunnels:

```bash
docker run --rm -it \
  -v $HOME/.ssh:/root/.ssh:ro \
  kickflip-client:local setup

# Example connect
docker run --rm -it \
  -v $HOME/.ssh:/root/.ssh:ro \
  kickflip-client:local connect http --subdomain app -p 3000
```

## Development

### Prerequisites

- Rust toolchain (rustup, cargo): https://rustup.rs
- macOS/Linux recommended
- For running the server locally (optional):
  - nginx, sshd, certbot (e.g., on macOS via Homebrew: `brew install nginx openssh certbot`)

### Workspace layout

- `crates/client`: CLI for end users (`kickflip-client`)
- `crates/server`: Server CLI (`kickflip-server`) and daemon (`daemon`)
- `crates/proto`: Shared protocol models and helpers

### Build

```bash
# Build all crates
cargo build --all

# Build a specific crate
cargo build -p kickflip-server
cargo build -p kickflip-client
```

### Run

```bash
# Run server configure (interactive)
cargo run -p kickflip-server -- configure

# Start server daemon via CLI (uses saved config if present)
cargo run -p kickflip-server -- start

# Alternatively, run the daemon binary directly (advanced)
cargo run -p kickflip-server --bin daemon

# Client setup and connect
cargo run -p kickflip-client -- setup
cargo run -p kickflip-client -- connect http --subdomain app -p 3000
```

### Tests

```bash
# Run all tests in the workspace
cargo test --all

# Run only server tests
cargo test -p kickflip-server

# Run only proto tests
cargo test -p kickflip-proto
```

### Linting (optional)

```bash
# Run clippy lints (add nightly flags if desired)
cargo clippy --all -- -D warnings
```

## systemd templates (Linux)

Create a config directory/file first (generated by `kickflip-server configure`):

```bash
sudo mkdir -p /etc/kickflip
sudo cp kickflip-server.toml /etc/kickflip/kickflip-server.toml
```

Example unit to manage the daemon via the unified CLI (recommended):

```ini
# /etc/systemd/system/kickflip-server.service
[Unit]
Description=Kickflip server (nginx+ssh tunnel orchestrator)
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=root
Group=root
Environment=KICKFLIP_SERVER_CONFIG=/etc/kickflip/kickflip-server.toml
Environment=KICKFLIP_SKIP_NGINX_RELOAD=0
ExecStart=/usr/local/bin/kickflip-server start
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

If you prefer to run the daemon directly (advanced), pass flags explicitly:

```ini
# /etc/systemd/system/kickflip-daemon.service
[Unit]
Description=Kickflip server daemon (advanced)
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/daemon \
  --rp-id example.com \
  --clients-dir /etc/kickflip/clients.d \
  --nginx-available /etc/nginx/sites-available \
  --nginx-enabled /etc/nginx/sites-enabled \
  --acme-webroot /var/www/letsencrypt \
  --tls-enable true \
  --http-redirect true
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kickflip-server.service
sudo systemctl status kickflip-server.service
```
