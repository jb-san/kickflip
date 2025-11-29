# Kickflip Quickstart Guide

A self-hosted ngrok alternative that exposes your local services to the internet via SSH reverse tunnels.

## Overview

```
┌─────────────────┐     HTTPS      ┌─────────────────────────────────────┐
│   The Internet  │ ─────────────▶ │           Your VPS                  │
│                 │                │  ┌─────────┐      ┌──────────────┐  │
│  myapp.example.com               │  │  nginx  │ ───▶ │ kickflip     │  │
│                 │                │  │ :80/443 │      │ daemon :8080 │  │
└─────────────────┘                │  └─────────┘      └──────────────┘  │
                                   │        ▲                │           │
                                   │        │           SSH tunnel       │
                                   │        │                │           │
                                   └────────│────────────────│───────────┘
                                            │                │
                                            │                ▼
                                   ┌────────│────────────────────────────┐
                                   │        │        Your Laptop         │
                                   │  ┌─────┴─────┐    ┌──────────────┐  │
                                   │  │ kickflip  │ ◀─ │  your app    │  │
                                   │  │  client   │    │  :3000       │  │
                                   │  └───────────┘    └──────────────┘  │
                                   └─────────────────────────────────────┘
```

---

## Part 1: DNS Configuration

**📍 Where:** Your domain registrar or DNS provider (e.g., Cloudflare, Route53, Namecheap)

You need to point a wildcard subdomain to your server. This allows any `*.example.com` to resolve to your VPS.

### Option A: Dedicated Subdomain (Recommended)

Use a subdomain like `*.t.example.com` so your tunnels appear as `myapp.t.example.com`:

| Type | Name  | Value              | TTL |
| ---- | ----- | ------------------ | --- |
| A    | `*.t` | `YOUR_SERVER_IP`   | 300 |
| AAAA | `*.t` | `YOUR_SERVER_IPV6` | 300 |

### Option B: Root Domain Wildcard

Use `*.example.com` directly so tunnels appear as `myapp.example.com`:

| Type | Name | Value              | TTL |
| ---- | ---- | ------------------ | --- |
| A    | `*`  | `YOUR_SERVER_IP`   | 300 |
| AAAA | `*`  | `YOUR_SERVER_IPV6` | 300 |

> **Note:** If using the root domain, you may want to also add a non-wildcard A record for `example.com` itself.

### Verify DNS

Wait a few minutes, then verify:

```bash
# Replace with your actual domain
dig +short test.t.example.com
# Should return your server IP
```

---

## Part 2: Server Setup

**📍 Where:** Your VPS/server (the machine with the public IP)

### Prerequisites

- A VPS with ports 22, 80, 443 open
- Docker and Docker Compose installed
- The DNS records from Part 1 configured

### Step 1: Create Project Directory

```bash
# SSH into your server
ssh root@YOUR_SERVER_IP

# Create kickflip directory
mkdir -p /opt/kickflip/config/clients.d
cd /opt/kickflip
```

### Step 2: Create Configuration File

```bash
cat > config/kickflip-server.toml << 'EOF'
# Your base domain (from DNS setup)
rp_id = "t.example.com"

# Directory containing allowed client public keys
clients_dir = "/etc/kickflip/clients.d"

# Unix socket for CLI communication
socket = "/tmp/kickflip.sock"

# Nginx directories
nginx_available = "/etc/nginx/sites-available"
nginx_enabled = "/etc/nginx/sites-enabled"

# Let's Encrypt settings
acme_webroot = "/var/www/letsencrypt"
acme_email = "admin@example.com"
auto_cert = true

# TLS settings
tls_enable = true
tls_cert = ""
tls_key = ""
http_redirect = true
hsts_enable = false
hsts_max_age = 31536000

# SSH tunnel user
ssh_user = "kickflip"
authorized_keys = "/home/kickflip/.ssh/authorized_keys"
EOF
```

**Important:** Replace:

- `t.example.com` with your actual domain from Part 1
- `admin@example.com` with your email for Let's Encrypt notifications

### Step 3: Create docker-compose.yml

```bash
cat > docker-compose.yml << 'EOF'
services:
  kickflip:
    # Use GitHub Container Registry:
    image: ghcr.io/jb-san/kickflip-server:latest
    # Or Docker Hub:
    # image: jbsan/kickflip-server:latest
    # Or build from source:
    # build:
    #   context: .
    #   dockerfile: Dockerfile.server
    container_name: kickflip-server
    restart: unless-stopped
    network_mode: host
    environment:
      - KICKFLIP_SERVER_CONFIG=/etc/kickflip/kickflip-server.toml
    volumes:
      - ./config:/etc/kickflip
      - letsencrypt:/etc/letsencrypt
      - nginx-sites:/etc/nginx/sites-available
      - nginx-enabled:/etc/nginx/sites-enabled
      - acme-webroot:/var/www/letsencrypt

volumes:
  letsencrypt:
  nginx-sites:
  nginx-enabled:
  acme-webroot:
EOF
```

### Step 4: Build and Start (if building from source)

```bash
# Clone the repository
git clone https://github.com/yourusername/kickflip.git /opt/kickflip-src
cd /opt/kickflip-src

# Copy your config
cp -r /opt/kickflip/config .

# Build and start
docker compose build
docker compose up -d
```

### Step 5: Verify Server is Running

```bash
# Check container status
docker compose ps

# Check logs
docker compose logs -f

# Check health endpoint
curl http://localhost:8080/health
```

---

## Part 3: Add a Client

**📍 Where:** Your server (still)

Before a client can connect, their public key must be added to the server's allow-list.

### Get Client's Public Key

On the **client machine** (your laptop), run:

```bash
# If not installed yet
curl -L https://github.com/yourusername/kickflip/releases/latest/download/kickflip-client-$(uname -s)-$(uname -m).tar.gz | tar xz
./kickflip-client setup
./kickflip-client get-pub-key
```

This outputs something like:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... kickflip@my-laptop
```

### Add Key to Server

On the **server**, add the client's public key:

```bash
docker compose exec kickflip kickflip-server add-client \
  --pubkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." \
  --name "my-laptop"
```

Or add directly to the clients directory:

```bash
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." > config/clients.d/my-laptop.pub
```

---

## Part 4: Client Setup

**📍 Where:** Your local machine (laptop/workstation)

### Step 1: Install kickflip-client

**macOS/Linux:**

```bash
# Download latest release
curl -L https://github.com/yourusername/kickflip/releases/latest/download/kickflip-client-$(uname -s)-$(uname -m).tar.gz | tar xz

# Move to PATH
sudo mv kickflip-client /usr/local/bin/
```

**Or build from source:**

```bash
git clone https://github.com/yourusername/kickflip.git
cd kickflip
cargo build --release -p kickflip-client
sudo cp target/release/kickflip-client /usr/local/bin/
```

### Step 2: Run Setup

```bash
kickflip-client setup
```

This will:

1. Generate an SSH key (`~/.ssh/kickflip`) if needed
2. Prompt for your server URL (e.g., `https://t.example.com:8080`)
3. Prompt for the SSH user (default: `kickflip`)

Configuration is saved to `~/.kickflip.toml`.

### Step 3: Share Your Public Key

After setup, get your public key:

```bash
kickflip-client get-pub-key
```

Send this to whoever manages the server (or add it yourself per Part 3).

---

## Part 5: Connect!

**📍 Where:** Your local machine

### Start Your Local Service

```bash
# Example: start a local web server on port 3000
python3 -m http.server 3000
# or
npm start  # for a Node.js app
```

### Create a Tunnel

```bash
# Expose local port 3000 as myapp.t.example.com
kickflip-client connect http --subdomain myapp --port 3000
```

You should see:

```
🔗 Connecting to https://t.example.com:8080
   Subdomain: myapp.t.example.com
   Local port: 3000
✅ Tunnel established!
   Public URL: https://myapp.t.example.com
```

### Test It

Open your browser and visit `https://myapp.t.example.com` - you should see your local app!

### Disconnect

```bash
kickflip-client disconnect
```

---

## Command Reference

### Server Commands

```bash
# Start server
docker compose up -d

# Stop server
docker compose down

# View logs
docker compose logs -f

# Check status
docker compose exec kickflip kickflip-server status

# Add a client
docker compose exec kickflip kickflip-server add-client --pubkey "ssh-ed25519 ..." --name "client-name"

# List clients
docker compose exec kickflip kickflip-server list-clients

# Remove a client
docker compose exec kickflip kickflip-server remove-client --key-id "SHA256:..."

# Launch TUI dashboard
docker compose exec -it kickflip kickflip-server tui
```

### Client Commands

```bash
# Initial setup
kickflip-client setup

# Show public key
kickflip-client get-pub-key

# Connect (HTTP/HTTPS)
kickflip-client connect http --subdomain myapp --port 3000
kickflip-client connect https --subdomain myapp --port 3000

# Connect (raw TCP port)
kickflip-client connect 8080 --subdomain myapp --port 3000

# Disconnect all tunnels
kickflip-client disconnect
```

---

## Troubleshooting

### "Connection refused" on client

1. Check the server is running: `docker compose ps`
2. Verify firewall allows ports 22, 80, 443, 8080
3. Check your DNS is resolving: `dig +short myapp.t.example.com`

### "Unauthorized" or "key mismatch"

1. Make sure your public key is added to the server
2. Check the key ID matches: `kickflip-client get-pub-key`
3. On server: `docker compose exec kickflip kickflip-server list-clients`

### SSL certificate errors

1. Ensure DNS is correctly configured and propagated
2. Check certbot can reach the ACME challenge: `curl http://myapp.t.example.com/.well-known/acme-challenge/test`
3. View certbot logs: `docker compose exec kickflip cat /var/log/letsencrypt/letsencrypt.log`

### SSH tunnel fails

1. Check SSH is running in container: `docker compose exec kickflip pgrep sshd`
2. Test SSH directly: `ssh -i ~/.ssh/kickflip kickflip@t.example.com -p 22`
3. Check authorized_keys: `docker compose exec kickflip cat /home/kickflip/.ssh/authorized_keys`

---

## Configuration Reference

### Server Config (`kickflip-server.toml`)

| Key               | Description                        | Default                               |
| ----------------- | ---------------------------------- | ------------------------------------- |
| `rp_id`           | Base domain for subdomains         | `localhost`                           |
| `clients_dir`     | Directory with allowed client keys | `clients.d`                           |
| `socket`          | Unix socket path for CLI           | `/tmp/kickflip.sock`                  |
| `nginx_available` | Nginx sites-available path         | `/etc/nginx/sites-available`          |
| `nginx_enabled`   | Nginx sites-enabled path           | `/etc/nginx/sites-enabled`            |
| `acme_webroot`    | Let's Encrypt challenge directory  | `/var/www/letsencrypt`                |
| `acme_email`      | Email for Let's Encrypt            | (empty)                               |
| `auto_cert`       | Auto-obtain SSL certs              | `true`                                |
| `tls_enable`      | Enable HTTPS                       | `true`                                |
| `tls_cert`        | Custom TLS cert path               | (auto from Let's Encrypt)             |
| `tls_key`         | Custom TLS key path                | (auto from Let's Encrypt)             |
| `http_redirect`   | Redirect HTTP→HTTPS                | `true`                                |
| `hsts_enable`     | Enable HSTS header                 | `false`                               |
| `hsts_max_age`    | HSTS max-age seconds               | `31536000`                            |
| `ssh_user`        | SSH user for tunnels               | `kickflip`                            |
| `authorized_keys` | SSH authorized_keys path           | `/home/kickflip/.ssh/authorized_keys` |

### Client Config (`~/.kickflip.toml`)

| Key          | Description             | Default                  |
| ------------ | ----------------------- | ------------------------ |
| `server_url` | Kickflip server API URL | `https://localhost:8080` |
| `ssh_user`   | SSH user for tunnels    | `kickflip`               |

---

## Security Notes

1. **Client keys are allow-listed** - Only keys in `clients.d/` can connect
2. **SSH is restricted** - The kickflip user cannot get a shell, only tunnel
3. **Automatic HTTPS** - SSL certs are obtained automatically via Let's Encrypt
4. **No root required on client** - Client runs entirely in userspace

---

## Architecture

Kickflip consists of three components:

1. **kickflip-server** - CLI for managing the server (add/remove clients, start daemon)
2. **daemon** - Background service handling API requests and nginx configuration
3. **kickflip-client** - CLI for connecting tunnels from your local machine

The flow is:

1. Client calls `/connect` API with subdomain and key ID
2. Server returns a challenge
3. Client signs challenge with private key
4. Client calls `/auth` API with signature
5. Server verifies signature, generates nginx config, obtains SSL cert
6. Client opens SSH reverse tunnel to allocated port
7. nginx proxies `subdomain.rp_id` to the tunnel port
