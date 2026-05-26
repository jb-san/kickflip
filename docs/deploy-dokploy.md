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
