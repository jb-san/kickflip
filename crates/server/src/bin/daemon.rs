use axum::{
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, info};

use chrono::{DateTime, Utc};
use clap::Parser;
use kickflip_proto::api::{
    AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, DisconnectRequest,
    DisconnectResponse,
};
use kickflip_proto::auth::Challenge;
use kickflip_proto::b64::{decode_url_nopad, encode_url_nopad};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Parser, Clone, Debug)]
struct DaemonArgs {
    /// Clients allow-list directory
    #[arg(long, default_value = "clients.d")]
    clients_dir: PathBuf,
    /// Nginx sites-available directory
    #[arg(long, default_value = "/etc/nginx/sites-available")]
    nginx_available: PathBuf,
    /// Nginx sites-enabled directory
    #[arg(long, default_value = "/etc/nginx/sites-enabled")]
    nginx_enabled: PathBuf,
    /// Nginx server_name base domain (rpId)
    #[arg(long, default_value = "localhost")]
    rp_id: String,
    /// Enable TLS server block and HTTPS redirect [true/false]
    #[arg(long, default_value = "true", num_args = 1)]
    tls_enable: bool,
    /// TLS cert (fullchain.pem). If unset, defaults to /etc/letsencrypt/live/<subdomain>.<rp_id>/fullchain.pem
    #[arg(long, default_value = "")]
    tls_cert: String,
    /// TLS key (privkey.pem). If unset, defaults to /etc/letsencrypt/live/<subdomain>.<rp_id>/privkey.pem
    #[arg(long, default_value = "")]
    tls_key: String,
    /// ACME webroot for /.well-known/acme-challenge
    #[arg(long, default_value = "/var/www/letsencrypt")]
    acme_webroot: PathBuf,
    /// Email for Let's Encrypt certificate notifications
    #[arg(long, default_value = "")]
    acme_email: String,
    /// Automatically obtain SSL certificates via certbot [true/false]
    #[arg(long, default_value = "true", num_args = 1)]
    auto_cert: bool,
    /// Redirect HTTP to HTTPS when TLS is enabled [true/false]
    #[arg(long, default_value = "true", num_args = 1)]
    http_redirect: bool,
    /// Enable HSTS header on HTTPS responses [true/false]
    #[arg(long, default_value = "false", num_args = 1)]
    hsts_enable: bool,
    /// HSTS max-age seconds
    #[arg(long, default_value_t = 31536000)]
    hsts_max_age: u32,
    /// API server bind address
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,
}

// Middleware to log HTTP requests
async fn log_requests(
    request: Request<axum::body::Body>, // Explicitly use axum::body::Body
    next: Next,                         // No generics, just Next
) -> Result<impl IntoResponse, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    debug!("Received HTTP request: {} {}", method, path);
    let response = next.run(request).await;
    info!("Responded: {} {} -> {}", method, path, response.status());
    Ok(response)
}

#[derive(Clone)]
struct AppState {
    inner: Arc<InnerState>,
}

struct InnerState {
    clients_dir: PathBuf,
    rp_id: String,
    nginx_available: PathBuf,
    nginx_enabled: PathBuf,
    tls_enable: bool,
    tls_cert: String,
    tls_key: String,
    acme_webroot: PathBuf,
    acme_email: String,
    auto_cert: bool,
    http_redirect: bool,
    hsts_enable: bool,
    hsts_max_age: u32,
    challenges: Mutex<HashMap<String, PendingChallenge>>, // challenge_id -> pending
    connections: Mutex<HashMap<String, ActiveConnection>>, // subdomain -> connection
    port_pool: Mutex<PortPool>,
}

struct PendingChallenge {
    key_id: String,
    challenge: Challenge,
    subdomain: String,
    reverse_port: u16,
    expires_at: Instant,
}

/// Tracks an active tunnel connection
#[derive(Clone, Debug)]
struct ActiveConnection {
    subdomain: String,
    key_id: String,
    reverse_port: u16,
    local_port: u16,
    connected_at: DateTime<Utc>,
}

/// Port pool for allocating and recycling reverse ports
struct PortPool {
    next_port: u16,
    available: HashSet<u16>,
    in_use: HashSet<u16>,
}

impl PortPool {
    fn new(start: u16) -> Self {
        Self {
            next_port: start,
            available: HashSet::new(),
            in_use: HashSet::new(),
        }
    }

    /// Allocate a port - reuse from available pool first, then increment
    fn allocate(&mut self) -> u16 {
        if let Some(&port) = self.available.iter().next() {
            self.available.remove(&port);
            self.in_use.insert(port);
            port
        } else {
            let port = self.next_port;
            self.next_port = self.next_port.saturating_add(1);
            self.in_use.insert(port);
            port
        }
    }

    /// Release a port back to the available pool
    fn release(&mut self, port: u16) {
        if self.in_use.remove(&port) {
            self.available.insert(port);
        }
    }

    /// Get count of active ports
    fn active_count(&self) -> usize {
        self.in_use.len()
    }
}

const CHALLENGE_TTL_SECS: u64 = 60;
const DEFAULT_REVERSE_PORT_START: u16 = 33000;

#[tokio::main]
async fn main() {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_env_filter("info") // Set to "debug" for more verbosity
        .init();
    info!("Starting daemon...");

    let args = DaemonArgs::parse();

    // Shared channel for shutdown signal
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

    // Spawn Unix socket listener for CLI control
    let socket_path = Path::new("/tmp/kickflip.sock");
    if socket_path.exists() {
        std::fs::remove_file(socket_path).unwrap();
    }
    let uds_listener = UnixListener::bind(socket_path).unwrap();
    info!("Unix socket listening at {:?}", socket_path);

    // Build app state
    let state = AppState {
        inner: Arc::new(InnerState {
            clients_dir: args.clients_dir.clone(),
            rp_id: args.rp_id.clone(),
            nginx_available: args.nginx_available.clone(),
            nginx_enabled: args.nginx_enabled.clone(),
            tls_enable: args.tls_enable,
            tls_cert: args.tls_cert.clone(),
            tls_key: args.tls_key.clone(),
            acme_webroot: args.acme_webroot.clone(),
            acme_email: args.acme_email.clone(),
            auto_cert: args.auto_cert,
            http_redirect: args.http_redirect,
            hsts_enable: args.hsts_enable,
            hsts_max_age: args.hsts_max_age,
            challenges: Mutex::new(HashMap::new()),
            connections: Mutex::new(HashMap::new()),
            port_pool: Mutex::new(PortPool::new(DEFAULT_REVERSE_PORT_START)),
        }),
    };

    // Spawn purge task for challenges
    let purge_state = state.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(5)).await;
            purge_expired_challenges(&purge_state);
        }
    });

    // Spawn control loop with state access for status
    let control_state = state.clone();
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        control_loop(uds_listener, shutdown_tx_clone, control_state).await;
    });

    // Build web app with routes and logging middleware
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/auth", post(auth_handler))
        .route("/connect", post(connect_handler))
        .route("/disconnect", post(disconnect_handler))
        .layer(middleware::from_fn(log_requests))
        .with_state(state);

    // Start HTTP server with axum::serve
    let addr: SocketAddr = args.bind.parse().unwrap_or_else(|_| {
        eprintln!("Invalid bind address: {}, using default", args.bind);
        SocketAddr::from(([127, 0, 0, 1], 8080))
    });
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("HTTP server listening on http://{}", addr);
    let server =
        axum::serve(listener, app.into_make_service()).with_graceful_shutdown(async move {
            shutdown_rx.recv().await;
            info!("Received shutdown signal, stopping...");
        });

    // Handle OS signals for clean shutdown (e.g., Ctrl+C)
    let mut sig_int = signal(SignalKind::interrupt()).unwrap();
    let mut sig_term = signal(SignalKind::terminate()).unwrap();
    tokio::select! {
        result = server => { result.unwrap(); },
        _ = sig_int.recv() => {
            info!("Received SIGINT, shutting down...");
            let _ = shutdown_tx.send(()).await;
        },
        _ = sig_term.recv() => {
            info!("Received SIGTERM, shutting down...");
            let _ = shutdown_tx.send(()).await;
        },
    }

    // Cleanup socket on exit
    if socket_path.exists() {
        std::fs::remove_file(socket_path).unwrap();
        info!("Cleaned up Unix socket {:?}", socket_path);
    }
    info!("Daemon stopped");
}

fn purge_expired_challenges(state: &AppState) {
    let mut guard = state.inner.challenges.lock().unwrap();
    let now = Instant::now();
    guard.retain(|_, p| p.expires_at > now);
}

async fn connect_handler(
    State(state): State<AppState>,
    Json(req): Json<ConnectRequest>,
) -> (StatusCode, Json<ConnectResponse>) {
    // Basic validation
    if req.subdomain.is_empty() || req.local_port == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ConnectResponse {
                challenge_id: String::new(),
                reverse_port: 0,
                challenge: String::new(),
            }),
        );
    }

    // Check if subdomain is already connected
    {
        let connections = state.inner.connections.lock().unwrap();
        if connections.contains_key(&req.subdomain) {
            return (
                StatusCode::CONFLICT,
                Json(ConnectResponse {
                    challenge_id: String::new(),
                    reverse_port: 0,
                    challenge: String::new(),
                }),
            );
        }
    }

    // Allocate reverse port from pool
    let reverse_port = match req.remote_port {
        Some(p) if p > 0 => p,
        _ => {
            let mut pool = state.inner.port_pool.lock().unwrap();
            pool.allocate()
        }
    };

    // Build challenge
    let nonce = random_nonce_b64url(16);
    let issued_at: DateTime<Utc> = Utc::now();
    let expires_at: DateTime<Utc> =
        issued_at + chrono::Duration::seconds(CHALLENGE_TTL_SECS as i64);
    let challenge = Challenge {
        rp_id: state.inner.rp_id.clone(),
        subdomain: req.subdomain.clone(),
        reverse_port,
        local_port: req.local_port,
        nonce_b64url: nonce,
        issued_at_rfc3339: issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        expires_at_rfc3339: expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };

    let challenge_id = Uuid::new_v4().to_string();
    let expires_at_instant = Instant::now() + Duration::from_secs(CHALLENGE_TTL_SECS);

    // Store pending challenge (includes local_port for connection tracking)
    let pending = PendingChallenge {
        key_id: req.key_id.0.clone(),
        challenge: challenge.clone(),
        subdomain: req.subdomain,
        reverse_port,
        expires_at: expires_at_instant,
    };
    state
        .inner
        .challenges
        .lock()
        .unwrap()
        .insert(challenge_id.clone(), pending);

    let resp = ConnectResponse {
        challenge_id,
        reverse_port,
        challenge: challenge.to_base64url(),
    };
    (StatusCode::OK, Json(resp))
}

async fn auth_handler(
    State(state): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> (StatusCode, Json<AuthResponse>) {
    let maybe = state
        .inner
        .challenges
        .lock()
        .unwrap()
        .remove(&req.challenge_id);
    let Some(pending) = maybe else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                ok: false,
                message: Some("invalid or expired challenge".into()),
            }),
        );
    };

    if pending.expires_at <= Instant::now() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                ok: false,
                message: Some("expired".into()),
            }),
        );
    }

    if pending.key_id != req.key_id.0 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                ok: false,
                message: Some("key mismatch".into()),
            }),
        );
    }

    match verify_signature_for_key_id(
        &req.key_id.0,
        &req.signature,
        &pending.challenge.to_canonical_string(),
        &state.inner.clients_dir,
    ) {
        Ok(true) => {
            // Setup nginx config and SSL cert if needed
            if let Err(e) = setup_subdomain(
                &state.inner.nginx_available,
                &state.inner.nginx_enabled,
                &state.inner.acme_webroot,
                &state.inner.acme_email,
                state.inner.tls_enable,
                state.inner.auto_cert,
                state.inner.http_redirect,
                state.inner.hsts_enable,
                state.inner.hsts_max_age,
                &state.inner.tls_cert,
                &state.inner.tls_key,
                &pending.subdomain,
                pending.reverse_port,
                &state.inner.rp_id,
            ) {
                tracing::error!("subdomain setup error: {}", e);
                // Release the port back to pool on failure
                state
                    .inner
                    .port_pool
                    .lock()
                    .unwrap()
                    .release(pending.reverse_port);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthResponse {
                        ok: false,
                        message: Some(format!("setup error: {}", e)),
                    }),
                );
            }

            // Track the active connection
            let connection = ActiveConnection {
                subdomain: pending.subdomain.clone(),
                key_id: req.key_id.0.clone(),
                reverse_port: pending.reverse_port,
                local_port: pending.challenge.local_port,
                connected_at: Utc::now(),
            };
            state
                .inner
                .connections
                .lock()
                .unwrap()
                .insert(pending.subdomain.clone(), connection);

            info!(
                "Client connected: subdomain={}, port={}, key_id={}",
                pending.subdomain, pending.reverse_port, req.key_id.0
            );

            (
                StatusCode::OK,
                Json(AuthResponse {
                    ok: true,
                    message: None,
                }),
            )
        }
        Ok(false) => (
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                ok: false,
                message: Some("signature verification failed".into()),
            }),
        ),
        Err(e) => {
            tracing::error!("auth verify error: {}", e);
            (
                StatusCode::UNAUTHORIZED,
                Json(AuthResponse {
                    ok: false,
                    message: Some("verification error".into()),
                }),
            )
        }
    }
}

async fn disconnect_handler(
    State(state): State<AppState>,
    Json(req): Json<DisconnectRequest>,
) -> (StatusCode, Json<DisconnectResponse>) {
    let mut connections = state.inner.connections.lock().unwrap();

    if let Some(conn) = connections.get(&req.subdomain) {
        // Verify the key_id matches
        if conn.key_id != req.key_id.0 {
            return (
                StatusCode::FORBIDDEN,
                Json(DisconnectResponse {
                    ok: false,
                    message: Some("key_id mismatch".into()),
                }),
            );
        }

        let port = conn.reverse_port;
        connections.remove(&req.subdomain);
        drop(connections); // Release lock before modifying port pool

        // Release port back to pool
        state.inner.port_pool.lock().unwrap().release(port);

        // Optionally remove nginx config
        let _ = remove_nginx_config(
            &state.inner.nginx_available,
            &state.inner.nginx_enabled,
            &req.subdomain,
        );

        info!("Client disconnected: subdomain={}", req.subdomain);

        (
            StatusCode::OK,
            Json(DisconnectResponse {
                ok: true,
                message: None,
            }),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(DisconnectResponse {
                ok: false,
                message: Some("connection not found".into()),
            }),
        )
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize)]
struct HealthResponse {
    status: String,
    active_connections: usize,
    rp_id: String,
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let active = state.inner.connections.lock().unwrap().len();
    Json(HealthResponse {
        status: "ok".into(),
        active_connections: active,
        rp_id: state.inner.rp_id.clone(),
    })
}

fn random_nonce_b64url(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    encode_url_nopad(&buf)
}

fn remove_nginx_config(available: &Path, enabled: &Path, subdomain: &str) -> Result<(), String> {
    let file_name = format!("kickflip-{}.conf", subdomain);
    let avail_path = available.join(&file_name);
    let enabled_path = enabled.join(&file_name);

    let _ = std::fs::remove_file(&enabled_path);
    let _ = std::fs::remove_file(&avail_path);

    // Reload nginx if not skipped
    if std::env::var("KICKFLIP_SKIP_NGINX_RELOAD").unwrap_or_default() != "1" {
        let status = std::process::Command::new("nginx")
            .arg("-s")
            .arg("reload")
            .status()
            .map_err(|e| format!("reload: {}", e))?;
        if !status.success() {
            return Err("nginx reload failed".into());
        }
    }
    Ok(())
}

fn verify_signature_for_key_id(
    key_id: &str,
    signature_b64url: &str,
    canonical: &str,
    clients_dir: &Path,
) -> Result<bool, String> {
    // Iterate allow-listed keys to find matching key_id
    let read_dir = std::fs::read_dir(clients_dir).map_err(|e| format!("read_dir: {}", e))?;
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("entry: {}", e))?;
        if !entry
            .file_type()
            .map_err(|e| format!("file_type: {}", e))?
            .is_file()
        {
            continue;
        }
        let content =
            std::fs::read_to_string(entry.path()).map_err(|e| format!("read_to_string: {}", e))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(pubkey) = parse_ssh_public_key_line(line) {
                let fingerprint = compute_openssh_sha256_fingerprint(&pubkey.blob);
                let key_id_line = format!("SHA256:{}", fingerprint);
                if key_id_line == key_id {
                    // Verify signature
                    if let Ok(ok) =
                        verify_ed25519_signature(&pubkey, signature_b64url, canonical.as_bytes())
                    {
                        return Ok(ok);
                    }
                    return Ok(false);
                }
            }
        }
    }
    Ok(false)
}

struct ParsedSshEd25519Key {
    blob: Vec<u8>,        // full base64-decoded blob
    pubkey_raw: [u8; 32], // raw 32-byte ed25519 pubkey
}

fn parse_ssh_public_key_line(line: &str) -> Option<ParsedSshEd25519Key> {
    // Format: "ssh-ed25519 <base64> [comment]"
    let mut parts = line.split_whitespace();
    let kind = parts.next()?;
    if kind != "ssh-ed25519" {
        return None;
    }
    let b64 = parts.next()?;
    let blob = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    // Parse SSH wire format: string("ssh-ed25519"), string(pubkey)
    let mut cursor = &blob[..];
    let typ = read_ssh_string(&mut cursor)?;
    if typ != b"ssh-ed25519" {
        return None;
    }
    let key = read_ssh_string(&mut cursor)?;
    if key.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(key);
    Some(ParsedSshEd25519Key {
        blob,
        pubkey_raw: raw,
    })
}

fn read_ssh_string<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    if cursor.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
    *cursor = &cursor[4..];
    if cursor.len() < len {
        return None;
    }
    let (s, rest) = cursor.split_at(len);
    *cursor = rest;
    Some(s)
}

fn compute_openssh_sha256_fingerprint(blob: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(blob);
    let digest = hasher.finalize();
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
}

fn verify_ed25519_signature(
    pubkey: &ParsedSshEd25519Key,
    signature_b64url: &str,
    message: &[u8],
) -> Result<bool, String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let sig_bytes = decode_url_nopad(signature_b64url).map_err(|e| format!("sig b64: {}", e))?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|e| format!("sig parse: {}", e))?;
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey.pubkey_raw).map_err(|e| format!("pk parse: {}", e))?;
    Ok(verifying_key.verify_strict(message, &signature).is_ok())
}

// Unix socket control loop: Accept connections, process commands
async fn control_loop(listener: UnixListener, shutdown_tx: mpsc::Sender<()>, state: AppState) {
    loop {
        let (mut socket, addr) = listener.accept().await.unwrap();
        let mut buf = [0; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        let command = String::from_utf8_lossy(&buf[0..n]).trim().to_string();
        info!("Received CLI command from {:?}: {}", addr, command);

        match command.as_str() {
            "status" => {
                // Extract data while holding locks, then drop locks before await
                let response = {
                    let connections = state.inner.connections.lock().unwrap();
                    let port_pool = state.inner.port_pool.lock().unwrap();
                    let mut response = format!(
                        "Server running\nDomain: {}\nActive connections: {}\nPorts in use: {}\n",
                        state.inner.rp_id,
                        connections.len(),
                        port_pool.active_count()
                    );
                    if !connections.is_empty() {
                        response.push_str("\nConnections:\n");
                        for (subdomain, conn) in connections.iter() {
                            response.push_str(&format!(
                                "  - {}.{} -> port {} (since {})\n",
                                subdomain,
                                state.inner.rp_id,
                                conn.reverse_port,
                                conn.connected_at.format("%Y-%m-%d %H:%M:%S UTC")
                            ));
                        }
                    }
                    response
                };
                socket.write_all(response.as_bytes()).await.unwrap();
                info!("Responded to 'status'");
            }
            "shutdown" => {
                socket.write_all(b"Shutting down\n").await.unwrap();
                info!("Responded to 'shutdown': Initiating shutdown");
                let _ = shutdown_tx.send(()).await;
                break;
            }
            "reload" => {
                socket
                    .write_all(b"Reloaded config (placeholder)\n")
                    .await
                    .unwrap();
                info!("Responded to 'reload': Reloaded config (placeholder)");
            }
            "connections" => {
                let response = {
                    let connections = state.inner.connections.lock().unwrap();
                    if connections.is_empty() {
                        "No active connections\n".to_string()
                    } else {
                        let mut json = serde_json::to_string_pretty(
                            &connections
                                .values()
                                .map(|c| ConnectionInfo {
                                    subdomain: c.subdomain.clone(),
                                    reverse_port: c.reverse_port,
                                    local_port: c.local_port,
                                    connected_at: c.connected_at.to_rfc3339(),
                                })
                                .collect::<Vec<_>>(),
                        )
                        .unwrap_or_else(|_| "[]".to_string());
                        json.push('\n');
                        json
                    }
                };
                socket.write_all(response.as_bytes()).await.unwrap();
                info!("Responded to 'connections'");
            }
            _ => {
                socket
                    .write_all(
                        b"Unknown command. Available: status, connections, reload, shutdown\n",
                    )
                    .await
                    .unwrap();
                info!(
                    "Responded to unknown command '{}': Unknown command",
                    command
                );
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionInfo {
    subdomain: String,
    reverse_port: u16,
    local_port: u16,
    connected_at: String,
}

/// Check if an SSL certificate exists for the given subdomain
fn cert_exists(subdomain: &str, rp_id: &str, tls_cert: &str) -> bool {
    let cert_path = if tls_cert.is_empty() {
        format!(
            "/etc/letsencrypt/live/{}.{}/fullchain.pem",
            subdomain, rp_id
        )
    } else {
        tls_cert.to_string()
    };
    std::path::Path::new(&cert_path).exists()
}

/// Obtain an SSL certificate using certbot
fn obtain_cert(
    subdomain: &str,
    rp_id: &str,
    acme_webroot: &Path,
    acme_email: &str,
) -> Result<(), String> {
    let fqdn = format!("{}.{}", subdomain, rp_id);
    info!("Obtaining SSL certificate for {}...", fqdn);

    let mut cmd = std::process::Command::new("certbot");
    cmd.arg("certonly")
        .arg("--non-interactive")
        .arg("--agree-tos")
        .arg("--webroot")
        .arg("--webroot-path")
        .arg(acme_webroot)
        .arg("-d")
        .arg(&fqdn);

    // Add email if provided
    if !acme_email.is_empty() {
        cmd.arg("--email").arg(acme_email);
    } else {
        cmd.arg("--register-unsafely-without-email");
    }

    let output = cmd.output().map_err(|e| format!("certbot exec: {}", e))?;

    if output.status.success() {
        info!("SSL certificate obtained for {}", fqdn);
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("certbot failed: {}", stderr))
    }
}

/// Write HTTP-only nginx config for ACME challenge
fn write_http_only_nginx_config(
    available: &Path,
    enabled: &Path,
    acme_webroot: &Path,
    subdomain: &str,
    rp_id: &str,
) -> Result<(), String> {
    std::fs::create_dir_all(available).map_err(|e| format!("mkdir avail: {}", e))?;
    std::fs::create_dir_all(enabled).map_err(|e| format!("mkdir enabled: {}", e))?;
    std::fs::create_dir_all(acme_webroot).map_err(|e| format!("mkdir webroot: {}", e))?;

    let server_name = format!("{}.{}", subdomain, rp_id);
    let contents = format!(
        r"# Temporary config for ACME challenge
server {{
    server_name {server_name};
    listen 80;

    location /.well-known/acme-challenge/ {{
        root {webroot};
    }}

    location / {{
        return 503;
    }}
}}
",
        server_name = server_name,
        webroot = acme_webroot.display(),
    );

    let file_name = format!("kickflip-{}.conf", subdomain);
    let avail_path = available.join(&file_name);
    std::fs::write(&avail_path, contents).map_err(|e| format!("write: {}", e))?;

    let enabled_path = enabled.join(&file_name);
    let _ = std::fs::remove_file(&enabled_path);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&avail_path, &enabled_path)
            .map_err(|e| format!("symlink: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::copy(&avail_path, &enabled_path).map_err(|e| format!("copy: {}", e))?;
    }

    reload_nginx()?;
    Ok(())
}

/// Reload nginx configuration
fn reload_nginx() -> Result<(), String> {
    if std::env::var("KICKFLIP_SKIP_NGINX_RELOAD").unwrap_or_default() == "1" {
        return Ok(());
    }

    let status = std::process::Command::new("nginx")
        .arg("-s")
        .arg("reload")
        .status()
        .map_err(|e| format!("nginx reload: {}", e))?;

    if !status.success() {
        return Err("nginx reload failed".into());
    }
    Ok(())
}

/// Setup a subdomain: obtain cert if needed, write nginx config
#[allow(clippy::too_many_arguments)]
fn setup_subdomain(
    nginx_available: &Path,
    nginx_enabled: &Path,
    acme_webroot: &Path,
    acme_email: &str,
    tls_enable: bool,
    auto_cert: bool,
    http_redirect: bool,
    hsts_enable: bool,
    hsts_max_age: u32,
    tls_cert: &str,
    tls_key: &str,
    subdomain: &str,
    reverse_port: u16,
    rp_id: &str,
) -> Result<(), String> {
    // If TLS is enabled and we should auto-obtain certs
    if tls_enable && auto_cert && !cert_exists(subdomain, rp_id, tls_cert) {
        info!(
            "Certificate not found for {}.{}, obtaining...",
            subdomain, rp_id
        );

        // Step 1: Write HTTP-only config for ACME challenge
        write_http_only_nginx_config(
            nginx_available,
            nginx_enabled,
            acme_webroot,
            subdomain,
            rp_id,
        )?;

        // Step 2: Obtain certificate
        obtain_cert(subdomain, rp_id, acme_webroot, acme_email)?;
    }

    // Step 3: Write full nginx config (with or without TLS)
    write_nginx_config(
        nginx_available,
        nginx_enabled,
        acme_webroot,
        tls_enable && cert_exists(subdomain, rp_id, tls_cert), // Only enable TLS if cert exists
        http_redirect,
        hsts_enable,
        hsts_max_age,
        tls_cert,
        tls_key,
        subdomain,
        reverse_port,
        rp_id,
    )
}

fn write_nginx_config(
    available: &Path,
    enabled: &Path,
    acme_webroot: &Path,
    tls_enable: bool,
    http_redirect: bool,
    hsts_enable: bool,
    hsts_max_age: u32,
    tls_cert: &str,
    tls_key: &str,
    subdomain: &str,
    reverse_port: u16,
    rp_id: &str,
) -> Result<(), String> {
    // Paths
    std::fs::create_dir_all(available).map_err(|e| format!("mkdir avail: {}", e))?;
    std::fs::create_dir_all(enabled).map_err(|e| format!("mkdir enabled: {}", e))?;
    std::fs::create_dir_all(acme_webroot).map_err(|e| format!("mkdir webroot: {}", e))?;

    // Template
    let server_name = format!("{}.{}", subdomain, rp_id);
    let effective_cert = if tls_cert.is_empty() {
        format!("/etc/letsencrypt/live/{}/fullchain.pem", server_name)
    } else {
        tls_cert.to_string()
    };
    let effective_key = if tls_key.is_empty() {
        format!("/etc/letsencrypt/live/{}/privkey.pem", server_name)
    } else {
        tls_key.to_string()
    };

    let https_block = {
        let mut block = format!(
            "server {{\n    server_name {server_name};\n\n    access_log /var/log/nginx/$host;\n\n    listen 443 ssl;\n    ssl_certificate {tls_cert};\n    ssl_certificate_key {tls_key};\n\n    location / {{\n        proxy_pass http://127.0.0.1:{reverse_port}/;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header Host $host;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto https;\n        proxy_redirect off;\n    }}\n",
            server_name = server_name,
            tls_cert = effective_cert,
            tls_key = effective_key,
            reverse_port = reverse_port,
        );
        if hsts_enable {
            block.push_str(&format!(
                "    add_header Strict-Transport-Security \"max-age={}; includeSubDomains\" always;\n",
                hsts_max_age
            ));
        }
        block.push_str("}\n");
        block
    };

    let http_block_tls = if http_redirect {
        format!(
            "server {{\n    server_name {server_name};\n    listen 80;\n\n    location /.well-known/acme-challenge/ {{\n        root {webroot};\n    }}\n\n    location / {{\n        return 301 https://$host$request_uri;\n    }}\n}}\n",
            server_name = server_name,
            webroot = acme_webroot.display(),
        )
    } else {
        format!(
            "server {{\n    server_name {server_name};\n    listen 80;\n\n    location /.well-known/acme-challenge/ {{\n        root {webroot};\n    }}\n\n    location / {{\n        return 404;\n    }}\n}}\n",
            server_name = server_name,
            webroot = acme_webroot.display(),
        )
    };

    let http_block_plain = format!(
        "server {{\n    server_name {server_name};\n    listen 80;\n\n    access_log /var/log/nginx/$host;\n\n    location / {{\n        proxy_pass http://127.0.0.1:{reverse_port}/;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header Host $host;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto http;\n        proxy_redirect off;\n    }}\n}}\n",
        server_name = server_name,
        reverse_port = reverse_port,
    );

    let contents = if tls_enable {
        format!("{}\n{}", https_block, http_block_tls)
    } else {
        http_block_plain
    };

    let file_name = format!("kickflip-{}.conf", subdomain);
    let avail_path = available.join(&file_name);
    std::fs::write(&avail_path, contents).map_err(|e| format!("write: {}", e))?;
    let enabled_path = enabled.join(&file_name);
    // replace symlink
    let _ = std::fs::remove_file(&enabled_path);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&avail_path, &enabled_path)
            .map_err(|e| format!("symlink: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::copy(&avail_path, &enabled_path).map_err(|e| format!("copy: {}", e))?;
    }

    reload_nginx()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode as HttpStatus;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use tempfile::tempdir;
    use tower::ServiceExt; // for `oneshot`

    fn test_router(state: AppState) -> Router {
        Router::new()
            .route("/connect", post(connect_handler))
            .route("/auth", post(auth_handler))
            .with_state(state)
    }

    fn write_openssh_pubkey(dir: &Path, signing_key: &SigningKey) -> (String, VerifyingKey) {
        let verifying = signing_key.verifying_key();
        let raw = verifying.to_bytes();
        // Build OpenSSH blob: string("ssh-ed25519"), string(pubkey)
        let mut blob = Vec::new();
        let t = b"ssh-ed25519";
        blob.extend_from_slice(&(t.len() as u32).to_be_bytes());
        blob.extend_from_slice(t);
        blob.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        blob.extend_from_slice(&raw);
        let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
        let line = format!("ssh-ed25519 {} test@kickflip\n", blob_b64);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("client.pub"), line).unwrap();
        // Compute fingerprint
        let fp = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob));
        (format!("SHA256:{}", fp), verifying)
    }

    #[tokio::test]
    async fn connect_then_auth_success() {
        let tmp = tempdir().unwrap();
        std::env::set_var("KICKFLIP_SKIP_NGINX_RELOAD", "1");
        let state = AppState {
            inner: Arc::new(InnerState {
                clients_dir: tmp.path().to_path_buf(),
                rp_id: "localhost".into(),
                nginx_available: tmp.path().join("available"),
                nginx_enabled: tmp.path().join("enabled"),
                tls_enable: false,
                tls_cert: String::new(),
                tls_key: String::new(),
                acme_webroot: tmp.path().join("letsencrypt"),
                acme_email: String::new(),
                auto_cert: false, // Disable auto-cert in tests
                http_redirect: false,
                hsts_enable: false,
                hsts_max_age: 31_536_000,
                challenges: Mutex::new(HashMap::new()),
                connections: Mutex::new(HashMap::new()),
                port_pool: Mutex::new(PortPool::new(DEFAULT_REVERSE_PORT_START)),
            }),
        };
        let router = test_router(state.clone());

        // Generate key and write allow-list
        // Generate random bytes for the signing key (avoids rand_core version mismatch)
        let mut seed = [0u8; 32];
        rand::Fill::fill(&mut seed, &mut rand::rng());
        let signing = SigningKey::from_bytes(&seed);
        let (key_id, _verifying) = write_openssh_pubkey(tmp.path(), &signing);

        // 1) /connect
        let req_body = serde_json::to_string(&ConnectRequest {
            subdomain: "app".into(),
            protocol: Some("http".into()),
            remote_port: None,
            local_port: 3000,
            key_id: kickflip_proto::types::KeyId(key_id.clone()),
        })
        .unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connect")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(req_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let conn_resp: ConnectResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(conn_resp.reverse_port, DEFAULT_REVERSE_PORT_START);
        assert!(!conn_resp.challenge_id.is_empty());

        // 2) sign challenge
        let challenge_bytes = decode_url_nopad(&conn_resp.challenge).unwrap();
        let signature = signing.sign(&challenge_bytes);
        let signature_b64url = encode_url_nopad(&signature.to_bytes());

        // 3) /auth
        let auth_body = serde_json::to_string(&AuthRequest {
            challenge_id: conn_resp.challenge_id,
            key_id: kickflip_proto::types::KeyId(key_id),
            signature: signature_b64url,
        })
        .unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(auth_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), HttpStatus::OK);
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let auth_resp: AuthResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(auth_resp.ok);
    }
}
