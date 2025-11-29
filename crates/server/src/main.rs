use base64::Engine;
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
mod config;
mod tui;
use config::ServerConfig;

#[derive(Parser)]
#[command(name = "kickflip-server")]
#[command(about = "Self-hosted ngrok alternative")]
#[command(version)]
struct Cli {
    /// Set the verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Server port
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Server host
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Clients directory (allow-list)
    #[arg(long, default_value = "clients.d")]
    clients_dir: PathBuf,

    /// Daemon control socket path
    #[arg(long, default_value = "/tmp/kickflip.sock")]
    socket: PathBuf,

    /// Nginx sites-available directory
    #[arg(long, default_value = "/etc/nginx/sites-available")]
    nginx_available: PathBuf,

    /// Nginx sites-enabled directory
    #[arg(long, default_value = "/etc/nginx/sites-enabled")]
    nginx_enabled: PathBuf,

    /// Base domain (rpId) for generated server_name
    #[arg(long, default_value = "localhost")]
    rp_id: String,

    /// Enable TLS server block and HTTPS redirect (default true)
    #[arg(long, default_value_t = true)]
    tls_enable: bool,

    /// TLS cert (fullchain.pem). Default: /etc/letsencrypt/live/<rp_id>/fullchain.pem
    #[arg(long, default_value = "")]
    tls_cert: String,

    /// TLS key (privkey.pem). Default: /etc/letsencrypt/live/<rp_id>/privkey.pem
    #[arg(long, default_value = "")]
    tls_key: String,

    /// ACME webroot for /.well-known/acme-challenge
    #[arg(long, default_value = "/var/www/letsencrypt")]
    acme_webroot: PathBuf,

    /// Redirect HTTP to HTTPS when TLS is enabled
    #[arg(long, default_value_t = true)]
    http_redirect: bool,

    /// Enable HSTS header on HTTPS responses
    #[arg(long, default_value_t = false)]
    hsts_enable: bool,

    /// HSTS max-age seconds
    #[arg(long, default_value_t = 31536000)]
    hsts_max_age: u32,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the configuration wizard
    Configure,
    /// Start the daemon
    Start,
    /// Query daemon status via Unix socket
    Status,
    /// Ask daemon to shutdown
    Stop,
    /// Add an allow-listed client public key
    AddClient {
        #[arg(long, value_name = "PATH", conflicts_with = "pubkey")]
        file: Option<PathBuf>,
        #[arg(long, value_name = "STRING")]
        pubkey: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove an allow-listed client by key fingerprint (key_id)
    RemoveClient {
        #[arg(long)]
        key_id: String,
    },
    /// List all allow-listed clients
    ListClients,
    /// Launch the terminal UI for managing server and clients
    Tui,
}

fn main() {
    let cli = Cli::parse();

    // Handle verbosity
    match cli.verbose {
        0 => println!("Running in normal mode"),
        1 => println!("Running in verbose mode (-v)"),
        2 => println!("Running in very verbose mode (-vv)"),
        _ => println!("Running in debug mode (-vvv+)"),
    }

    println!("Config file: {}", cli.config);
    println!("Server: {}:{}", cli.host, cli.port);

    // Handle subcommands
    match cli.command {
        Some(Commands::Configure) => {
            let cfg = run_configure();
            // Save config to file
            let path = std::env::var("KICKFLIP_SERVER_CONFIG")
                .unwrap_or_else(|_| "kickflip-server.toml".into());
            match cfg.save_path(&path) {
                Ok(_) => println!("Saved config to {}", path),
                Err(e) => eprintln!("Failed to save config: {}", e),
            }
        }
        Some(Commands::Start) => {
            // Try to load config file if present
            let path = std::env::var("KICKFLIP_SERVER_CONFIG")
                .unwrap_or_else(|_| "kickflip-server.toml".into());
            let maybe_cfg = ServerConfig::load_path(&path).ok();
            let rp_id;
            let clients_dir;
            let nginx_available;
            let nginx_enabled;
            let acme_webroot;
            let acme_email;
            let auto_cert;
            let tls_enable;
            let tls_cert;
            let tls_key;
            let http_redirect;
            let hsts_enable;
            let hsts_max_age;
            if let Some(cfg) = maybe_cfg {
                rp_id = cfg.rp_id;
                clients_dir = cfg.clients_dir.to_string_lossy().to_string();
                nginx_available = cfg.nginx_available.to_string_lossy().to_string();
                nginx_enabled = cfg.nginx_enabled.to_string_lossy().to_string();
                acme_webroot = cfg.acme_webroot.to_string_lossy().to_string();
                acme_email = cfg.acme_email;
                auto_cert = cfg.auto_cert;
                tls_enable = cfg.tls_enable;
                tls_cert = cfg.tls_cert;
                tls_key = cfg.tls_key;
                http_redirect = cfg.http_redirect;
                hsts_enable = cfg.hsts_enable;
                hsts_max_age = cfg.hsts_max_age;
            } else {
                rp_id = cli.rp_id;
                clients_dir = cli.clients_dir.to_string_lossy().to_string();
                nginx_available = cli.nginx_available.to_string_lossy().to_string();
                nginx_enabled = cli.nginx_enabled.to_string_lossy().to_string();
                acme_webroot = cli.acme_webroot.to_string_lossy().to_string();
                acme_email = String::new();
                auto_cert = true;
                tls_enable = cli.tls_enable;
                tls_cert = cli.tls_cert;
                tls_key = cli.tls_key;
                http_redirect = cli.http_redirect;
                hsts_enable = cli.hsts_enable;
                hsts_max_age = cli.hsts_max_age;
            }
            // spawn daemon with flags
            match Command::new("daemon")
                .arg("--clients-dir")
                .arg(clients_dir)
                .arg("--nginx-available")
                .arg(nginx_available)
                .arg("--nginx-enabled")
                .arg(nginx_enabled)
                .arg("--rp-id")
                .arg(&rp_id)
                .arg("--acme-webroot")
                .arg(acme_webroot)
                .arg("--acme-email")
                .arg(&acme_email)
                .arg("--auto-cert")
                .arg(if auto_cert { "true" } else { "false" })
                .arg("--tls-enable")
                .arg(if tls_enable { "true" } else { "false" })
                .arg("--tls-cert")
                .arg(&tls_cert)
                .arg("--tls-key")
                .arg(&tls_key)
                .arg("--http-redirect")
                .arg(if http_redirect { "true" } else { "false" })
                .arg("--hsts-enable")
                .arg(if hsts_enable { "true" } else { "false" })
                .arg("--hsts-max-age")
                .arg(hsts_max_age.to_string())
                .spawn()
            {
                Ok(_) => println!("Daemon started"),
                Err(e) => {
                    eprintln!("failed to start daemon: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Status) => match unix_socket_request(&cli.socket, b"status\n") {
            Ok(resp) => print!("{}", resp),
            Err(e) => {
                eprintln!("status error: {}", e);
                std::process::exit(1);
            }
        },
        Some(Commands::Stop) => match unix_socket_request(&cli.socket, b"shutdown\n") {
            Ok(resp) => print!("{}", resp),
            Err(e) => {
                eprintln!("stop error: {}", e);
                std::process::exit(1);
            }
        },
        Some(Commands::AddClient { file, pubkey, name }) => {
            let line = match (file, pubkey) {
                (Some(path), None) => fs::read_to_string(path).expect("read pubkey file"),
                (None, Some(s)) => s,
                _ => {
                    eprintln!("Provide either --file or --pubkey");
                    std::process::exit(2);
                }
            };
            let (_parsed, key_id) = parse_and_fingerprint(&line).expect("invalid ssh public key");
            ensure_dir(&cli.clients_dir).expect("create clients dir");
            let filename = sanitize_filename(&format!("{}.pub", key_id.replace(":", "_")));
            let mut content = line;
            if !content.ends_with('\n') {
                content.push('\n');
            }
            if let Some(n) = name {
                content.push_str(&format!("# name: {}\n", n));
            }
            let out_path = cli.clients_dir.join(filename);
            fs::write(&out_path, content.clone()).expect("write client key");
            println!("Added client: {} -> {}", key_id, out_path.display());

            // Also add to current user's authorized_keys by default
            if let Some(home) = std::env::var_os("HOME") {
                let ssh_dir = std::path::Path::new(&home).join(".ssh");
                let auth_path = ssh_dir.join("authorized_keys");
                let _ = fs::create_dir_all(&ssh_dir);
                let mut existing = String::new();
                if let Ok(mut f) = fs::File::open(&auth_path) {
                    use std::io::Read as _;
                    let _ = f.read_to_string(&mut existing);
                }
                if !existing.lines().any(|l| l.trim() == content.trim()) {
                    use std::io::Write as _;
                    let mut f = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&auth_path)
                        .expect("open authorized_keys");
                    f.write_all(content.as_bytes())
                        .expect("append authorized_keys");
                    println!("Appended key to {}", auth_path.display());
                } else {
                    println!("Key already present in {}", auth_path.display());
                }
            }
        }
        Some(Commands::RemoveClient { key_id }) => {
            let fname = sanitize_filename(&format!("{}.pub", key_id.replace(":", "_")));
            let path = cli.clients_dir.join(fname);
            if path.exists() {
                fs::remove_file(&path).expect("remove file");
                println!("Removed {}", key_id);
            } else {
                eprintln!("Not found in clients dir: {}", key_id);
            }

            // Also remove from current user's authorized_keys
            if let Some(home) = std::env::var_os("HOME") {
                let auth_path = std::path::Path::new(&home).join(".ssh/authorized_keys");
                if let Ok(text) = fs::read_to_string(&auth_path) {
                    let mut out = String::new();
                    for l in text.lines() {
                        let t = l.trim();
                        if t.is_empty() || t.starts_with('#') {
                            out.push_str(l);
                            out.push('\n');
                            continue;
                        }
                        if let Ok((_p, fp)) = parse_and_fingerprint(t) {
                            if fp == key_id {
                                continue;
                            } // skip matching
                        }
                        out.push_str(l);
                        out.push('\n');
                    }
                    if out != text {
                        fs::write(&auth_path, out).expect("write authorized_keys");
                        println!("Removed key from {}", auth_path.display());
                    } else {
                        println!("No matching key in {}", auth_path.display());
                    }
                }
            }
        }
        Some(Commands::ListClients) => match fs::read_dir(&cli.clients_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                        if let Ok(text) = fs::read_to_string(entry.path()) {
                            for line in text.lines() {
                                let l = line.trim();
                                if l.is_empty() || l.starts_with('#') {
                                    continue;
                                }
                                if let Ok((_parsed, key_id)) = parse_and_fingerprint(l) {
                                    println!("{}\t{}", key_id, entry.file_name().to_string_lossy());
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => println!("(empty) {}", cli.clients_dir.display()),
        },
        Some(Commands::Tui) => {
            if let Err(e) = tui::run(&cli.socket, &cli.clients_dir) {
                eprintln!("TUI error: {}", e);
                std::process::exit(1);
            }
        }
        None => {
            println!("No command specified. Use --help for usage information.");
        }
    }
}

fn unix_socket_request(socket_path: &std::path::Path, data: &[u8]) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(data)?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf)
}

fn ensure_dir(path: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

struct ParsedSshEd25519Key {
    blob: Vec<u8>,
}

fn parse_and_fingerprint(line: &str) -> Result<(ParsedSshEd25519Key, String), String> {
    let mut parts = line.split_whitespace();
    let kind = parts.next().ok_or("missing kind")?;
    if kind != "ssh-ed25519" {
        return Err("only ssh-ed25519 supported".into());
    }
    let b64 = parts.next().ok_or("missing key")?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("b64: {}", e))?;
    let fp = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob));
    Ok((ParsedSshEd25519Key { blob }, format!("SHA256:{}", fp)))
}

fn run_configure() -> ServerConfig {
    use inquire::{Confirm, Text};

    println!("\n== Kickflip server configuration ==\n");

    // 1) Check binaries
    let nginx_ok = which::which("nginx").is_ok();
    let sshd_ok = which::which("sshd").is_ok();
    let certbot_ok = which::which("certbot").is_ok();

    println!("nginx: {}", if nginx_ok { "found" } else { "missing" });
    println!("sshd: {}", if sshd_ok { "found" } else { "missing" });
    println!("certbot: {}", if certbot_ok { "found" } else { "missing" });
    if !nginx_ok {
        eprintln!("Please install nginx and re-run configure.");
        return ServerConfig::default();
    }
    if !sshd_ok {
        eprintln!("Please install and enable sshd.");
    }

    // 2) Prompt for domain and ACME
    let rp_id = Text::new("Base domain (rpId), e.g. example.com")
        .with_help_message("Used for <subdomain>.<rpId>")
        .prompt()
        .unwrap_or_else(|_| "localhost".into());
    let acme_webroot = Text::new("ACME webroot path")
        .with_initial_value("/var/www/letsencrypt")
        .prompt()
        .unwrap_or_else(|_| "/var/www/letsencrypt".into());
    let email = if certbot_ok {
        Text::new("Email for Let's Encrypt (optional)")
            .with_help_message("Needed for cert issuance/renewal notifications")
            .prompt()
            .unwrap_or_default()
    } else {
        String::new()
    };
    let want_https = Confirm::new("Enable HTTPS with Let's Encrypt?")
        .with_default(true)
        .prompt()
        .unwrap_or(true);
    let _http_redirect = if want_https {
        Confirm::new("Redirect HTTP to HTTPS?")
            .with_default(true)
            .prompt()
            .unwrap_or(true)
    } else {
        false
    };

    // 3) Ensure webroot
    let _ = std::fs::create_dir_all(&acme_webroot);

    // 4) Print DNS guidance
    println!("\nDNS: Create A/AAAA records for: *.{rp}", rp = rp_id);
    println!("  A     *.{rp} -> <your server IPv4>", rp = rp_id);
    println!(
        "  AAAA  *.{rp} -> <your server IPv6> (optional)",
        rp = rp_id
    );

    // 5) Optionally run certbot for a sample subdomain now
    if want_https && certbot_ok {
        let sub = Text::new("Test subdomain to issue a cert for now (or leave blank to skip)")
            .prompt()
            .unwrap_or_default();
        if !sub.is_empty() && !email.is_empty() {
            println!("Running certbot for {}.{} ...", sub, rp_id);
            let fqdn = format!("{}.{}", sub, rp_id);
            let status = Command::new("certbot")
                .arg("certonly")
                .arg("--non-interactive")
                .arg("--agree-tos")
                .arg("--email")
                .arg(&email)
                .arg("--domains")
                .arg(&fqdn)
                .arg("--webroot")
                .arg("--webroot-path")
                .arg(&acme_webroot)
                .status();
            match status {
                Ok(s) if s.success() => println!("Certbot succeeded for {}", fqdn),
                Ok(s) => eprintln!("Certbot failed (code {:?})", s.code()),
                Err(e) => eprintln!("Failed to run certbot: {}", e),
            }
        }
    }

    // Build config
    ServerConfig {
        rp_id,
        clients_dir: PathBuf::from("clients.d"),
        socket: PathBuf::from("/tmp/kickflip.sock"),
        nginx_available: PathBuf::from("/etc/nginx/sites-available"),
        nginx_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
        acme_webroot: PathBuf::from(acme_webroot),
        acme_email: email,
        auto_cert: want_https && certbot_ok,
        tls_enable: want_https,
        tls_cert: String::new(),
        tls_key: String::new(),
        http_redirect: want_https,
        hsts_enable: false,
        hsts_max_age: 31536000,
        ssh_user: std::env::var("USER").unwrap_or_else(|_| "root".into()),
        authorized_keys: std::env::var_os("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".ssh/authorized_keys"))
            .unwrap_or_else(|| std::path::PathBuf::from("/root/.ssh/authorized_keys")),
    }
}
