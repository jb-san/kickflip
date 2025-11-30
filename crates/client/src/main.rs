use clap::{Parser, Subcommand};
use inquire::{Confirm, Text};
use std::fmt;
use std::str::FromStr;
mod config;
mod networking;
mod ssh;

#[derive(Parser)]
#[command(name = "kickflip-client")]
#[command(about = "Self-hosted ngrok alternative")]
#[command(version)]
struct Cli {
    /// Set the verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// The command to run
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
    Port(u16),
}
#[derive(Debug)]
pub struct ProtocolParseError;
impl From<u16> for Protocol {
    fn from(port: u16) -> Self {
        Protocol::Port(port)
    }
}

impl FromStr for Protocol {
    type Err = ProtocolParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "http" => Ok(Protocol::Http),
            "https" => Ok(Protocol::Https),
            _ => s
                .parse::<u16>()
                .map(Protocol::Port)
                .map_err(|_| ProtocolParseError),
        }
    }
}

impl fmt::Display for ProtocolParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid protocol: expected 'http', 'https', or a numeric port"
        )
    }
}

impl std::error::Error for ProtocolParseError {}
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Protocol::Http => write!(f, "http"),
            Protocol::Https => write!(f, "https"),
            Protocol::Port(p) => write!(f, "{p}"),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Run the setup wizard
    Setup,
    /// Get the public key of the client
    GetPubKey,
    /// Connect to a kickflip server
    Connect {
        //  protocol to use ("http", "https") or a numeric port
        #[arg(value_name = "protocol|port")]
        protocol: Protocol,
        /// The subdomain to connect to
        #[arg(short, long)]
        subdomain: String,
        #[arg(short = 'p', long = "port")]
        local_port: u16,
    },
    /// Disconnect from a kickflip server
    Disconnect,
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
    // Handle subcommands
    match cli.command {
        Some(Commands::Setup) => {
            println!("Starting setup...");
            // 1. check if ssh is installed
            match ssh::is_ssh_installed() {
                true => println!("✅ SSH is installed"),
                false => println!("❌ SSH is not installed"),
            }
            // 2. check if the user has a ~/.ssh/kickflip.pub key
            match ssh::has_kickflip_key() {
                true => println!("✅ Kickflip key found"),
                false => {
                    match ask_yes_no_with_inquire("Would you like to generate a new kickflip key?")
                    {
                        Ok(true) => {
                            println!("Generating new kickflip key...");
                            ssh::generate_kickflip_key().unwrap();
                        }
                        Ok(false) => {
                            println!("Setup cancelled. You'll need a key to use kickflip. You can always run the setup again");
                            return;
                        }
                        Err(e) => {
                            println!("Error: {}", e);
                            return;
                        }
                    }
                }
            }
            // 3. supply the kickflip server url and ssh user
            let mut cfg = config::Config::load();

            let server_url = Text::new("Server URL")
                .with_initial_value(&cfg.server_url)
                .with_help_message("The kickflip server API endpoint")
                .prompt()
                .unwrap_or_default();
            cfg.server_url = server_url;

            let ssh_user = Text::new("SSH user on server")
                .with_initial_value(&cfg.ssh_user)
                .with_help_message("The user account for SSH tunnel connections")
                .prompt()
                .unwrap_or_default();
            cfg.ssh_user = ssh_user;

            let ssh_port_str = Text::new("SSH port on server")
                .with_initial_value(&cfg.ssh_port.to_string())
                .with_help_message("The SSH port for tunnel connections (default: 2222)")
                .prompt()
                .unwrap_or_else(|_| "2222".to_string());
            cfg.ssh_port = ssh_port_str.parse().unwrap_or(2222);

            if let Err(e) = cfg.save() {
                eprintln!("❌ Error saving config: {}", e);
            } else {
                println!("✅ Configuration saved to ~/.kickflip.toml");
            }
        }
        Some(Commands::GetPubKey) => {
            ssh::display_public_key().unwrap();
            // Your get public key logic here
        }
        Some(Commands::Connect {
            protocol,
            subdomain,
            local_port,
        }) => {
            let cfg = config::Config::load();
            // Convert protocol enum to string for server
            // Format: "http", "https", or "port:NNNN" for custom ports
            let protocol_str = match &protocol {
                Protocol::Http => "http".to_string(),
                Protocol::Https => "https".to_string(),
                Protocol::Port(p) => format!("port:{}", p),
            };

            println!("🔗 Connecting to {}", cfg.server_url);
            println!(
                "   Subdomain: {}.{}",
                subdomain,
                extract_domain(&cfg.server_url)
            );
            println!("   Protocol: {}", protocol);
            println!("   Local port: {}", local_port);

            // remote_port = 0 means server will auto-allocate a high port
            if let Err(e) = networking::connect(
                &cfg.server_url,
                &subdomain,
                &protocol_str,
                local_port,
                &cfg.ssh_user,
                cfg.ssh_port,
            ) {
                eprintln!("❌ Connection failed: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Disconnect) => {
            println!("🔌 Disconnecting...");

            // First, try to notify server using saved connection info
            if let Some(conn_info) = networking::load_connection_info() {
                println!(
                    "   Notifying server about subdomain: {}",
                    conn_info.subdomain
                );
                if let Err(e) = networking::disconnect(&conn_info.server_url, &conn_info.subdomain)
                {
                    eprintln!("   Warning: could not notify server: {}", e);
                } else {
                    println!("   ✅ Server notified");
                }
            }

            // Then kill any kickflip SSH tunnels locally
            match find_and_kill_tunnels() {
                Ok(count) if count > 0 => println!("✅ Killed {} tunnel(s)", count),
                Ok(_) => println!("ℹ️  No active tunnels found"),
                Err(e) => eprintln!("❌ Error: {}", e),
            }
        }
        None => {
            println!("No command provided");
        }
    }
}

/**
 * Utility function to ask a yes/no question with inquire
 */
pub fn ask_yes_no_with_inquire(question: &str) -> Result<bool, inquire::InquireError> {
    Confirm::new(question).with_default(false).prompt()
}

/// Extract domain from a URL (e.g., "https://example.com:8080" -> "example.com")
fn extract_domain(url: &str) -> String {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("localhost")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string()
}

/// Find and kill any SSH processes using the kickflip key
fn find_and_kill_tunnels() -> Result<usize, std::io::Error> {
    use std::process::Command;

    // Use pgrep to find SSH processes, then filter by kickflip key
    let output = Command::new("pgrep")
        .arg("-f")
        .arg("ssh.*kickflip")
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let pids: Vec<&str> = stdout.lines().collect();
            let count = pids.len();

            for pid in pids {
                let _ = Command::new("kill").arg(pid.trim()).status();
            }

            Ok(count)
        }
        Ok(_) => Ok(0), // pgrep returns non-zero when no matches
        Err(e) => Err(e),
    }
}
