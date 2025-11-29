use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub rp_id: String,
    pub clients_dir: PathBuf,
    pub socket: PathBuf,
    pub nginx_available: PathBuf,
    pub nginx_enabled: PathBuf,
    pub acme_webroot: PathBuf,
    #[serde(default)]
    pub acme_email: String,
    #[serde(default = "default_auto_cert")]
    pub auto_cert: bool,
    pub tls_enable: bool,
    pub tls_cert: String,
    pub tls_key: String,
    pub http_redirect: bool,
    pub hsts_enable: bool,
    pub hsts_max_age: u32,
    pub ssh_user: String,
    pub authorized_keys: PathBuf,
}

fn default_auto_cert() -> bool {
    true
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".into(),
            clients_dir: PathBuf::from("clients.d"),
            socket: PathBuf::from("/tmp/kickflip.sock"),
            nginx_available: PathBuf::from("/etc/nginx/sites-available"),
            nginx_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
            acme_webroot: PathBuf::from("/var/www/letsencrypt"),
            acme_email: String::new(),
            auto_cert: true,
            tls_enable: true,
            tls_cert: String::new(),
            tls_key: String::new(),
            http_redirect: true,
            hsts_enable: false,
            hsts_max_age: 31536000,
            ssh_user: "kickflip".into(),
            authorized_keys: PathBuf::from("/home/kickflip/.ssh/authorized_keys"),
        }
    }
}

impl ServerConfig {
    pub fn load_path<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let data = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(cfg)
    }

    pub fn save_path<P: AsRef<Path>>(&self, path: P) -> Result<(), std::io::Error> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let data = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        fs::write(path, data)
    }
}
