use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;

/**
 * Configuration for the Kickflip client.
 * Serializes to TOML in the user's home directory.
 */
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_server_url")]
    pub server_url: String,
    #[serde(default = "default_ssh_user")]
    pub ssh_user: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
            ssh_user: default_ssh_user(),
        }
    }
}

fn default_server_url() -> String {
    "https://localhost:8080".to_string()
}

fn default_ssh_user() -> String {
    "kickflip".to_string()
}

impl Config {
    /// Create a new config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Load config from disk, falling back to defaults on any error
    pub fn load() -> Self {
        Self::load_from_path(&Self::config_path().unwrap_or_default()).unwrap_or_default()
    }

    /// Load config with error handling - more explicit version
    pub fn load_with_errors() -> Result<Self, Error> {
        let config_path = Self::config_path()?;
        Self::load_from_path(&config_path)
    }

    /// Get the config file path
    #[allow(deprecated)]
    fn config_path() -> Result<PathBuf, Error> {
        env::home_dir()
            .map(|home| home.join(".kickflip.toml"))
            .ok_or(Error::HomeDirNotFound)
    }

    /// Load config from a specific path
    fn load_from_path(path: &PathBuf) -> Result<Self, Error> {
        let config_str = fs::read_to_string(path).map_err(Error::Io)?;
        toml::from_str(&config_str).map_err(Error::TomlParse)
    }

    /// Save config to disk
    pub fn save(&self) -> Result<(), Error> {
        let config_path = Self::config_path()?;

        let config_str = toml::to_string_pretty(self).map_err(Error::TomlSerialize)?;
        fs::write(config_path, config_str).map_err(Error::Io)
    }

    /// Load config, falling back to defaults, then save if file didn't exist
    pub fn load_or_create() -> Result<Self, Error> {
        let config_path = Self::config_path()?;

        match Self::load_from_path(&config_path) {
            Ok(config) => Ok(config),
            Err(Error::Io(_)) => {
                // File doesn't exist, create default config and save it
                let default_config = Self::default();
                default_config.save()?;
                Ok(default_config)
            }
            Err(e) => Err(e), // Other errors (parsing, etc.) should bubble up
        }
    }

    /// Update server URL and save
    pub fn set_server_url(&mut self, url: String) -> Result<(), Error> {
        self.server_url = url;
        self.save()
    }

    /// Builder pattern for chaining updates
    pub fn with_server_url(mut self, url: String) -> Self {
        self.server_url = url;
        self
    }

    pub fn with_ssh_user(mut self, user: String) -> Self {
        self.ssh_user = user;
        self
    }
}

/// Global config loading functions using unwrap_or_default
pub fn load_config() -> Config {
    Config::load() // This already uses unwrap_or_default internally
}

/// Load config with environment variable fallbacks
pub fn load_config_with_env() -> Config {
    let mut config = Config::load();

    // Override with environment variables if present
    config.server_url = std::env::var("KICKFLIP_SERVER_URL").unwrap_or(config.server_url);
    config.ssh_user = std::env::var("KICKFLIP_SSH_USER").unwrap_or(config.ssh_user);

    config
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Home directory not found")]
    HomeDirNotFound,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parsing error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert_eq!(config.server_url, "https://localhost:8080");
        assert_eq!(config.ssh_user, "kickflip");
    }

    #[test]
    fn test_config_new() {
        let config = Config::new();
        assert_eq!(config.server_url, "https://localhost:8080");
        assert_eq!(config.ssh_user, "kickflip");
    }

    #[test]
    fn test_load_fallback() {
        // This should not panic even if file doesn't exist
        let config = Config::load();
        assert!(!config.server_url.is_empty());
    }

    #[test]
    fn test_builder_pattern() {
        let config = Config::new().with_server_url("https://example.com".to_string());
        assert_eq!(config.server_url, "https://example.com");
    }
}
