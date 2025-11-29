use serde::{Deserialize, Serialize};

pub const AUTH_VERSION: &str = "kickflip-auth-v1";

pub const ROUTE_CONNECT: &str = "/connect";
pub const ROUTE_AUTH: &str = "/auth";

/// `KeyId` is the SHA256 fingerprint string of the OpenSSH public key (e.g., "SHA256:...")
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl KeyId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid_format(&self) -> bool {
        self.0.starts_with("SHA256:") && self.0.len() > 7
    }
}
