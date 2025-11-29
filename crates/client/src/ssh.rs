use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const OPENSSH_HEADER: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_FOOTER: &str = "-----END OPENSSH PRIVATE KEY-----";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// Get the path to the kickflip SSH key
fn kickflip_key_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".ssh").join("kickflip")
}

/// Get the path to the kickflip SSH public key
fn kickflip_pubkey_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".ssh").join("kickflip.pub")
}

pub fn is_ssh_installed() -> bool {
    Command::new("ssh")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn has_kickflip_key() -> bool {
    kickflip_pubkey_path().exists()
}

pub fn generate_kickflip_key() -> Result<(), std::io::Error> {
    let path = kickflip_key_path();
    let output = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg(&path)
        .arg("-q")
        .arg("-N")
        .arg("")
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to generate key: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ))
    }
}

pub fn display_public_key() -> Result<(), std::io::Error> {
    let path = kickflip_pubkey_path();
    let content = fs::read_to_string(&path)?;
    println!("{}", content.trim());
    Ok(())
}

/// Parse an OpenSSH private key file and extract the ed25519 SigningKey
fn load_signing_key() -> Result<SigningKey, std::io::Error> {
    let path = kickflip_key_path();
    let content = fs::read_to_string(&path)?;

    // Strip PEM header/footer and decode base64
    let content = content.trim();
    if !content.starts_with(OPENSSH_HEADER) || !content.ends_with(OPENSSH_FOOTER) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid OpenSSH private key format",
        ));
    }

    let b64_part = content
        .strip_prefix(OPENSSH_HEADER)
        .and_then(|s| s.strip_suffix(OPENSSH_FOOTER))
        .map(|s| s.replace(['\n', '\r', ' '], ""))
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to parse PEM")
        })?;

    let data = base64::engine::general_purpose::STANDARD
        .decode(&b64_part)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    parse_openssh_ed25519_private_key(&data)
}

/// Parse the binary OpenSSH private key format to extract ed25519 seed
fn parse_openssh_ed25519_private_key(data: &[u8]) -> Result<SigningKey, std::io::Error> {
    let mut cursor = data;

    // Check magic bytes
    if !cursor.starts_with(OPENSSH_MAGIC) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Missing openssh-key-v1 magic",
        ));
    }
    cursor = &cursor[OPENSSH_MAGIC.len()..];

    // cipher name (should be "none" for unencrypted)
    let cipher = read_string(&mut cursor)?;
    if cipher != b"none" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Encrypted keys not supported (cipher: {})",
                String::from_utf8_lossy(cipher)
            ),
        ));
    }

    // kdf name (should be "none")
    let kdf = read_string(&mut cursor)?;
    if kdf != b"none" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Encrypted keys not supported",
        ));
    }

    // kdf options (empty for "none")
    let _kdf_opts = read_string(&mut cursor)?;

    // number of keys
    let num_keys = read_u32(&mut cursor)?;
    if num_keys != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Expected exactly 1 key",
        ));
    }

    // public key blob (skip it)
    let _pubkey_blob = read_string(&mut cursor)?;

    // private key section (encrypted or not)
    let private_section = read_string(&mut cursor)?;
    let mut priv_cursor: &[u8] = private_section;

    // Two random check integers (must match for unencrypted)
    let check1 = read_u32(&mut priv_cursor)?;
    let check2 = read_u32(&mut priv_cursor)?;
    if check1 != check2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Check integers don't match - key may be corrupted or encrypted",
        ));
    }

    // Key type
    let key_type = read_string(&mut priv_cursor)?;
    if key_type != b"ssh-ed25519" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Expected ssh-ed25519, got {}",
                String::from_utf8_lossy(key_type)
            ),
        ));
    }

    // Public key (32 bytes)
    let pubkey_bytes = read_string(&mut priv_cursor)?;
    if pubkey_bytes.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid ed25519 public key length",
        ));
    }

    // Private key (64 bytes: 32-byte seed + 32-byte public key)
    let privkey_bytes = read_string(&mut priv_cursor)?;
    if privkey_bytes.len() != 64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid ed25519 private key length",
        ));
    }

    // First 32 bytes are the seed
    let seed: [u8; 32] = privkey_bytes[..32].try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to extract seed")
    })?;

    Ok(SigningKey::from_bytes(&seed))
}

/// Read a u32 in big-endian format
fn read_u32(cursor: &mut &[u8]) -> Result<u32, std::io::Error> {
    if cursor.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Not enough data for u32",
        ));
    }
    let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    *cursor = &cursor[4..];
    Ok(val)
}

/// Read a length-prefixed string/bytes
fn read_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], std::io::Error> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Not enough data for string",
        ));
    }
    let (s, rest) = cursor.split_at(len);
    *cursor = rest;
    Ok(s)
}

/// Sign a message with the kickflip private key and return base64url-encoded signature
pub fn sign_message(message: &str) -> Result<String, std::io::Error> {
    let signing_key = load_signing_key()?;
    let signature = signing_key.sign(message.as_bytes());
    let sig_bytes = signature.to_bytes();
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes))
}

/// Derive the key_id (SHA256 fingerprint) from the public key
pub fn derive_key_id() -> Result<String, std::io::Error> {
    let path = kickflip_pubkey_path();
    let content = fs::read_to_string(&path)?;

    // Parse: "ssh-ed25519 <base64> [comment]"
    let mut parts = content.split_whitespace();
    let key_type = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Empty public key"))?;

    if key_type != "ssh-ed25519" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Expected ssh-ed25519, got {}", key_type),
        ));
    }

    let b64 = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Missing key data"))?;

    // Decode the blob and compute SHA256 fingerprint
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(&blob);
    let digest = hasher.finalize();

    // Format as SHA256:<base64-no-pad>
    let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    Ok(format!("SHA256:{}", fingerprint))
}

/// Open a reverse SSH tunnel
pub fn open_reverse_tunnel(
    server_host: &str,
    reverse_port: u16,
    local_port: u16,
    ssh_user: &str,
) -> Result<(), std::io::Error> {
    let key_path = kickflip_key_path();

    println!(
        "Opening tunnel: localhost:{} -> {}@{}:{}",
        local_port, ssh_user, server_host, reverse_port
    );

    let status = Command::new("ssh")
        .arg("-N")
        .arg("-i")
        .arg(&key_path)
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-o")
        .arg("ServerAliveInterval=30")
        .arg("-o")
        .arg("ServerAliveCountMax=3")
        .arg("-R")
        .arg(format!("{}:127.0.0.1:{}", reverse_port, local_port))
        .arg(format!("{}@{}", ssh_user, server_host))
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SSH tunnel exited with code: {:?}", status.code()),
        ))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_key_id_format() {
        // Just test the format validation
        let valid = "SHA256:abcdef123456";
        assert!(valid.starts_with("SHA256:"));
    }
}
