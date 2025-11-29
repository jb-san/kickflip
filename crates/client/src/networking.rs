use crate::ssh;
use kickflip_proto::api::{
    AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, DisconnectRequest,
    DisconnectResponse,
};
use kickflip_proto::b64::decode_url_nopad;
use kickflip_proto::types::KeyId;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Stored connection info for disconnect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub subdomain: String,
    pub server_url: String,
    pub reverse_port: u16,
    pub local_port: u16,
}

fn connection_file_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home)
        .join(".kickflip")
        .join("connection.json")
}

fn save_connection_info(info: &ConnectionInfo) -> std::io::Result<()> {
    let path = connection_file_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(info)?;
    fs::write(path, json)
}

pub fn load_connection_info() -> Option<ConnectionInfo> {
    let path = connection_file_path();
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn clear_connection_info() {
    let _ = fs::remove_file(connection_file_path());
}

pub fn connect(
    server_url: &str,
    subdomain: &str,
    remote_port: u16,
    local_port: u16,
    ssh_user: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    let key_id_str = ssh::derive_key_id()?;

    let req = ConnectRequest {
        subdomain: subdomain.to_string(),
        protocol: None,
        remote_port: Some(remote_port),
        local_port,
        key_id: KeyId(key_id_str.clone()),
    };

    let response = client
        .post(&format!("{}/connect", server_url))
        .json(&req)
        .send()?;

    match response.status() {
        StatusCode::OK => {
            let resp = response.json::<ConnectResponse>()?;
            let challenge_bytes = decode_url_nopad(&resp.challenge)?;
            let challenge_str = String::from_utf8_lossy(&challenge_bytes);
            let signature = ssh::sign_message(challenge_str.as_ref())?;
            let auth_req = AuthRequest {
                challenge_id: resp.challenge_id,
                key_id: KeyId(key_id_str),
                signature,
            };
            let response = client
                .post(&format!("{}/auth", server_url))
                .json(&auth_req)
                .send()?;
            match response.status() {
                StatusCode::OK => {
                    let auth = response.json::<AuthResponse>()?;
                    if !auth.ok {
                        return Err(format!(
                            "Auth failed: {}",
                            auth.message.unwrap_or_default()
                        )
                        .into());
                    }
                    println!("✅ Authenticated successfully");

                    // Save connection info for later disconnect
                    let conn_info = ConnectionInfo {
                        subdomain: subdomain.to_string(),
                        server_url: server_url.to_string(),
                        reverse_port: resp.reverse_port,
                        local_port,
                    };
                    if let Err(e) = save_connection_info(&conn_info) {
                        eprintln!("Warning: could not save connection info: {}", e);
                    }

                    // Open reverse SSH tunnel
                    let server_host = extract_host(server_url).unwrap_or("localhost".to_string());
                    ssh::open_reverse_tunnel(&server_host, resp.reverse_port, local_port, ssh_user)?;
                    Ok(())
                }
                _ => Err(Box::new(response.error_for_status().unwrap_err())),
            }
        }
        StatusCode::CONFLICT => Err("Subdomain already connected".into()),
        _ => Err(Box::new(response.error_for_status().unwrap_err())),
    }
}

/// Notify server that we're disconnecting
pub fn disconnect(server_url: &str, subdomain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    let key_id_str = ssh::derive_key_id()?;

    let req = DisconnectRequest {
        subdomain: subdomain.to_string(),
        key_id: KeyId(key_id_str),
    };

    let response = client
        .post(&format!("{}/disconnect", server_url))
        .json(&req)
        .send()?;

    match response.status() {
        StatusCode::OK => {
            let resp = response.json::<DisconnectResponse>()?;
            if resp.ok {
                clear_connection_info();
                Ok(())
            } else {
                Err(format!(
                    "Disconnect failed: {}",
                    resp.message.unwrap_or_default()
                )
                .into())
            }
        }
        StatusCode::NOT_FOUND => {
            // Server doesn't know about this connection, still clean up locally
            clear_connection_info();
            Ok(())
        }
        _ => Err(Box::new(response.error_for_status().unwrap_err())),
    }
}

fn extract_host(url: &str) -> Option<String> {
    let url = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    Some(url.split('/').next()?.split(':').next()?.to_string())
}
