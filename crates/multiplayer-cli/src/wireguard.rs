use std::fs;
use std::process::{Command, Stdio};

use crate::{Result, err};

pub fn generate_keypair() -> Result<(String, String)> {
    let privkey_output = Command::new("wg")
        .arg("genkey")
        .output()
        .map_err(|e| err(format!("Failed to run wg genkey: {e}")))?;

    if !privkey_output.status.success() {
        return Err(err("wg genkey failed"));
    }

    let private_key = String::from_utf8_lossy(&privkey_output.stdout).trim().to_string();

    let pubkey_output = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(private_key.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| err(format!("Failed to run wg pubkey: {e}")))?;

    if !pubkey_output.status.success() {
        return Err(err("wg pubkey failed"));
    }

    let public_key = String::from_utf8_lossy(&pubkey_output.stdout).trim().to_string();

    Ok((private_key, public_key))
}

pub fn write_client_config(
    config_path: &str,
    private_key: &str,
    address: &str,
    server_public_key: &str,
    server_endpoint: &str,
    allowed_ips: &str,
) -> Result<()> {
    let config = format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = {address}\n\
         \n\
         [Peer]\n\
         PublicKey = {server_public_key}\n\
         Endpoint = {server_endpoint}\n\
         AllowedIPs = {allowed_ips}\n\
         PersistentKeepalive = 25\n"
    );
    fs::write(config_path, &config).map_err(|e| err(format!("Failed to write WG config: {e}")))?;
    Ok(())
}

pub fn up(config_path: &str) -> Result<()> {
    println!("  Setting up secure tunnel (requires sudo)...");
    let status = Command::new("sudo")
        .args(["wg-quick", "up", config_path])
        .status()
        .map_err(|e| err(format!("Failed to run wg-quick up: {e}")))?;

    if !status.success() {
        return Err(err("wg-quick up failed"));
    }
    Ok(())
}

pub fn down(config_path: &str) -> Result<()> {
    let status = Command::new("sudo")
        .args(["wg-quick", "down", config_path])
        .stderr(Stdio::null())
        .status()
        .map_err(|e| err(format!("Failed to run wg-quick down: {e}")))?;

    if !status.success() {
        // May already be down
    }
    Ok(())
}
