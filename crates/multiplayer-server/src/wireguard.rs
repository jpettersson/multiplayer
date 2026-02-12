use std::process::Command;
use std::fs;

use crate::{Result, err};

// ---------------------------------------------------------------------------
// Trait for WireGuard operations (enables mocking in tests)
// ---------------------------------------------------------------------------

pub trait WgOps: Send + Sync {
    fn generate_keypair(&self) -> Result<(String, String)>;
    fn write_server_config(
        &self,
        interface_name: &str,
        private_key: &str,
        address: &str,
        listen_port: u16,
    ) -> Result<String>;
    fn interface_up(&self, interface_name: &str) -> Result<()>;
    fn interface_down(&self, interface_name: &str) -> Result<()>;
    fn add_peer(
        &self,
        interface_name: &str,
        public_key: &str,
        allowed_ips: &str,
    ) -> Result<()>;
    fn remove_config(&self, interface_name: &str);
    fn get_interface_public_key(&self, interface_name: &str) -> Option<String>;
}

// ---------------------------------------------------------------------------
// Real implementation (shells out to wg/wg-quick)
// ---------------------------------------------------------------------------

pub struct SystemWgOps;

impl WgOps for SystemWgOps {
    fn generate_keypair(&self) -> Result<(String, String)> {
        generate_keypair()
    }
    fn write_server_config(
        &self,
        interface_name: &str,
        private_key: &str,
        address: &str,
        listen_port: u16,
    ) -> Result<String> {
        write_server_config(interface_name, private_key, address, listen_port)
    }
    fn interface_up(&self, interface_name: &str) -> Result<()> {
        interface_up(interface_name)
    }
    fn interface_down(&self, interface_name: &str) -> Result<()> {
        interface_down(interface_name)
    }
    fn add_peer(&self, interface_name: &str, public_key: &str, allowed_ips: &str) -> Result<()> {
        add_peer(interface_name, public_key, allowed_ips)
    }
    fn remove_config(&self, interface_name: &str) {
        remove_config(interface_name)
    }
    fn get_interface_public_key(&self, interface_name: &str) -> Option<String> {
        get_interface_public_key(interface_name)
    }
}

// ---------------------------------------------------------------------------
// Standalone functions (used by SystemWgOps)
// ---------------------------------------------------------------------------

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
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
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

pub fn write_server_config(
    interface_name: &str,
    private_key: &str,
    address: &str,
    listen_port: u16,
) -> Result<String> {
    let config = format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = {address}\nListenPort = {listen_port}\n"
    );

    let path = format!("/etc/wireguard/{interface_name}.conf");
    fs::write(&path, &config).map_err(|e| err(format!("Failed to write WG config {path}: {e}")))?;
    Ok(path)
}

pub fn interface_up(interface_name: &str) -> Result<()> {
    let status = Command::new("wg-quick")
        .args(["up", interface_name])
        .status()
        .map_err(|e| err(format!("Failed to run wg-quick up: {e}")))?;

    if !status.success() {
        return Err(err(format!("wg-quick up {interface_name} failed")));
    }
    Ok(())
}

pub fn interface_down(interface_name: &str) -> Result<()> {
    let status = Command::new("wg-quick")
        .args(["down", interface_name])
        .status()
        .map_err(|e| err(format!("Failed to run wg-quick down: {e}")))?;

    if !status.success() {
        // Interface may already be down
        tracing::warn!("wg-quick down {interface_name} returned non-zero (may already be down)");
    }
    Ok(())
}

pub fn add_peer(
    interface_name: &str,
    public_key: &str,
    allowed_ips: &str,
) -> Result<()> {
    let status = Command::new("wg")
        .args(["set", interface_name, "peer", public_key, "allowed-ips", allowed_ips])
        .status()
        .map_err(|e| err(format!("Failed to run wg set: {e}")))?;

    if !status.success() {
        return Err(err(format!("wg set peer failed for {interface_name}")));
    }
    Ok(())
}

pub fn remove_config(interface_name: &str) {
    let path = format!("/etc/wireguard/{interface_name}.conf");
    let _ = fs::remove_file(&path);
}

pub fn get_interface_public_key(interface_name: &str) -> Option<String> {
    let output = Command::new("wg")
        .args(["show", interface_name, "public-key"])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}
