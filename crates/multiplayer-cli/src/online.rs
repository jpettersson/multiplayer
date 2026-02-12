use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;

use crate::{Result, err};
use crate::config;
use crate::lan;
use crate::wireguard;

// ---------------------------------------------------------------------------
// Session info (JSON)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct OnlineSessionInfo {
    session_name: String,
    session_id: String,
    server_url: String,
    online: bool,
    wg_config_path: String,
    heartbeat_pid: Option<u32>,
}

fn session_info_path(session: &str) -> std::path::PathBuf {
    lan::tmp_session_info_path(session)
}

fn write_online_session_info(info: &OnlineSessionInfo) -> Result<()> {
    let json = serde_json::to_string_pretty(info)
        .map_err(|e| err(format!("Failed to serialize session info: {e}")))?;
    fs::write(session_info_path(&info.session_name), json)?;
    Ok(())
}

fn read_online_session_info(session: &str) -> Option<OnlineSessionInfo> {
    let content = fs::read_to_string(session_info_path(session)).ok()?;
    serde_json::from_str(&content).ok()
}

// ---------------------------------------------------------------------------
// API types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CreateSessionRequest {
    session_name: String,
    host_wg_public_key: String,
    ssh_user: String,
    ssh_private_key_b64: String,
}

#[derive(Deserialize)]
struct CreateSessionResponse {
    session_id: String,
    join_url: String,
    wg_config: WgConfigResponse,
}

#[derive(Deserialize)]
struct WgConfigResponse {
    host_address: String,
    server_public_key: String,
    server_endpoint: String,
    allowed_ips: String,
}

#[derive(Serialize)]
struct JoinRequest {
    token: String,
    guest_wg_public_key: String,
}

#[derive(Deserialize)]
struct JoinResponse {
    wg_config: GuestWgConfigResponse,
    ssh_token: String,
}

#[derive(Deserialize)]
struct GuestWgConfigResponse {
    guest_address: String,
    server_public_key: String,
    server_endpoint: String,
    allowed_ips: String,
}

// ---------------------------------------------------------------------------
// Start online session
// ---------------------------------------------------------------------------

pub async fn cmd_start_online(name: Option<String>) -> Result<()> {
    lan::check_dependencies(&["tmux", "ssh-keygen", "wg", "wg-quick"])?;

    let cfg = config::load_required()?;
    let server_url = cfg.server_url.unwrap();
    let auth_token = cfg.auth_token.unwrap();

    let session = match name {
        Some(n) => {
            lan::validate_session_name(&n)?;
            n
        }
        None => lan::generate_session_name(),
    };

    if lan::tmp_session_info_path(&session).exists() {
        return Err(err(format!(
            "Session '{session}' already exists. Run `multiplayer stop {session}` first."
        )));
    }

    // Generate WG keypair
    let (wg_private_key, wg_public_key) = wireguard::generate_keypair()?;

    // Generate SSH keypair
    lan::generate_ssh_keypair(&session)?;
    let ssh_private_key = fs::read_to_string(lan::tmp_key_path(&session))?;
    let ssh_private_key_b64 = URL_SAFE_NO_PAD.encode(ssh_private_key.as_bytes());

    let ssh_user = std::env::var("USER").unwrap_or_else(|_| "root".into());

    // Call server API
    let client = reqwest::Client::new();
    let url = format!("{}/api/sessions", server_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .bearer_auth(&auth_token)
        .json(&CreateSessionRequest {
            session_name: session.clone(),
            host_wg_public_key: wg_public_key,
            ssh_user: ssh_user.clone(),
            ssh_private_key_b64,
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        lan::cleanup_ssh_keys(&session);
        return Err(err(format!("Failed to create online session ({status}): {body}")));
    }

    let resp: CreateSessionResponse = resp.json().await?;

    // Write WG client config
    let wg_config_path = format!("/tmp/multiplayer-{session}-wg.conf");
    wireguard::write_client_config(
        &wg_config_path,
        &wg_private_key,
        &resp.wg_config.host_address,
        &resp.wg_config.server_public_key,
        &resp.wg_config.server_endpoint,
        &resp.wg_config.allowed_ips,
    )?;

    // Bring up WG interface
    if let Err(e) = wireguard::up(&wg_config_path) {
        lan::cleanup_ssh_keys(&session);
        let _ = fs::remove_file(&wg_config_path);
        return Err(e);
    }

    // Install SSH authorized_key and create tmux session
    lan::install_authorized_key(&session)?;
    lan::create_tmux_session(&session)?;

    // Spawn heartbeat daemon
    let exe = std::env::current_exe().map_err(|e| err(format!("Failed to get exe path: {e}")))?;
    let heartbeat_child = Command::new(&exe)
        .args([
            "--heartbeat-daemon",
            &server_url,
            &resp.session_id,
            &auth_token,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| err(format!("Failed to spawn heartbeat daemon: {e}")))?;

    let heartbeat_pid = heartbeat_child.id();

    // Write session info
    write_online_session_info(&OnlineSessionInfo {
        session_name: session.clone(),
        session_id: resp.session_id,
        server_url: server_url.clone(),
        online: true,
        wg_config_path,
        heartbeat_pid: Some(heartbeat_pid),
    })?;

    println!();
    println!("  {}  {}", "Session:".bold(), session.green().bold());
    println!();
    println!("  Share this link so others can join:");
    println!("    {} {}", "multiplayer join".cyan(), resp.join_url.cyan());
    println!();
    println!("  To enter your session:");
    println!("    {}", "multiplayer join".cyan());

    Ok(())
}

// ---------------------------------------------------------------------------
// Join online session
// ---------------------------------------------------------------------------

pub async fn cmd_join_online(url: &str) -> Result<()> {
    lan::check_dependencies(&["ssh", "wg", "wg-quick"])?;

    // Parse URL: https://server/s/{session_id}/{token}
    let (server_base, session_id, token) = parse_join_url(url)?;

    // Generate WG keypair
    let (wg_private_key, wg_public_key) = wireguard::generate_keypair()?;

    // Call join API
    let client = reqwest::Client::new();
    let api_url = format!("{}/api/sessions/{}/join", server_base, session_id);
    let resp = client
        .post(&api_url)
        .json(&JoinRequest {
            token,
            guest_wg_public_key: wg_public_key,
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(err(format!("Failed to join session ({status}): {body}")));
    }

    let resp: JoinResponse = resp.json().await?;

    // Write WG client config
    let wg_config_path = format!("/tmp/multiplayer-guest-{session_id}-wg.conf");
    wireguard::write_client_config(
        &wg_config_path,
        &wg_private_key,
        &resp.wg_config.guest_address,
        &resp.wg_config.server_public_key,
        &resp.wg_config.server_endpoint,
        &resp.wg_config.allowed_ips,
    )?;

    // Bring up WG interface
    if let Err(e) = wireguard::up(&wg_config_path) {
        let _ = fs::remove_file(&wg_config_path);
        return Err(e);
    }

    // Decode the ssh_token (mp:// format) and connect
    let ssh_token = &resp.ssh_token;
    if !ssh_token.starts_with("mp://") {
        let _ = wireguard::down(&wg_config_path);
        let _ = fs::remove_file(&wg_config_path);
        return Err(err("Invalid SSH token from server"));
    }

    // Parse mp:// token parts
    let rest = ssh_token.strip_prefix("mp://").unwrap();
    let (addr_session, encoded_key) = rest.split_once('#').ok_or_else(|| err("Invalid SSH token"))?;
    let (addr, session) = addr_session.split_once('/').ok_or_else(|| err("Invalid SSH token"))?;
    let (user_host, port_str) = addr.rsplit_once(':').ok_or_else(|| err("Invalid SSH token"))?;
    let port: u16 = port_str.parse().map_err(|_| err("Invalid SSH token port"))?;
    let (user, host) = user_host.split_once('@').ok_or_else(|| err("Invalid SSH token"))?;

    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| err("Invalid SSH token key"))?;
    let private_key = String::from_utf8(key_bytes).map_err(|_| err("Invalid SSH token key"))?;

    // Connect via SSH through WG tunnel
    let result = lan::join_with_key(user, session, host, port, &private_key);

    // Cleanup WG on disconnect
    let _ = wireguard::down(&wg_config_path);
    let _ = fs::remove_file(&wg_config_path);

    result
}

fn parse_join_url(url: &str) -> Result<(String, String, String)> {
    // URL format: https://server/s/{session_id}/{token}
    let url_parsed = url::Url::parse(url).map_err(|_| err("Invalid join URL"))?;

    let segments: Vec<&str> = url_parsed.path_segments()
        .ok_or_else(|| err("Invalid join URL: no path"))?
        .collect();

    // Expect: ["s", session_id, token]
    if segments.len() < 3 || segments[0] != "s" {
        return Err(err("Invalid join URL format. Expected: https://server/s/{session_id}/{token}"));
    }

    let session_id = segments[1].to_string();
    let token = segments[2].to_string();
    let server_base = format!("{}://{}", url_parsed.scheme(), url_parsed.host_str().unwrap_or(""));

    // Include port if present
    let server_base = if let Some(port) = url_parsed.port() {
        format!("{server_base}:{port}")
    } else {
        server_base
    };

    Ok((server_base, session_id, token))
}

// ---------------------------------------------------------------------------
// Stop (handles both online and LAN)
// ---------------------------------------------------------------------------

pub async fn cmd_stop(name: Option<String>) -> Result<()> {
    let session = match name {
        Some(n) => n,
        None => lan::find_active_session()
            .ok_or_else(|| err("No active session found. Specify a session name: multiplayer stop <name>"))?,
    };

    // Check if this is an online session
    if let Some(info) = read_online_session_info(&session) {
        if info.online {
            return stop_online(info).await;
        }
    }

    // LAN mode stop
    lan::cleanup_session(&session);

    println!();
    println!("  {} {}", "Stopped session:".bold(), session.yellow());
    println!("  Cleaned up tmux session and authorized_keys entry.");

    Ok(())
}

async fn stop_online(info: OnlineSessionInfo) -> Result<()> {
    // Kill heartbeat daemon
    if let Some(pid) = info.heartbeat_pid {
        let _ = Command::new("kill")
            .arg(pid.to_string())
            .status();
    }

    // Call server to delete session
    let cfg = config::load()?;
    if let Some(auth_token) = cfg.auth_token {
        let client = reqwest::Client::new();
        let url = format!(
            "{}/api/sessions/{}",
            info.server_url.trim_end_matches('/'),
            info.session_id
        );
        let _ = client
            .delete(&url)
            .bearer_auth(&auth_token)
            .send()
            .await;
    }

    // Tear down WG
    let _ = wireguard::down(&info.wg_config_path);
    let _ = fs::remove_file(&info.wg_config_path);

    // Clean up tmux + SSH keys
    lan::cleanup_session(&info.session_name);

    println!();
    println!("  {} {}", "Stopped session:".bold(), info.session_name.yellow());
    println!("  Cleaned up tunnel, tmux session, and authorized_keys entry.");

    Ok(())
}

// ---------------------------------------------------------------------------
// Heartbeat daemon (invoked via hidden --heartbeat-daemon flag)
// ---------------------------------------------------------------------------

pub async fn run_heartbeat_daemon(server_url: &str, session_id: &str, auth_token: &str) {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/sessions/{}/heartbeat",
        server_url.trim_end_matches('/'),
        session_id
    );

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let result = client
            .post(&url)
            .bearer_auth(auth_token)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() || resp.status() == 204 => {}
            Ok(resp) => {
                eprintln!("heartbeat failed: {}", resp.status());
            }
            Err(e) => {
                eprintln!("heartbeat error: {e}");
            }
        }
    }
}
