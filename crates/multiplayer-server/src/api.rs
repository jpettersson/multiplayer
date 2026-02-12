use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;
use crate::auth::{AuthUser, sha256_hex};

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

pub struct RateLimiter {
    attempts: Mutex<HashMap<(IpAddr, u64), u32>>,
    max_attempts: u32,
}

impl RateLimiter {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
        }
    }

    fn current_minute() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60
    }

    pub fn check_and_increment(&self, ip: IpAddr) -> bool {
        let minute = Self::current_minute();
        let mut attempts = self.attempts.lock().unwrap();

        // Clean old entries
        attempts.retain(|&(_, m), _| m >= minute.saturating_sub(1));

        let key = (ip, minute);
        let count = attempts.entry(key).or_insert(0);
        *count += 1;
        *count <= self.max_attempts
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub secret: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub token: String,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub session_name: String,
    pub host_wg_public_key: String,
    pub ssh_user: String,
    pub ssh_private_key_b64: String,
}

#[derive(Serialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub join_url: String,
    pub wg_config: WgConfigResponse,
}

#[derive(Serialize)]
pub struct WgConfigResponse {
    pub host_address: String,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub allowed_ips: String,
}

#[derive(Deserialize)]
pub struct JoinRequest {
    pub token: String,
    pub guest_wg_public_key: String,
}

#[derive(Serialize)]
pub struct JoinResponse {
    pub wg_config: GuestWgConfigResponse,
    pub ssh_token: String,
}

#[derive(Serialize)]
pub struct GuestWgConfigResponse {
    pub guest_address: String,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub allowed_ips: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_session_id() -> String {
    let bytes: [u8; 16] = rand::thread_rng().r#gen();
    hex::encode(&bytes)
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// We use a simple hex encoding module since we only need it for session IDs
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> std::result::Result<Json<RegisterResponse>, StatusCode> {
    // Check registration secret
    match &state.register_secret {
        Some(expected) => {
            let provided = req.secret.as_deref().unwrap_or("");
            if provided != expected {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        None => {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let username = req.username.trim().to_string();
    if username.is_empty() || username.len() > 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(StatusCode::BAD_REQUEST);
    }

    if state.db.username_exists(&username).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)? {
        return Err(StatusCode::CONFLICT);
    }

    let token = generate_token();
    let token_hash = sha256_hex(&token);

    state
        .db
        .create_user(&username, &token_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("registered user: {username}");

    Ok(Json(RegisterResponse { token }))
}

pub async fn create_session(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Json(req): Json<CreateSessionRequest>,
) -> std::result::Result<Json<CreateSessionResponse>, StatusCode> {
    // Limit active sessions per user
    let count = state
        .db
        .user_active_session_count(user.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if count >= 5 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let session_id = generate_session_id();
    let join_token = generate_token();
    let join_token_hash = sha256_hex(&join_token);

    let subnet_index = state
        .db
        .next_subnet_index()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let host_address = format!("10.100.{subnet_index}.1/24");
    let server_address = format!("10.100.{subnet_index}.254/24");
    let subnet = format!("10.100.{subnet_index}.0/24");
    let interface_name = format!("wg-mp-{subnet_index}");

    // Generate server WG keypair for this session
    let (server_private_key, server_public_key) = state.wg.generate_keypair()
        .map_err(|e| {
            tracing::error!("WG keypair generation failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Write WG config and bring up interface
    state.wg.write_server_config(
        &interface_name,
        &server_private_key,
        &server_address,
        state.wg_port_start + subnet_index as u16,
    )
    .map_err(|e| {
        tracing::error!("WG config write failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    state.wg.interface_up(&interface_name).map_err(|e| {
        tracing::error!("WG interface up failed: {e}");
        state.wg.remove_config(&interface_name);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Add host as peer
    let host_allowed = format!("10.100.{subnet_index}.1/32");
    state.wg.add_peer(&interface_name, &req.host_wg_public_key, &host_allowed)
        .map_err(|e| {
            tracing::error!("WG add host peer failed: {e}");
            let _ = state.wg.interface_down(&interface_name);
            state.wg.remove_config(&interface_name);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Save to DB
    state
        .db
        .create_session(
            &session_id,
            user.id,
            &req.session_name,
            &join_token_hash,
            &req.host_wg_public_key,
            &req.ssh_user,
            &req.ssh_private_key_b64,
            &interface_name,
            subnet_index,
            &host_address,
        )
        .map_err(|e| {
            tracing::error!("DB create session failed: {e}");
            let _ = state.wg.interface_down(&interface_name);
            state.wg.remove_config(&interface_name);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let join_url = format!("{}/s/{}/{}", state.server_url, session_id, join_token);
    let server_endpoint = format!("{}:{}", state.wg_endpoint, state.wg_port_start + subnet_index as u16);

    tracing::info!("created session: {session_id} for user: {}", user.username);

    Ok(Json(CreateSessionResponse {
        session_id,
        join_url,
        wg_config: WgConfigResponse {
            host_address,
            server_public_key,
            server_endpoint,
            allowed_ips: subnet,
        },
    }))
}

pub async fn join_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<JoinRequest>,
) -> std::result::Result<Json<JoinResponse>, StatusCode> {
    // Rate limiting — use 127.0.0.1 as fallback (real deployments use a reverse proxy header)
    let ip: IpAddr = "127.0.0.1".parse().unwrap();
    if !state.rate_limiter.check_and_increment(ip) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let session = state
        .db
        .find_session_by_session_id(&session_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify token
    let token_hash = sha256_hex(&req.token);
    if token_hash != session.join_token_hash {
        return Err(StatusCode::FORBIDDEN);
    }

    // Allocate peer address
    let peer_index = state
        .db
        .next_peer_index(session.id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let guest_address = format!("10.100.{}.{}/24", session.subnet_index, peer_index);
    let subnet = format!("10.100.{}.0/24", session.subnet_index);

    // Add guest WG peer
    let guest_allowed = format!("10.100.{}.{}/32", session.subnet_index, peer_index);
    state.wg.add_peer(&session.wg_interface, &req.guest_wg_public_key, &guest_allowed)
        .map_err(|e| {
            tracing::error!("WG add guest peer failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Save peer to DB
    state
        .db
        .add_peer(session.id, &req.guest_wg_public_key, &guest_address, peer_index)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build SSH token (mp:// format pointing at host's WG IP)
    let host_ip = format!("10.100.{}.1", session.subnet_index);
    let ssh_token = format!(
        "mp://{}@{}:22/{}#{}",
        session.ssh_user, host_ip, session.session_name, session.ssh_private_key_b64
    );

    let server_endpoint = format!(
        "{}:{}",
        state.wg_endpoint,
        state.wg_port_start + session.subnet_index as u16
    );

    // Read server public key from the WG interface
    let server_public_key = state.wg.get_interface_public_key(&session.wg_interface)
        .unwrap_or_default();

    tracing::info!("guest joined session: {session_id} as peer {peer_index}");

    Ok(Json(JoinResponse {
        wg_config: GuestWgConfigResponse {
            guest_address,
            server_public_key,
            server_endpoint,
            allowed_ips: subnet,
        },
        ssh_token,
    }))
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    AuthUser(_user): AuthUser,
    Path(session_id): Path<String>,
) -> StatusCode {
    match state.db.update_heartbeat(&session_id) {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    AuthUser(user): AuthUser,
    Path(session_id): Path<String>,
) -> StatusCode {
    // Verify session belongs to user
    let session = match state.db.find_session_by_session_id(&session_id) {
        Ok(Some(s)) => s,
        Ok(None) => return StatusCode::NOT_FOUND,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    if session.user_id != user.id {
        return StatusCode::FORBIDDEN;
    }

    // Tear down WG interface
    let _ = state.wg.interface_down(&session.wg_interface);
    state.wg.remove_config(&session.wg_interface);

    // Delete from DB (cascade deletes peers)
    match state.db.delete_session(&session_id) {
        Ok(true) => {
            tracing::info!("deleted session: {session_id}");
            StatusCode::NO_CONTENT
        }
        Ok(false) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
