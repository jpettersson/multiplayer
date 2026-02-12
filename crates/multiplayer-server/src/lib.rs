pub mod api;
pub mod auth;
pub mod db;
pub mod wireguard;

use axum::Router;
use axum::routing::{delete, post};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn err(msg: impl Into<String>) -> Error {
    Error::Msg(msg.into())
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

pub struct AppState {
    pub db: db::Db,
    pub server_url: String,
    pub wg_endpoint: String,
    pub wg_port_start: u16,
    pub rate_limiter: api::RateLimiter,
    pub register_secret: Option<String>,
    pub wg: Box<dyn wireguard::WgOps>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/register", post(api::register))
        .route("/api/sessions", post(api::create_session))
        .route("/api/sessions/{id}/join", post(api::join_session))
        .route("/api/sessions/{id}/heartbeat", post(api::heartbeat))
        .route("/api/sessions/{id}", delete(api::delete_session))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Session expiry
// ---------------------------------------------------------------------------

pub fn expire_sessions(state: &AppState) {
    match state.db.find_expired_sessions(60) {
        Ok(sessions) => {
            for session in sessions {
                tracing::info!("expiring session: {} (no heartbeat for 60s)", session.session_id);
                let _ = state.wg.interface_down(&session.wg_interface);
                state.wg.remove_config(&session.wg_interface);
                let _ = state.db.delete_session(&session.session_id);
            }
        }
        Err(e) => {
            tracing::error!("failed to check expired sessions: {e}");
        }
    }
}
