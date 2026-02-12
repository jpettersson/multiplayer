use clap::Parser;
use std::sync::Arc;

use multiplayer_server::{AppState, api, build_router, db, expire_sessions, wireguard};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "multiplayer-server", about = "Multiplayer relay server")]
struct Cli {
    /// Address to bind to
    #[arg(long, env = "MULTIPLAYER_BIND", default_value = "0.0.0.0:8080")]
    bind: String,

    /// Public URL of this server (for join URLs)
    #[arg(long, env = "MULTIPLAYER_SERVER_URL", default_value = "http://localhost:8080")]
    server_url: String,

    /// Public IP/hostname for WireGuard endpoint
    #[arg(long, env = "MULTIPLAYER_WG_ENDPOINT")]
    wg_endpoint: String,

    /// Starting port for WireGuard interfaces
    #[arg(long, env = "MULTIPLAYER_WG_PORT_START", default_value = "51820")]
    wg_port_start: u16,

    /// SQLite database path
    #[arg(long, env = "MULTIPLAYER_DB_PATH", default_value = "multiplayer.db")]
    db_path: String,

    /// Secret required to register (if unset, registration is closed)
    #[arg(long, env = "MULTIPLAYER_REGISTER_SECRET")]
    register_secret: Option<String>,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let db = db::Db::open(&cli.db_path).expect("Failed to open database");

    let state = Arc::new(AppState {
        db,
        server_url: cli.server_url,
        wg_endpoint: cli.wg_endpoint,
        wg_port_start: cli.wg_port_start,
        rate_limiter: api::RateLimiter::new(10),
        register_secret: cli.register_secret,
        wg: Box::new(wireguard::SystemWgOps),
    });

    // Spawn background expiry task
    let expiry_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            expire_sessions(&expiry_state);
        }
    });

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&cli.bind)
        .await
        .expect("Failed to bind");

    tracing::info!("listening on {}", cli.bind);

    axum::serve(listener, app).await.expect("Server failed");
}
