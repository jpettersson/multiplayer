mod config;
mod lan;
mod online;
mod wireguard;

use clap::{Parser, Subcommand};
use colored::Colorize;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "multiplayer", about = "Instant shared terminal sessions")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start a new multiplayer session
    Start {
        /// Session name (default: random adjective-animal)
        #[arg(long)]
        name: Option<String>,
        /// Create an internet session via the relay server
        #[arg(long)]
        online: bool,
    },
    /// Join a session (local attach if no token, remote SSH if token given)
    Join {
        /// mp:// token, join URL, or omit to attach to local session
        target: Option<String>,
    },
    /// Stop the current session and clean up
    Stop {
        /// Session name (auto-detected if omitted)
        name: Option<String>,
    },
    /// Show current session info
    Status {
        /// Session name (auto-detected if omitted)
        name: Option<String>,
    },
    /// Register with a multiplayer relay server
    Register {
        /// Server URL
        #[arg(long)]
        server: String,
        /// Username
        #[arg(long)]
        username: String,
        /// Registration secret (provided by the server admin)
        #[arg(long)]
        secret: String,
    },
    /// Login to a multiplayer relay server
    Login {
        /// Server URL
        #[arg(long)]
        server: String,
        /// Auth token
        #[arg(long)]
        token: String,
    },
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("{0}")]
    Msg(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn err(msg: impl Into<String>) -> Error {
    Error::Msg(msg.into())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Hidden heartbeat daemon mode (spawned as subprocess)
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 5 && args[1] == "--heartbeat-daemon" {
        online::run_heartbeat_daemon(&args[2], &args[3], &args[4]).await;
        return;
    }

    let cli = Cli::parse();

    let result = match cli.command {
        Cmd::Start { name, online } => {
            if online {
                online::cmd_start_online(name).await
            } else {
                lan::cmd_start(name)
            }
        }
        Cmd::Join { target } => cmd_join(target).await,
        Cmd::Stop { name } => online::cmd_stop(name).await,
        Cmd::Status { name } => lan::cmd_status(name),
        Cmd::Register { server, username, secret } => cmd_register(server, username, secret).await,
        Cmd::Login { server, token } => cmd_login(server, token),
    };

    if let Err(e) = result {
        eprintln!("  {} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

async fn cmd_join(target: Option<String>) -> Result<()> {
    match &target {
        None => lan::cmd_join(None),
        Some(t) if t.starts_with("mp://") => lan::cmd_join(target),
        Some(t) if t.starts_with("http://") || t.starts_with("https://") => {
            online::cmd_join_online(t).await
        }
        Some(_) => lan::cmd_join(target),
    }
}

async fn cmd_register(server: String, username: String, secret: String) -> Result<()> {
    #[derive(serde::Serialize)]
    struct Req {
        username: String,
        secret: String,
    }
    #[derive(serde::Deserialize)]
    struct Resp {
        token: String,
    }

    let url = format!("{}/api/register", server.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&Req { username: username.clone(), secret })
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(err(format!("Registration failed ({status}): {body}")));
    }

    let resp: Resp = resp.json().await?;

    config::save(&config::Config {
        server_url: Some(server.clone()),
        auth_token: Some(resp.token),
    })?;

    println!();
    println!("  {} Registered as {} on {}", "OK".green().bold(), username.bold(), server);
    println!("  Config saved to ~/.config/multiplayer/config.toml");

    Ok(())
}

fn cmd_login(server: String, token: String) -> Result<()> {
    config::save(&config::Config {
        server_url: Some(server.clone()),
        auth_token: Some(token),
    })?;

    println!();
    println!("  {} Logged in to {}", "OK".green().bold(), server);
    println!("  Config saved to ~/.config/multiplayer/config.toml");

    Ok(())
}
