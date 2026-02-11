use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use colored::Colorize;
use rand::Rng;
use std::fs;
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "multiplayer", about = "Instant shared terminal sessions on LAN")]
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
    },
    /// Join a session (local attach if no token, remote SSH if token given)
    Join {
        /// mp:// token (omit to attach to local session)
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
}

type Result<T> = std::result::Result<T, Error>;

fn err(msg: impl Into<String>) -> Error {
    Error::Msg(msg.into())
}

// ---------------------------------------------------------------------------
// Session name generator (adjective-animal)
// ---------------------------------------------------------------------------

const ADJECTIVES: &[&str] = &[
    "brave", "calm", "daring", "eager", "fancy", "gentle", "happy", "jolly",
    "keen", "lively", "merry", "noble", "proud", "quick", "rapid", "sharp",
    "swift", "tall", "vivid", "witty", "bold", "cool", "crisp", "fresh",
    "grand", "hungry", "icy", "lucky", "mighty", "neat",
];

const ANIMALS: &[&str] = &[
    "otter", "falcon", "panda", "wolf", "tiger", "hawk", "dolphin", "fox",
    "eagle", "bear", "lynx", "raven", "cobra", "crane", "bison", "shark",
    "whale", "koala", "gecko", "heron", "moose", "viper", "finch", "badger",
    "trout", "robin", "squid", "lemur", "newt", "stork",
];

fn generate_session_name() -> String {
    let mut rng = rand::thread_rng();
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let animal = ANIMALS[rng.gen_range(0..ANIMALS.len())];
    format!("{adj}-{animal}")
}

fn validate_session_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(err("Session name cannot be empty"));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(err("Session name must contain only alphanumeric characters and hyphens"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn tmp_key_path(session: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/multiplayer-{session}-key"))
}

fn tmp_pub_key_path(session: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/multiplayer-{session}-key.pub"))
}

fn tmp_session_info_path(session: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/multiplayer-{session}-info"))
}

fn authorized_keys_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".ssh").join("authorized_keys")
}

// ---------------------------------------------------------------------------
// Dependency checking
// ---------------------------------------------------------------------------

fn check_dependency(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn check_dependencies(deps: &[&str]) -> Result<()> {
    let missing: Vec<&str> = deps.iter().filter(|d| !check_dependency(d)).copied().collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(err(format!(
            "Missing required dependencies: {}. Install them and try again.",
            missing.join(", ")
        )))
    }
}

// ---------------------------------------------------------------------------
// Host IP detection
// ---------------------------------------------------------------------------

fn get_local_ip() -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| err(format!("Failed to bind UDP socket: {e}")))?;
    socket
        .connect("8.8.8.8:80")
        .map_err(|e| err(format!("Failed to determine local IP: {e}")))?;
    let addr = socket.local_addr().map_err(|e| err(format!("Failed to get local address: {e}")))?;
    Ok(addr.ip().to_string())
}

// ---------------------------------------------------------------------------
// SSH key management
// ---------------------------------------------------------------------------

fn generate_ssh_keypair(session: &str) -> Result<()> {
    let key_path = tmp_key_path(session);
    // Remove existing key files if they exist
    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(tmp_pub_key_path(session));

    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&key_path)
        .args(["-N", "", "-q"])
        .status()?;

    if !status.success() {
        return Err(err("ssh-keygen failed"));
    }
    Ok(())
}

fn install_authorized_key(session: &str) -> Result<()> {
    let pub_key = fs::read_to_string(tmp_pub_key_path(session))?;
    let pub_key = pub_key.trim();

    // Extract just the key type and key data (drop any existing comment)
    let parts: Vec<&str> = pub_key.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(err("Invalid public key format"));
    }
    let key_type = parts[0];
    let key_data = parts[1];

    let ak_path = authorized_keys_path();
    // Ensure ~/.ssh directory exists
    if let Some(parent) = ak_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmux_path = resolve_tmux_path()?;
    let entry = format!(
        "command=\"{tmux_path} -u attach -t {session}\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding {key_type} {key_data} multiplayer:{session}\n"
    );

    // Append to authorized_keys
    let mut existing = fs::read_to_string(&ak_path).unwrap_or_default();
    if !existing.is_empty() && !existing.ends_with('\n') {
        existing.push('\n');
    }
    existing.push_str(&entry);
    fs::write(&ak_path, existing)?;

    Ok(())
}

fn remove_authorized_key(session: &str) -> Result<()> {
    let ak_path = authorized_keys_path();
    if !ak_path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(&ak_path)?;
    let tag = format!("multiplayer:{session}");
    let filtered: String = content
        .lines()
        .filter(|line| !line.contains(&tag))
        .map(|line| format!("{line}\n"))
        .collect();
    fs::write(&ak_path, filtered)?;
    Ok(())
}

fn cleanup_ssh_keys(session: &str) {
    let _ = fs::remove_file(tmp_key_path(session));
    let _ = fs::remove_file(tmp_pub_key_path(session));
}

// ---------------------------------------------------------------------------
// tmux path resolution
// ---------------------------------------------------------------------------

/// Resolve the absolute path to tmux so that the authorized_keys forced
/// command works in non-interactive SSH sessions (where PATH may be minimal).
fn resolve_tmux_path() -> Result<String> {
    let output = Command::new("which")
        .arg("tmux")
        .output()?;
    if !output.status.success() {
        return Err(err("Could not find tmux. Install it and try again."));
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err(err("Could not determine tmux path"));
    }
    Ok(path)
}

// ---------------------------------------------------------------------------
// tmux management
// ---------------------------------------------------------------------------

fn create_tmux_session(session: &str) -> Result<()> {
    let status = Command::new("tmux")
        .args(["-u", "new-session", "-d", "-s", session])
        .status()?;
    if !status.success() {
        return Err(err(format!("Failed to create tmux session '{session}'")));
    }
    // Enable mouse scrolling in the session
    let _ = Command::new("tmux")
        .args(["set-option", "-t", session, "mouse", "on"])
        .status();
    Ok(())
}

fn attach_tmux_session(session: &str) -> Result<()> {
    let status = Command::new("tmux")
        .args(["-u", "attach", "-t", session])
        .status()?;
    if !status.success() {
        return Err(err(format!("tmux session '{session}' ended")));
    }
    Ok(())
}

fn kill_tmux_session(session: &str) -> Result<()> {
    let status = Command::new("tmux")
        .args(["kill-session", "-t", session])
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        // Session may already be gone, that's fine
    }
    Ok(())
}

fn tmux_client_count(session: &str) -> usize {
    Command::new("tmux")
        .args(["list-clients", "-t", session])
        .output()
        .ok()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            out.lines().count()
        })
        .unwrap_or(0)
}

fn tmux_session_alive(session: &str) -> bool {
    Command::new("tmux")
        .args(["has-session", "-t", session])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ---------------------------------------------------------------------------
// Token encoding / decoding
// ---------------------------------------------------------------------------

struct Token {
    host: String,
    port: u16,
    session: String,
    private_key: String,
}

fn encode_token(host: &str, ssh_port: u16, session: &str, private_key: &str) -> String {
    let encoded_key = URL_SAFE_NO_PAD.encode(private_key.as_bytes());
    format!("mp://{host}:{ssh_port}/{session}#{encoded_key}")
}

fn decode_token(token: &str) -> Result<Token> {
    let rest = token.strip_prefix("mp://").ok_or_else(|| err("Invalid token: must start with mp://"))?;

    let (addr_session, encoded_key) = rest
        .split_once('#')
        .ok_or_else(|| err("Invalid token: missing # separator"))?;

    let (addr, session) = addr_session
        .split_once('/')
        .ok_or_else(|| err("Invalid token: missing / separator"))?;

    let (host, port_str) = addr
        .split_once(':')
        .ok_or_else(|| err("Invalid token: missing :port"))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| err("Invalid token: bad port number"))?;

    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| err("Invalid token: bad base64 key"))?;

    let private_key =
        String::from_utf8(key_bytes).map_err(|_| err("Invalid token: key is not valid UTF-8"))?;

    Ok(Token {
        host: host.to_string(),
        port,
        session: session.to_string(),
        private_key,
    })
}

// ---------------------------------------------------------------------------
// Session info file (for stop/status when name is not provided)
// ---------------------------------------------------------------------------

fn write_session_info(session: &str, host_ip: &str) {
    let info = format!("{session}\n{host_ip}\n");
    let _ = fs::write(tmp_session_info_path(session), &info);
}

fn find_active_session() -> Option<String> {
    // Look for any /tmp/multiplayer-*-info file
    if let Ok(entries) = fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("multiplayer-") && name.ends_with("-info") {
                let session = name
                    .strip_prefix("multiplayer-")
                    .and_then(|s| s.strip_suffix("-info"))
                    .map(String::from);
                if let Some(s) = session {
                    if tmux_session_alive(&s) {
                        return Some(s);
                    }
                    // Session is stale — clean it up
                    cleanup_session(&s);
                }
            }
        }
    }
    None
}

fn read_session_info(session: &str) -> Option<(String, String)> {
    let content = fs::read_to_string(tmp_session_info_path(session)).ok()?;
    let mut lines = content.lines();
    let name = lines.next()?.to_string();
    let host = lines.next()?.to_string();
    Some((name, host))
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

fn cleanup_session(session: &str) {
    let _ = kill_tmux_session(session);
    let _ = remove_authorized_key(session);
    cleanup_ssh_keys(session);
    let _ = fs::remove_file(tmp_session_info_path(session));
}

// ---------------------------------------------------------------------------
// Stale session cleanup
// ---------------------------------------------------------------------------

/// Remove any multiplayer authorized_keys entries whose tmux session no longer
/// exists (e.g. after a crash, kill -9, or power loss). This prevents stale
/// keys from granting access if a session name is later reused.
fn cleanup_stale_sessions() {
    let ak_path = authorized_keys_path();
    let content = match fs::read_to_string(&ak_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut stale_sessions = Vec::new();
    for line in content.lines() {
        if let Some(session_name) = line.rsplit_once("multiplayer:").map(|(_, s)| s.trim()) {
            if session_name.is_empty() {
                continue;
            }
            if !tmux_session_alive(session_name) {
                stale_sessions.push(session_name.to_string());
            }
        }
    }

    for session in &stale_sessions {
        cleanup_session(session);
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_start(name: Option<String>) -> Result<()> {
    check_dependencies(&["tmux", "ssh-keygen"])?;

    // Clean up any stale sessions left behind by crashes or kill -9
    cleanup_stale_sessions();

    let session = match name {
        Some(n) => {
            validate_session_name(&n)?;
            n
        }
        None => generate_session_name(),
    };

    // Check if session is genuinely still active
    if tmp_session_info_path(&session).exists() {
        return Err(err(format!("Session '{session}' already exists. Run `multiplayer stop {session}` first.")));
    }

    let host_ip = get_local_ip()?;

    // 1. Generate SSH keypair
    generate_ssh_keypair(&session)?;

    // 2. Install public key in authorized_keys
    install_authorized_key(&session)?;

    // 3. Create tmux session
    create_tmux_session(&session)?;

    // 4. Read private key for the token
    let private_key = fs::read_to_string(tmp_key_path(&session))?;

    // 5. Build token
    let token = encode_token(&host_ip, 22, &session, &private_key);

    // 6. Save session info
    write_session_info(&session, &host_ip);

    println!();
    println!("  {}  {}", "Session:".bold(), session.green().bold());
    println!("  {}  {}", "Token:".bold(), token.dimmed());
    println!();
    println!("  Share the token so others can join:");
    println!("    {} {}", "multiplayer join".cyan(), token.cyan());
    println!();
    println!("  To enter your session:");
    println!("    {}", "multiplayer join".cyan());

    Ok(())
}

fn cmd_join(target: Option<String>) -> Result<()> {
    match target {
        None => {
            check_dependencies(&["tmux"])?;
            let session = find_active_session()
                .ok_or_else(|| err("No active session found. Start one first: multiplayer start"))?;
            println!("  {} {}", "Attaching to session:".bold(), session.green().bold());
            attach_tmux_session(&session)
        }
        Some(t) => {
            check_dependencies(&["ssh"])?;
            if !t.starts_with("mp://") {
                return Err(err(
                    "Expected an mp:// token. Get one from the session host and run: multiplayer join mp://..."
                ));
            }
            let token = decode_token(&t)?;
            join_with_key(&token.session, &token.host, token.port, &token.private_key)
        }
    }
}

fn join_with_key(session: &str, host: &str, ssh_port: u16, private_key: &str) -> Result<()> {
    // Write private key to temp file
    let key_path = PathBuf::from(format!("/tmp/multiplayer-join-{session}-key"));
    fs::write(&key_path, private_key)?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;

    println!("  {}...", "Connecting".bold());

    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());

    let status = Command::new("ssh")
        .args([
            "-i",
            key_path.to_str().unwrap(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-p",
            &ssh_port.to_string(),
            &format!("{user}@{host}"),
        ])
        .status()?;

    // Cleanup temp key
    let _ = fs::remove_file(&key_path);

    if !status.success() {
        return Err(err("SSH connection failed"));
    }

    Ok(())
}

fn cmd_stop(name: Option<String>) -> Result<()> {
    let session = match name {
        Some(n) => n,
        None => find_active_session()
            .ok_or_else(|| err("No active session found. Specify a session name: multiplayer stop <name>"))?,
    };

    cleanup_session(&session);

    println!();
    println!(
        "  {} {}",
        "Stopped session:".bold(),
        session.yellow()
    );
    println!("  Cleaned up tmux session and authorized_keys entry.");

    Ok(())
}

fn cmd_status(name: Option<String>) -> Result<()> {
    let session = match name {
        Some(n) => n,
        None => find_active_session()
            .ok_or_else(|| err("No active session found. Specify a session name: multiplayer status <name>"))?,
    };

    if !tmux_session_alive(&session) {
        cleanup_session(&session);
        return Err(err(format!("Session '{session}' is no longer active.")));
    }

    let info = read_session_info(&session);
    let clients = tmux_client_count(&session);

    println!();
    println!("  {:<16} {}", "Session:".bold(), session.green().bold());
    if let Some((_, host)) = &info {
        println!("  {:<16} {}", "Host:".bold(), host);
    }
    println!("  {:<16} {} attached", "Participants:".bold(), clients);

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Cmd::Start { name } => cmd_start(name),
        Cmd::Join { target } => cmd_join(target),
        Cmd::Stop { name } => cmd_stop(name),
        Cmd::Status { name } => cmd_status(name),
    };

    if let Err(e) = result {
        eprintln!("  {} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
