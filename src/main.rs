use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use colored::Colorize;
use rand::Rng;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

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
        /// Relay through a GCP VM (provide the VM instance name)
        #[arg(long = "gcp")]
        gcp_vm: Option<String>,
        /// GCP zone (defaults to gcloud config value)
        #[arg(long)]
        zone: Option<String>,
        /// GCP project (defaults to gcloud config value)
        #[arg(long)]
        project: Option<String>,
        /// Relay through an SSH host (config name from ~/.multiplayer/config.yml, defaults to "default")
        #[arg(long = "ssh", num_args = 0..=1, default_missing_value = "default")]
        ssh_relay: Option<String>,
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
// Config file (~/.multiplayer/config.yml)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Config {
    hosts: HashMap<String, HostConfig>,
}

#[derive(Deserialize)]
struct HostConfig {
    host: String,
    user: String,
    key: String,
}

fn multiplayer_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    PathBuf::from(home).join(".multiplayer")
}

fn load_config() -> Result<Config> {
    let config_path = multiplayer_dir().join("config.yml");
    let content = fs::read_to_string(&config_path).map_err(|_| {
        err(format!(
            "Could not read config file: {}. Create it with your relay host entries.",
            config_path.display()
        ))
    })?;
    let config: Config = serde_yaml::from_str(&content)
        .map_err(|e| err(format!("Invalid config file: {e}")))?;
    Ok(config)
}

fn resolve_key_path(key_field: &str) -> PathBuf {
    let path = PathBuf::from(key_field);
    if path.is_absolute() {
        path
    } else {
        multiplayer_dir().join(key_field)
    }
}

fn find_config_by_host<'a>(config: &'a Config, relay_host: &str) -> Result<&'a HostConfig> {
    config
        .hosts
        .values()
        .find(|h| h.host == relay_host)
        .ok_or_else(|| {
            err(format!(
                "No config entry found matching relay host '{relay_host}' in ~/.multiplayer/config.yml"
            ))
        })
}

fn validate_relay_key(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        return Err(err(format!(
            "Relay key not found: {}. Place the key file there or update ~/.multiplayer/config.yml.",
            path.display()
        )));
    }
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(err(format!(
            "Relay key {} has permissions {:04o}, expected 0600. Run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        )));
    }
    Ok(())
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

fn tmp_tunnel_pid_path(session: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/multiplayer-{session}-tunnel-pid"))
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
    user: String,
    host: String,
    port: u16,
    session: String,
    private_key: String,
}

fn encode_token(user: &str, host: &str, ssh_port: u16, session: &str, private_key: &str) -> String {
    let encoded_key = URL_SAFE_NO_PAD.encode(private_key.as_bytes());
    format!("mp://{user}@{host}:{ssh_port}/{session}#{encoded_key}")
}

fn decode_token(token: &str) -> Result<Token> {
    let rest = token.strip_prefix("mp://").ok_or_else(|| err("Invalid token: must start with mp://"))?;

    let (addr_session, encoded_key) = rest
        .split_once('#')
        .ok_or_else(|| err("Invalid token: missing # separator"))?;

    let (addr, session) = addr_session
        .split_once('/')
        .ok_or_else(|| err("Invalid token: missing / separator"))?;

    let (user_host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| err("Invalid token: missing :port"))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| err("Invalid token: bad port number"))?;

    let (user, host) = user_host
        .split_once('@')
        .ok_or_else(|| err("Invalid token: missing user@host"))?;

    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| err("Invalid token: bad base64 key"))?;

    let private_key =
        String::from_utf8(key_bytes).map_err(|_| err("Invalid token: key is not valid UTF-8"))?;

    Ok(Token {
        user: user.to_string(),
        host: host.to_string(),
        port,
        session: session.to_string(),
        private_key,
    })
}

// ---------------------------------------------------------------------------
// GCP token encoding / decoding
// ---------------------------------------------------------------------------

struct GcpToken {
    user: String,
    vm: String,
    relay_port: u16,
    session: String,
    zone: Option<String>,
    project: Option<String>,
    private_key: String,
}

fn encode_gcp_token(
    user: &str,
    vm: &str,
    relay_port: u16,
    session: &str,
    zone: Option<&str>,
    project: Option<&str>,
    private_key: &str,
) -> String {
    let encoded_key = URL_SAFE_NO_PAD.encode(private_key.as_bytes());
    let mut query_parts = Vec::new();
    if let Some(z) = zone {
        query_parts.push(format!("zone={z}"));
    }
    if let Some(p) = project {
        query_parts.push(format!("project={p}"));
    }
    let query = if query_parts.is_empty() {
        String::new()
    } else {
        format!("?{}", query_parts.join("&"))
    };
    format!("mp-gcp://{user}@{vm}:{relay_port}/{session}{query}#{encoded_key}")
}

fn decode_gcp_token(token: &str) -> Result<GcpToken> {
    let rest = token
        .strip_prefix("mp-gcp://")
        .ok_or_else(|| err("Invalid GCP token: must start with mp-gcp://"))?;

    let (addr_session_query, encoded_key) = rest
        .split_once('#')
        .ok_or_else(|| err("Invalid GCP token: missing # separator"))?;

    let (addr_session, query) = match addr_session_query.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (addr_session_query, None),
    };

    let (addr, session) = addr_session
        .split_once('/')
        .ok_or_else(|| err("Invalid GCP token: missing / separator"))?;

    let (user_vm, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| err("Invalid GCP token: missing :port"))?;

    let relay_port: u16 = port_str
        .parse()
        .map_err(|_| err("Invalid GCP token: bad port number"))?;

    let (user, vm) = user_vm
        .split_once('@')
        .ok_or_else(|| err("Invalid GCP token: missing user@vm"))?;

    let mut zone = None;
    let mut project = None;
    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                match k {
                    "zone" => zone = Some(v.to_string()),
                    "project" => project = Some(v.to_string()),
                    _ => {}
                }
            }
        }
    }

    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| err("Invalid GCP token: bad base64 key"))?;

    let private_key =
        String::from_utf8(key_bytes).map_err(|_| err("Invalid GCP token: key is not valid UTF-8"))?;

    Ok(GcpToken {
        user: user.to_string(),
        vm: vm.to_string(),
        relay_port,
        session: session.to_string(),
        zone,
        project,
        private_key,
    })
}

// ---------------------------------------------------------------------------
// SSH relay token encoding / decoding
// ---------------------------------------------------------------------------

struct SshToken {
    host_user: String,
    relay_host: String,
    relay_port: u16,
    session: String,
    relay_user: String,
    private_key: String,
}

fn encode_ssh_token(
    host_user: &str,
    relay_host: &str,
    relay_port: u16,
    session: &str,
    relay_user: &str,
    private_key: &str,
) -> String {
    let encoded_key = URL_SAFE_NO_PAD.encode(private_key.as_bytes());
    format!(
        "mp-ssh://{host_user}@{relay_host}:{relay_port}/{session}?relay_user={relay_user}#{encoded_key}"
    )
}

fn decode_ssh_token(token: &str) -> Result<SshToken> {
    let rest = token
        .strip_prefix("mp-ssh://")
        .ok_or_else(|| err("Invalid SSH token: must start with mp-ssh://"))?;

    let (addr_session_query, encoded_key) = rest
        .split_once('#')
        .ok_or_else(|| err("Invalid SSH token: missing # separator"))?;

    let (addr_session, query) = addr_session_query
        .split_once('?')
        .ok_or_else(|| err("Invalid SSH token: missing ? query"))?;

    let (addr, session) = addr_session
        .split_once('/')
        .ok_or_else(|| err("Invalid SSH token: missing / separator"))?;

    let (user_host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| err("Invalid SSH token: missing :port"))?;

    let relay_port: u16 = port_str
        .parse()
        .map_err(|_| err("Invalid SSH token: bad port number"))?;

    let (host_user, relay_host) = user_host
        .split_once('@')
        .ok_or_else(|| err("Invalid SSH token: missing user@host"))?;

    let mut relay_user = String::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "relay_user" {
                relay_user = v.to_string();
            }
        }
    }
    if relay_user.is_empty() {
        return Err(err("Invalid SSH token: missing relay_user parameter"));
    }

    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .map_err(|_| err("Invalid SSH token: bad base64 key"))?;

    let private_key =
        String::from_utf8(key_bytes).map_err(|_| err("Invalid SSH token: key is not valid UTF-8"))?;

    Ok(SshToken {
        host_user: host_user.to_string(),
        relay_host: relay_host.to_string(),
        relay_port,
        session: session.to_string(),
        relay_user,
        private_key,
    })
}

// ---------------------------------------------------------------------------
// GCP helpers
// ---------------------------------------------------------------------------

fn gcloud_config_value(key: &str) -> Option<String> {
    let output = Command::new("gcloud")
        .args(["config", "get-value", key])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if val.is_empty() || val == "(unset)" {
        None
    } else {
        Some(val)
    }
}

fn establish_reverse_tunnel(
    vm: &str,
    zone: Option<&str>,
    project: Option<&str>,
    relay_port: u16,
    session: &str,
) -> Result<()> {
    let mut cmd = Command::new("gcloud");
    cmd.arg("compute").arg("ssh");
    if let Some(z) = zone {
        cmd.arg(format!("--zone={z}"));
    }
    if let Some(p) = project {
        cmd.arg(format!("--project={p}"));
    }
    cmd.arg(vm);
    cmd.arg("--");
    cmd.arg("-R").arg(format!("{relay_port}:localhost:22"));
    cmd.arg("-N");
    cmd.arg("-o").arg("ExitOnForwardFailure=yes");
    cmd.arg("-o").arg("ServerAliveInterval=30");

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().map_err(|e| err(format!("Failed to start gcloud: {e}")))?;
    let pid = child.id();

    fs::write(tmp_tunnel_pid_path(session), pid.to_string())?;

    // Wait for tunnel to establish
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Verify process is still alive
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !alive {
        let _ = fs::remove_file(tmp_tunnel_pid_path(session));
        return Err(err(
            "Reverse tunnel failed to start. Check that the GCP VM is reachable and you have access.",
        ));
    }

    Ok(())
}

fn find_free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn establish_local_forward(
    vm: &str,
    zone: Option<&str>,
    project: Option<&str>,
    local_port: u16,
    relay_port: u16,
) -> Result<Child> {
    let mut cmd = Command::new("gcloud");
    cmd.arg("compute").arg("ssh");
    if let Some(z) = zone {
        cmd.arg(format!("--zone={z}"));
    }
    if let Some(p) = project {
        cmd.arg(format!("--project={p}"));
    }
    cmd.arg(vm);
    cmd.arg("--");
    cmd.arg("-L").arg(format!("{local_port}:localhost:{relay_port}"));
    cmd.arg("-N");
    cmd.arg("-o").arg("ServerAliveInterval=30");

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().map_err(|e| err(format!("Failed to start gcloud: {e}")))?;
    Ok(child)
}

fn kill_tunnel_process(session: &str) {
    let pid_path = tmp_tunnel_pid_path(session);
    if let Ok(pid_str) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            let _ = Command::new("kill")
                .arg(pid.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_file(&pid_path);
    }
}

// ---------------------------------------------------------------------------
// SSH relay tunnel helpers
// ---------------------------------------------------------------------------

fn establish_ssh_reverse_tunnel(
    relay_user: &str,
    relay_host: &str,
    relay_key_path: &PathBuf,
    relay_port: u16,
    session: &str,
) -> Result<()> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-i").arg(relay_key_path);
    cmd.arg("-R").arg(format!("{relay_port}:localhost:22"));
    cmd.arg("-N");
    cmd.arg("-o").arg("StrictHostKeyChecking=no");
    cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
    cmd.arg("-o").arg("LogLevel=ERROR");
    cmd.arg("-o").arg("ServerAliveInterval=30");
    cmd.arg("-o").arg("ExitOnForwardFailure=yes");
    cmd.arg(format!("{relay_user}@{relay_host}"));

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().map_err(|e| err(format!("Failed to start ssh tunnel: {e}")))?;
    let pid = child.id();

    fs::write(tmp_tunnel_pid_path(session), pid.to_string())?;

    // Wait for tunnel to establish
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Verify process is still alive
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !alive {
        let _ = fs::remove_file(tmp_tunnel_pid_path(session));
        return Err(err(
            "Reverse tunnel failed to start. Check that the relay host is reachable and the key is correct.",
        ));
    }

    Ok(())
}

fn establish_ssh_local_forward(
    relay_user: &str,
    relay_host: &str,
    relay_key_path: &PathBuf,
    local_port: u16,
    relay_port: u16,
) -> Result<Child> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-i").arg(relay_key_path);
    cmd.arg("-L").arg(format!("{local_port}:localhost:{relay_port}"));
    cmd.arg("-N");
    cmd.arg("-o").arg("StrictHostKeyChecking=no");
    cmd.arg("-o").arg("UserKnownHostsFile=/dev/null");
    cmd.arg("-o").arg("LogLevel=ERROR");
    cmd.arg("-o").arg("ServerAliveInterval=30");
    cmd.arg(format!("{relay_user}@{relay_host}"));

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::piped());

    let child = cmd.spawn().map_err(|e| err(format!("Failed to start ssh tunnel: {e}")))?;
    Ok(child)
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
    kill_tunnel_process(session);
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
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let token = encode_token(&user, &host_ip, 22, &session, &private_key);

    // 6. Save session info
    write_session_info(&session, &host_ip);

    println!();
    println!("  {}  {}", "Session:".bold(), session.green().bold());
    println!();
    println!("  Share the token so others can join:");
    println!("    {} \"{}\"", "multiplayer join".cyan(), token.cyan());
    println!();
    println!("  To enter your session:");
    println!("    {}", "multiplayer join".cyan());

    Ok(())
}

fn cmd_start_gcp(
    name: Option<String>,
    vm: String,
    zone: Option<String>,
    project: Option<String>,
) -> Result<()> {
    check_dependencies(&["tmux", "ssh-keygen", "gcloud"])?;

    cleanup_stale_sessions();

    let session = match name {
        Some(n) => {
            validate_session_name(&n)?;
            n
        }
        None => generate_session_name(),
    };

    if tmp_session_info_path(&session).exists() {
        return Err(err(format!(
            "Session '{session}' already exists. Run `multiplayer stop {session}` first."
        )));
    }

    // Resolve zone/project: flags > gcloud config defaults
    let zone = zone.or_else(|| gcloud_config_value("compute/zone"));
    let project = project.or_else(|| gcloud_config_value("core/project"));

    // 1. Generate SSH keypair
    generate_ssh_keypair(&session)?;

    // 2. Install public key in authorized_keys
    install_authorized_key(&session)?;

    // 3. Create tmux session
    create_tmux_session(&session)?;

    // 4. Establish reverse tunnel to GCP relay VM
    let relay_port = rand::thread_rng().gen_range(2222..=2322);
    println!(
        "  {} to GCP VM '{}'...",
        "Establishing tunnel".bold(),
        vm
    );
    establish_reverse_tunnel(&vm, zone.as_deref(), project.as_deref(), relay_port, &session)?;

    // 5. Read private key for the token
    let private_key = fs::read_to_string(tmp_key_path(&session))?;

    // 6. Build GCP token
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let token = encode_gcp_token(
        &user,
        &vm,
        relay_port,
        &session,
        zone.as_deref(),
        project.as_deref(),
        &private_key,
    );

    // 7. Save session info
    write_session_info(&session, &format!("gcp:{vm}"));

    println!();
    println!("  {}  {}", "Session:".bold(), session.green().bold());
    println!("  {}    {} (via GCP relay)", "Relay:".bold(), vm);
    println!();
    println!("  Share the token so others can join:");
    println!("    {} \"{}\"", "multiplayer join".cyan(), token.cyan());
    println!();
    println!("  To enter your session:");
    println!("    {}", "multiplayer join".cyan());

    Ok(())
}

fn cmd_start_ssh(name: Option<String>, config_name: String) -> Result<()> {
    check_dependencies(&["tmux", "ssh-keygen", "ssh"])?;

    // Load config and look up the relay entry
    let config = load_config()?;
    let host_config = config.hosts.get(&config_name).ok_or_else(|| {
        let available: Vec<&String> = config.hosts.keys().collect();
        err(format!(
            "Unknown SSH relay '{}'. Available hosts in ~/.multiplayer/config.yml: {}",
            config_name,
            if available.is_empty() {
                "(none)".to_string()
            } else {
                available.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            }
        ))
    })?;

    let relay_key_path = resolve_key_path(&host_config.key);
    validate_relay_key(&relay_key_path)?;

    cleanup_stale_sessions();

    let session = match name {
        Some(n) => {
            validate_session_name(&n)?;
            n
        }
        None => generate_session_name(),
    };

    if tmp_session_info_path(&session).exists() {
        return Err(err(format!(
            "Session '{session}' already exists. Run `multiplayer stop {session}` first."
        )));
    }

    // 1. Generate SSH keypair
    generate_ssh_keypair(&session)?;

    // 2. Install public key in authorized_keys
    install_authorized_key(&session)?;

    // 3. Create tmux session
    create_tmux_session(&session)?;

    // 4. Establish reverse tunnel to SSH relay
    let relay_port = rand::thread_rng().gen_range(2222..=2322);
    println!(
        "  {} to relay '{}'...",
        "Establishing tunnel".bold(),
        config_name
    );
    establish_ssh_reverse_tunnel(
        &host_config.user,
        &host_config.host,
        &relay_key_path,
        relay_port,
        &session,
    )?;

    // 5. Read private key for the token
    let private_key = fs::read_to_string(tmp_key_path(&session))?;

    // 6. Build SSH token (use actual host, not config name)
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let token = encode_ssh_token(
        &user,
        &host_config.host,
        relay_port,
        &session,
        &host_config.user,
        &private_key,
    );

    // 7. Save session info
    write_session_info(&session, &format!("ssh:{}", host_config.host));

    println!();
    println!("  {}  {}", "Session:".bold(), session.green().bold());
    println!(
        "  {}    {} (via SSH relay)",
        "Relay:".bold(),
        host_config.host
    );
    println!();
    println!("  Share the token so others can join:");
    println!("    {} \"{}\"", "multiplayer join".cyan(), token.cyan());
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
        Some(t) if t.starts_with("mp-gcp://") => cmd_join_gcp(&t),
        Some(t) if t.starts_with("mp-ssh://") => cmd_join_ssh(&t),
        Some(t) => {
            check_dependencies(&["ssh"])?;
            if !t.starts_with("mp://") {
                return Err(err(
                    "Expected an mp://, mp-gcp://, or mp-ssh:// token. Get one from the session host and run: multiplayer join <token>"
                ));
            }
            let token = decode_token(&t)?;
            join_with_key(&token.user, &token.session, &token.host, token.port, &token.private_key)
        }
    }
}

fn cmd_join_gcp(token_str: &str) -> Result<()> {
    check_dependencies(&["ssh", "gcloud"])?;

    let token = decode_gcp_token(token_str)?;

    let local_port = find_free_port()?;

    println!(
        "  {} to GCP VM '{}'...",
        "Establishing tunnel".bold(),
        token.vm
    );
    let mut tunnel = establish_local_forward(
        &token.vm,
        token.zone.as_deref(),
        token.project.as_deref(),
        local_port,
        token.relay_port,
    )?;

    // Wait for the local forward port to become reachable
    let timeout = std::time::Duration::from_secs(30);
    let poll_interval = std::time::Duration::from_millis(500);
    let start = std::time::Instant::now();
    let mut connected = false;

    while start.elapsed() < timeout {
        // Check if tunnel process died
        if let Some(_status) = tunnel.try_wait()? {
            return Err(err(
                "Local forward tunnel exited unexpectedly. Check that the GCP VM is reachable and you have access.",
            ));
        }
        // Try connecting to the forwarded port
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], local_port)),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
        {
            connected = true;
            break;
        }
        std::thread::sleep(poll_interval);
    }

    if !connected {
        let _ = tunnel.kill();
        let _ = tunnel.wait();
        return Err(err(
            "Timed out waiting for local forward tunnel. Check that the GCP VM is reachable and the host session is running.",
        ));
    }

    // Retry SSH connection — the local forward port may be listening before the
    // full tunnel chain (participant → relay → host:22) is ready.
    let max_attempts = 5;
    let mut last_err = None;
    for attempt in 1..=max_attempts {
        // Check tunnel is still alive before each attempt
        if let Some(_status) = tunnel.try_wait()? {
            let _ = tunnel.kill();
            let _ = tunnel.wait();
            return Err(err(
                "Local forward tunnel exited unexpectedly.",
            ));
        }

        match join_with_key(
            &token.user,
            &token.session,
            "127.0.0.1",
            local_port,
            &token.private_key,
        ) {
            Ok(()) => {
                let _ = tunnel.kill();
                let _ = tunnel.wait();
                return Ok(());
            }
            Err(e) => {
                if attempt < max_attempts {
                    println!("  {} (attempt {}/{})", "Retrying connection...".bold(), attempt, max_attempts);
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
                last_err = Some(e);
            }
        }
    }

    // Kill the local forward tunnel
    let _ = tunnel.kill();
    let _ = tunnel.wait();

    Err(last_err.unwrap_or_else(|| err("SSH connection failed after retries")))
}

fn cmd_join_ssh(token_str: &str) -> Result<()> {
    check_dependencies(&["ssh"])?;

    let token = decode_ssh_token(token_str)?;

    // Load config and find entry matching the relay host
    let config = load_config()?;
    let host_config = find_config_by_host(&config, &token.relay_host)?;

    let relay_key_path = resolve_key_path(&host_config.key);
    validate_relay_key(&relay_key_path)?;

    let local_port = find_free_port()?;

    println!(
        "  {} to relay '{}'...",
        "Establishing tunnel".bold(),
        token.relay_host
    );
    let mut tunnel = establish_ssh_local_forward(
        &token.relay_user,
        &token.relay_host,
        &relay_key_path,
        local_port,
        token.relay_port,
    )?;

    // Wait for the local forward port to become reachable
    let timeout = std::time::Duration::from_secs(30);
    let poll_interval = std::time::Duration::from_millis(500);
    let start = std::time::Instant::now();
    let mut connected = false;

    while start.elapsed() < timeout {
        if let Some(_status) = tunnel.try_wait()? {
            return Err(err(
                "Local forward tunnel exited unexpectedly. Check that the relay host is reachable and the key is correct.",
            ));
        }
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], local_port)),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
        {
            connected = true;
            break;
        }
        std::thread::sleep(poll_interval);
    }

    if !connected {
        let _ = tunnel.kill();
        let _ = tunnel.wait();
        return Err(err(
            "Timed out waiting for local forward tunnel. Check that the relay host is reachable and the host session is running.",
        ));
    }

    // Retry SSH connection — the local forward port may be listening before the
    // full tunnel chain (joiner → relay → host:22) is ready.
    let max_attempts = 5;
    let mut last_err = None;
    for attempt in 1..=max_attempts {
        if let Some(_status) = tunnel.try_wait()? {
            let _ = tunnel.kill();
            let _ = tunnel.wait();
            return Err(err("Local forward tunnel exited unexpectedly."));
        }

        match join_with_key(
            &token.host_user,
            &token.session,
            "127.0.0.1",
            local_port,
            &token.private_key,
        ) {
            Ok(()) => {
                let _ = tunnel.kill();
                let _ = tunnel.wait();
                return Ok(());
            }
            Err(e) => {
                if attempt < max_attempts {
                    println!(
                        "  {} (attempt {}/{})",
                        "Retrying connection...".bold(),
                        attempt,
                        max_attempts
                    );
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
                last_err = Some(e);
            }
        }
    }

    let _ = tunnel.kill();
    let _ = tunnel.wait();

    Err(last_err.unwrap_or_else(|| err("SSH connection failed after retries")))
}

fn join_with_key(user: &str, session: &str, host: &str, ssh_port: u16, private_key: &str) -> Result<()> {
    // Write private key to temp file
    let key_path = PathBuf::from(format!("/tmp/multiplayer-join-{session}-key"));
    fs::write(&key_path, private_key)?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;

    println!("  {}...", "Connecting".bold());

    let status = Command::new("ssh")
        .env("TERM", "xterm-256color")
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
        Cmd::Start {
            name,
            gcp_vm,
            zone,
            project,
            ssh_relay,
        } => {
            if gcp_vm.is_some() && ssh_relay.is_some() {
                Err(err("--gcp and --ssh are mutually exclusive"))
            } else if ssh_relay.is_some() && (zone.is_some() || project.is_some()) {
                Err(err("--zone and --project cannot be used with --ssh"))
            } else if gcp_vm.is_none() && ssh_relay.is_none() && (zone.is_some() || project.is_some()) {
                Err(err("--zone and --project require --gcp"))
            } else if let Some(relay) = ssh_relay {
                cmd_start_ssh(name, relay)
            } else if let Some(vm) = gcp_vm {
                cmd_start_gcp(name, vm, zone, project)
            } else {
                cmd_start(name)
            }
        }
        Cmd::Join { target } => cmd_join(target),
        Cmd::Stop { name } => cmd_stop(name),
        Cmd::Status { name } => cmd_status(name),
    };

    if let Err(e) = result {
        eprintln!("  {} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
