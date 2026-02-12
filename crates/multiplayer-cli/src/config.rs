use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::{Result, err};

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub server_url: Option<String>,
    pub auth_token: Option<String>,
}

fn config_dir() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .ok_or_else(|| err("Could not determine config directory"))?
        .join("multiplayer");
    Ok(dir)
}

fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn load() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let content = fs::read_to_string(&path)?;
    toml::from_str(&content).map_err(|e| err(format!("Failed to parse config: {e}")))
}

pub fn save(config: &Config) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)?;
    let content = toml::to_string_pretty(config)
        .map_err(|e| err(format!("Failed to serialize config: {e}")))?;
    let path = config_path()?;
    fs::write(&path, content)?;
    Ok(())
}

pub fn load_required() -> Result<Config> {
    let config = load()?;
    if config.auth_token.is_none() || config.server_url.is_none() {
        return Err(err(
            "Not registered. Run `multiplayer register --server <url> --username <name>` first."
        ));
    }
    Ok(config)
}
