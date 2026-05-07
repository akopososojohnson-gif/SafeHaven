use anyhow::Result;
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

const DEFAULT_SERVER: &str = "http://localhost:8080";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub server_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER.to_string(),
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str(&data) {
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

pub fn config_path() -> PathBuf {
    ProjectDirs::from("", "SafeHaven", "SafeHaven")
        .map(|d| d.config_dir().join("config.json"))
        .unwrap_or_else(|| PathBuf::from(".safehaven/config.json"))
}

pub fn token_path() -> PathBuf {
    ProjectDirs::from("", "SafeHaven", "SafeHaven")
        .map(|d| d.data_dir().join("token"))
        .unwrap_or_else(|| PathBuf::from(".safehaven/token"))
}
