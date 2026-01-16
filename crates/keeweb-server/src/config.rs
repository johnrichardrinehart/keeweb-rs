//! Configuration loading and management

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub syncthing: SyncthingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub watch_directories: Vec<PathBuf>,
    #[serde(default = "default_temp_dir")]
    pub temp_directory: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncthingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_conflict_pattern")]
    pub conflict_pattern: String,
    pub api_url: Option<String>,
    pub api_key: Option<String>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_temp_dir() -> PathBuf {
    std::env::temp_dir().join("keeweb-rs")
}

fn default_true() -> bool {
    true
}

fn default_conflict_pattern() -> String {
    r"\.sync-conflict-".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            watch_directories: Vec::new(),
            temp_directory: default_temp_dir(),
        }
    }
}

impl Default for SyncthingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            conflict_pattern: default_conflict_pattern(),
            api_url: None,
            api_key: None,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            syncthing: SyncthingConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from file or use defaults
    pub fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Try to load from standard locations
        let config_paths: Vec<PathBuf> = vec![
            Some(PathBuf::from("config.toml")),
            Some(PathBuf::from("keeweb-rs.toml")),
            dirs_config_path(),
        ]
        .into_iter()
        .flatten()
        .collect();

        for path in config_paths {
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                let config: Config = toml::from_str(&content)?;
                tracing::info!("Loaded config from {:?}", path);
                return Ok(config);
            }
        }

        // Return default config
        tracing::info!("Using default configuration");
        Ok(Config::default())
    }
}

fn dirs_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("keeweb-rs").join("config.toml"))
}

/// Helper to get user's config directory
mod dirs {
    use std::path::PathBuf;

    pub fn config_dir() -> Option<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var("HOME")
                        .ok()
                        .map(|h| PathBuf::from(h).join(".config"))
                })
        }

        #[cfg(target_os = "macos")]
        {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
        }

        #[cfg(target_os = "windows")]
        {
            std::env::var("APPDATA").ok().map(PathBuf::from)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }
}
