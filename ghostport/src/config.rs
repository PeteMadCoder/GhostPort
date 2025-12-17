use serde::Deserialize;
use std::fs;
use std::error::Error;
use std::env;
use std::collections::HashMap;
use crate::crypto::decrypt_private_key;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub backend: BackendConfig,
    pub security: SecurityConfig,
    pub reporting: ReportingConfig,
    pub rules: Vec<RuleConfig>,
    pub users: Option<Vec<UserConfig>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    pub profiles: HashMap<String, ClientProfile>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientProfile {
    pub target: String,
    pub knock: String,
    pub local_port: u16,
    pub server_pub: String,
    pub my_priv: String,
    pub server_cert_hash: String,
}

impl Config {
    pub fn get_private_key(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let encrypted = self.security.encrypted_private_key.as_ref()
            .ok_or("Configuration missing 'security.encrypted_private_key'")?;
            
        let master_key = env::var("GHOSTPORT_MASTER_KEY")
            .map_err(|_| "Environment variable GHOSTPORT_MASTER_KEY not set. Cannot decrypt private key.")?;
            
        decrypt_private_key(&master_key, encrypted)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_ip: String,
    pub listen_port: u16,
    pub knock_port: u16,
    pub tls_enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub max_connections: Option<usize>,
    pub max_concurrent_bidi_streams: Option<u32>,
    pub max_idle_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BackendConfig {
    pub target_addr: String,
    pub target_host: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BanConfig {
    pub enabled: bool,
    pub ban_duration: u64,
    pub max_violations: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub enable_deep_analysis: bool,
    pub session_timeout: u64,
    pub honeypot_file: Option<String>,
    pub ban: BanConfig,
    pub encrypted_private_key: Option<String>,
    pub authorized_keys: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReportingConfig {
    pub webhook_url: String,
    pub log_all_requests: bool,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RuleConfig {
    pub path: String,
    pub on_fail: String,
    pub allowed_roles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UserConfig {
    pub username: String,
    pub roles: Vec<String>,
    pub public_key: String,
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}

pub fn load_client_config(path: &str) -> Result<ClientConfig, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let config: ClientConfig = toml::from_str(&content)?;
    Ok(config)
}