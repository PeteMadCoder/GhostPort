use serde::Deserialize;
use std::fs;
use std::error::Error;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub backend: BackendConfig,
    pub security: SecurityConfig,
    pub reporting: ReportingConfig,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_ip: String,
    pub listen_port: u16,
    pub tls_enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub max_connections: Option<usize>,
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
    pub knock_token: String,
    pub session_timeout: u64,
    pub honeypot_file: Option<String>,
    pub ban: BanConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ReportingConfig {
    pub webhook_url: String,
    pub log_all_requests: bool,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct RuleConfig {
    pub path: String,
    #[serde(rename = "type")]
    pub rule_type: String, // "public" or "private"
    pub strict_waf: bool,
    pub on_fail: String, // "block", "honeypot"
}

pub fn load_config(path: &str) -> Result<Config, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
