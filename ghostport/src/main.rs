use ghostport::config::load_config;
use ghostport::udp::start_watcher;
use ghostport::proxy::start_proxy;
use ghostport::waf::WafEngine;
use ghostport::jail::Jail;
use ghostport::auth::AuthManager;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Instant;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("GhostPort v3.0 Starting...");

    // 1. Load Config
    let config = match load_config("GhostPort.toml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            return Ok(());
        }
    };

    println!("Configuration Loaded!");
    println!("   Listen: {}:{}", config.server.listen_ip, config.server.listen_port);
    println!("   Backend: {}", config.backend.target_addr);

    // 2. Shared State (The Whitelist)
    // Map: IP -> (Timestamp, Roles)
    let whitelist: Arc<Mutex<HashMap<IpAddr, (Instant, Vec<String>)>>> = Arc::new(Mutex::new(HashMap::new()));

    // 3. Auth Manager
    let users = config.users.clone().unwrap_or_default();
    let auth = Arc::new(AuthManager::new(&users));

    // 4. WAF Engine
    let waf = Arc::new(WafEngine::new());

    // 5. Jail (The Bouncer)
    let jail = Jail::new(
        config.security.ban.ban_duration,
        config.security.ban.max_violations
    );

    // 6. Start UDP Watcher (Background)
    let udp_config = config.clone();
    let udp_whitelist = whitelist.clone();
    let udp_auth = auth.clone();
    let udp_jail = jail.clone();
    tokio::spawn(start_watcher(udp_config, udp_whitelist, udp_auth, udp_jail));

    // 7. Start TCP Proxy (Main Thread)
    start_proxy(config, whitelist, waf, jail).await;

    Ok(())
}