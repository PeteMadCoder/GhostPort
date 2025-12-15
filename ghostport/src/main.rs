use ghostport::config::load_config;
use ghostport::udp::start_watcher;
use ghostport::proxy::start_proxy;
use ghostport::waf::WafEngine;
use ghostport::jail::Jail;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Instant;
use std::net::IpAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("GhostPort v2.0 Starting...");

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
    let whitelist: Arc<Mutex<HashMap<IpAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    // 3. WAF Engine
    let waf = Arc::new(WafEngine::new());

    // 4. Jail (The Bouncer)
    let jail = Jail::new(
        config.security.ban.ban_duration,
        config.security.ban.max_violations
    );

    // 5. Start UDP Watcher (Background)
    let udp_config = config.clone();
    let udp_whitelist = whitelist.clone();
    tokio::spawn(start_watcher(udp_config, udp_whitelist));

    // 6. Start TCP Proxy (Main Thread)
    start_proxy(config, whitelist, waf, jail).await;

    Ok(())
}
