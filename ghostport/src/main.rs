use ghostport::config::load_config;
use ghostport::udp::start_watcher;
use ghostport::proxy::start_proxy;
use ghostport::waf::WafEngine;
use ghostport::jail::Jail;
use ghostport::auth::AuthManager;
use ghostport::client::start_client;
use ghostport::crypto::encrypt_private_key;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::Instant;
use std::net::IpAddr;
use clap::{Parser, Subcommand};
use snow::Builder;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

#[derive(Parser)]
#[command(name = "ghostport")]
#[command(version = "5.0", about = "Zero-Trust Stealth Bunker")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the GhostPort Server
    Server {
        /// Safe Mode: Binds only to 127.0.0.1 for debugging
        #[arg(long)]
        safe_mode: bool,
    },
    /// Connect to a GhostPort Server (Creates Local Tunnel)
    Connect {
        /// Target Address (IP:Port of the Service, e.g., 1.2.3.4:8443)
        #[arg(long)]
        target: String,
        /// Knock Address (IP:Port of the Watcher, e.g., 1.2.3.4:9000)
        #[arg(long)]
        knock: String,
        /// Local Port to bind (e.g., 2222)
        #[arg(long, default_value_t = 2222)]
        local_port: u16,
        /// Server's Public Key (Base64)
        #[arg(long)]
        server_pub: String,
        /// Your Private Key (Base64)
        #[arg(long)]
        my_priv: String,
    },
    /// Generate a new Noise Keypair (and encrypt the private key)
    Keygen {
        /// Master Key for encryption (reads GHOSTPORT_MASTER_KEY env if not provided)
        #[arg(long, env = "GHOSTPORT_MASTER_KEY")]
        master_key: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { safe_mode } => run_server(safe_mode).await?,
        Commands::Connect { target, knock, local_port, server_pub, my_priv } => {
            start_client(&target, &knock, local_port, &server_pub, &my_priv).await?;
        }
        Commands::Keygen { master_key } => {
            // Generate Keypair using Snow
            let builder = Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()?);
            let keypair = builder.generate_keypair()?;
            
            let pub_b64 = BASE64.encode(&keypair.public);
            let priv_b64 = BASE64.encode(&keypair.private);
            
            // Encrypt Private Key
            let encrypted_priv = encrypt_private_key(&master_key, &keypair.private)?;
            
            println!("=== Generated Noise Keypair ===");
            println!("-------------------------------------------------------");
            println!("OPTION A: Are you setting up the SERVER?");
            println!("1. Copy 'Encrypted Private Key' to GhostPort.toml -> [security] -> encrypted_private_key");
            println!("2. Keep 'Public Key' safe; you will need to give it to your Clients.");
            println!("-------------------------------------------------------");
            println!("OPTION B: Are you setting up a CLIENT?");
            println!("1. Copy 'Public Key' to the Server's GhostPort.toml -> [[users]] -> public_key");
            println!("2. Use 'Raw Private Key' when running the 'connect' command.");
            println!("-------------------------------------------------------");
            
            println!("\n>> Public Key:");
            println!("{}", pub_b64);
            
            println!("\n>> Encrypted Private Key (Server Config Only):");
            println!("{}", encrypted_priv);

            println!("\n>> Raw Private Key (Client Local Use Only):");
            println!("{}", priv_b64);
            println!("===============================");
        }
    }

    Ok(())
}

async fn run_server(safe_mode: bool) -> Result<(), Box<dyn Error>> {
    println!("GhostPort v5.0 Starting...");

    // 1. Load Config
    let mut config = match load_config("GhostPort.toml") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load configuration: {}", e);
            return Ok(());
        }
    };

    if safe_mode {
        println!("!!! SAFE MODE ACTIVE !!!");
        println!("Overriding Listen IP to 127.0.0.1. External access is disabled.");
        config.server.listen_ip = "127.0.0.1".to_string();
    }

    println!("Configuration Loaded!");
    println!("   Listen: {}:{}", config.server.listen_ip, config.server.listen_port);
    println!("   Backend: {}", config.backend.target_addr);

    // Get Server Private Key (Decrypted)
    let server_private_key = match config.get_private_key() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("CRITICAL: Failed to decrypt server private key: {}", e);
            eprintln!("Ensure GHOSTPORT_MASTER_KEY is set and matches the encryption key.");
            return Ok(());
        }
    };

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
    // Pass the raw private key
    tokio::spawn(start_watcher(udp_config, server_private_key, udp_whitelist, udp_auth, udp_jail));

    // 7. Start TCP Proxy (Main Thread)
    start_proxy(config, whitelist, waf, jail).await;

    Ok(())
}