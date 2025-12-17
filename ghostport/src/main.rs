use ghostport::config::{load_config, load_client_config};
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
        target: Option<String>,
        /// Knock Address (IP:Port of the Watcher, e.g., 1.2.3.4:9000)
        #[arg(long)]
        knock: Option<String>,
        /// Local Port to bind (e.g., 2222)
        #[arg(long)]
        local_port: Option<u16>,
        /// Server's Public Key (Base64)
        #[arg(long)]
        server_pub: Option<String>,
        /// Your Private Key (Base64)
        #[arg(long)]
        my_priv: Option<String>,
        /// Server Certificate SHA256 Hash (Hex)
        #[arg(long)]
        server_cert_hash: Option<String>,
        
        /// Profile Name (from Client.toml)
        #[arg(long)]
        profile: Option<String>,
        /// Path to Client Configuration File (default: Client.toml)
        #[arg(long, default_value = "Client.toml")]
        config: String,
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
    // Install Rustls Crypto Provider (Ring)
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { safe_mode } => run_server(safe_mode).await?,
        Commands::Connect { 
            target, knock, local_port, server_pub, my_priv, server_cert_hash, profile, config 
        } => {
            // Logic: Profile > Flags > Error
            let (t, k, l, s, m, h) = if let Some(p_name) = profile {
                let c = load_client_config(&config).map_err(|e| format!("Failed to load {}: {}", config, e))?;
                let p = c.profiles.get(&p_name).ok_or(format!("Profile '{}' not found in {}", p_name, config))?;
                
                (
                    target.unwrap_or(p.target.clone()),
                    knock.unwrap_or(p.knock.clone()),
                    local_port.unwrap_or(p.local_port),
                    server_pub.unwrap_or(p.server_pub.clone()),
                    my_priv.unwrap_or(p.my_priv.clone()),
                    server_cert_hash.unwrap_or(p.server_cert_hash.clone())
                )
            } else {
                // No profile, check flags
                if target.is_none() || knock.is_none() || server_pub.is_none() || my_priv.is_none() || server_cert_hash.is_none() {
                    return Err("Missing required arguments. Use flags or --profile.".into());
                }
                (
                    target.unwrap(),
                    knock.unwrap(),
                    local_port.unwrap_or(2222),
                    server_pub.unwrap(),
                    my_priv.unwrap(),
                    server_cert_hash.unwrap()
                )
            };
            
            start_client(&t, &k, l, &s, &m, &h).await?;
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
            println!("3. Run the server to get the 'Server Certificate Hash' for clients.");
            println!("-------------------------------------------------------");
            println!("OPTION B: Are you setting up a CLIENT?");
            println!("1. Copy 'Public Key' to the Server's GhostPort.toml -> [[users]] -> public_key");
            println!("2. Use 'Raw Private Key' when running the 'connect' command.");
            println!("3. Ask the Admin for the 'Server Certificate Hash'.");
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

    // 2. Shared State (The Session Store)
    // Map: Token ([u8; 32]) -> (Timestamp, Roles)
    let session_store: Arc<Mutex<HashMap<[u8; 32], (Instant, Vec<String>)>>> = Arc::new(Mutex::new(HashMap::new()));

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
    let udp_sessions = session_store.clone();
    let udp_auth = auth.clone();
    let udp_jail = jail.clone();
    // Pass the raw private key
    tokio::spawn(start_watcher(udp_config, server_private_key, udp_sessions, udp_auth, udp_jail));

    // 7. Start TCP Proxy (Main Thread)
    start_proxy(config, session_store, waf, jail).await;

    Ok(())
}