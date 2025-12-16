use tokio::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use crate::config::Config;
use crate::reporting::{send_alert, AlertLevel};
use crate::auth::AuthManager;
use crate::jail::Jail;
use snow::Builder;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

pub async fn start_watcher(
    config: Config, 
    server_private_key: Vec<u8>,
    whitelist: Arc<Mutex<HashMap<IpAddr, (Instant, Vec<String>)>>>,
    auth: Arc<AuthManager>,
    jail: Jail
) {
    let knock_addr = "0.0.0.0:9000"; 

    let socket = match UdpSocket::bind(knock_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind UDP Watcher: {}", e);
            return;
        }
    };

    println!("GhostPort Watcher (Noise UDP) listening on {}", knock_addr);

    let mut buf = [0u8; 65535];
    let mut payload_buf = [0u8; 65535];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, addr)) => {
                // Initialize Noise Responder for each packet
                let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
                let mut noise = match builder.local_private_key(&server_private_key).build_responder() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Noise Build Error: {}", e);
                        continue;
                    }
                };

                // Attempt to read the handshake message
                if let Ok(_) = noise.read_message(&buf[..size], &mut payload_buf) {
                    if let Some(remote_static) = noise.get_remote_static() {
                        let pub_key_b64 = BASE64.encode(remote_static);
                        
                        if let Some((username, roles)) = auth.verify_key(&pub_key_b64) {
                            println!("Authorized Noise Session: {} [{}]", username, pub_key_b64);
                            
                            {
                                let mut list = whitelist.lock().unwrap();
                                list.insert(addr.ip(), (Instant::now(), roles.clone()));
                            }

                            send_alert(
                                config.clone(), 
                                format!("Authorized new session for IP: {} (User: {})", addr.ip(), username), 
                                AlertLevel::Info
                            ).await;
                        } else {
                            println!("Unauthorized Key: {}", pub_key_b64);
                            jail.add_strike(addr.ip());
                        }
                    } else {
                        // IK pattern should have remote static after first message if successful
                         jail.add_strike(addr.ip());
                    }
                } else {
                    // Decryption failed (Bad Key or Bad Noise)
                    // Silent drop (maybe debug log)
                    // println!("Decryption Failed from {}", addr);
                }
            }
            Err(e) => eprintln!("UDP Error: {}", e),
        }
    }
}