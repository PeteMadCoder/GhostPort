use tokio::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use crate::config::Config;
use crate::reporting::{send_alert, AlertLevel};
use crate::auth::AuthManager;
use crate::jail::Jail;

pub async fn start_watcher(
    config: Config, 
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

    println!("GhostPort Watcher (UDP) listening on {}", knock_addr);

    let mut buf = [0; 1024];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((size, addr)) => {
                let packet_content = String::from_utf8_lossy(&buf[..size]).trim().to_string();
                
                // Parse "username:code"
                let parts: Vec<&str> = packet_content.split(':').collect();
                
                if parts.len() == 2 {
                    let username = parts[0];
                    let code = parts[1];

                    if let Some(roles) = auth.verify(username, code) {
                        println!("{} authorized with roles {:?}", username, roles);
                        {
                            let mut list = whitelist.lock().unwrap();
                            list.insert(addr.ip(), (Instant::now(), roles));
                        }
                        
                        send_alert(
                            config.clone(), 
                            format!("Authorized new session for IP: {} (User: {})", addr.ip(), username), 
                            AlertLevel::Info
                        ).await;
                    } else {
                        println!("Auth failed for {}", username);
                        jail.add_strike(addr.ip());
                    }
                } else {
                    // Invalid format or legacy knock?
                    // We treat it as strike if strict, or ignore.
                    // Let's ignore to prevent noise from random UDP.
                }
            }
            Err(e) => eprintln!("UDP Error: {}", e),
        }
    }
}