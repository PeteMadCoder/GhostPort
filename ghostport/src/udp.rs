use tokio::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use crate::config::Config;
use crate::reporting::{send_alert, AlertLevel};

pub async fn start_watcher(config: Config, whitelist: Arc<Mutex<HashMap<IpAddr, Instant>>>) {
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
                let data = &buf[..size];
                let token_bytes = config.security.knock_token.as_bytes();

                if data == token_bytes {
                    println!("KNOCK VALID! Authorizing: {}", addr.ip());
                    {
                        let mut list = whitelist.lock().unwrap();
                        list.insert(addr.ip(), Instant::now());
                    } // Lock is dropped here
                    
                    send_alert(
                        config.clone(), 
                        format!("🔓 Authorized new session for IP: {}", addr.ip()), 
                        AlertLevel::Info
                    ).await;

                } else {
                     // silent drop
                }
            }
            Err(e) => eprintln!("UDP Error: {}", e),
        }
    }
}
