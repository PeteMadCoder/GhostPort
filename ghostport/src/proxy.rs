use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use tokio::sync::Semaphore;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::IpAddr;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::Instant;

use tokio_rustls::rustls::{ServerConfig as TlsServerConfig, pki_types::{CertificateDer, PrivateKeyDer, PrivateKeyDer::Pkcs8}};
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::router::{match_route, RoutingDecision};
use crate::reporting::{send_alert, AlertLevel};
use crate::waf::WafEngine;
use crate::honeypot::serve_honeypot;
use crate::jail::Jail;

// Constants
const HEADER_READ_TIMEOUT: u64 = 5; // seconds

// Load Certificates
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

// Load Private Key
fn load_keys(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    
    if let Some(key) = keys.into_iter().next() {
        Ok(Pkcs8(key))
    } else {
        Err("No private key found".into())
    }
}

pub async fn start_proxy(
    config: Config, 
    whitelist: Arc<Mutex<HashMap<IpAddr, Instant>>>, 
    waf: Arc<WafEngine>,
    jail: Jail
) {
    let addr = format!("{}:{}", config.server.listen_ip, config.server.listen_port);
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind TCP Proxy");
    
    println!("GhostPort (TCP) listening on {}", addr);
    println!("Forwarding traffic to {}", config.backend.target_addr);

    // Setup TLS if enabled
    let tls_acceptor = if config.server.tls_enabled {
        println!("TLS Enabled. Loading certs...");
        let certs = load_certs(Path::new(&config.server.cert_path)).expect("Failed to load certs");
        let key = load_keys(Path::new(&config.server.key_path)).expect("Failed to load key");
        
        let tls_config = TlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("Invalid TLS config");
            
        Some(TlsAcceptor::from(Arc::new(tls_config)))
    } else {
        None
    };

    // Connection Limiter (DoS Protection)
    let max_conn = config.server.max_connections.unwrap_or(1000);
    let connection_limit = Arc::new(Semaphore::new(max_conn));
    println!("🛡️ DoS Shield Active: Max {} concurrent connections", max_conn);

    loop {
        // 1. Accept Connection
        let (client_socket, addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };

        // 2. JAIL CHECK (Active Defense)
        // If banned, drop immediately.
        if !jail.check_ip(addr.ip()) {
            // Silent drop (don't even log to avoid log spam)
            continue; 
        }

        // 3. Acquire Permit
        let permit = match connection_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Semaphore error: {}", e);
                break;
            }
        };

        let config_clone = config.clone();
        let whitelist_clone = whitelist.clone();
        let acceptor = tls_acceptor.clone();
        let waf_clone = waf.clone();
        let jail_clone = jail.clone();

        tokio::spawn(async move {
            let _permit = permit;

            if let Some(tls) = acceptor {
                match timeout(Duration::from_secs(HEADER_READ_TIMEOUT), tls.accept(client_socket)).await {
                    Ok(Ok(stream)) => {
                         if let Err(e) = handle_connection(stream, addr, config_clone, whitelist_clone, waf_clone, jail_clone).await {
                             eprintln!("[{}] Connection Error: {}", addr, e);
                         }
                    }
                    Ok(Err(e)) => eprintln!("[{}] TLS Handshake Error: {}", addr, e),
                    Err(_) => eprintln!("[{}] TLS Handshake Timeout (Slowloris?)", addr),
                }
            } else {
                if let Err(e) = handle_connection(client_socket, addr, config_clone, whitelist_clone, waf_clone, jail_clone).await {
                    eprintln!("[{}] Connection Error: {}", addr, e);
                }
            }
        });
    }
}

async fn handle_connection<T>(
    mut client_socket: T, 
    addr: std::net::SocketAddr,
    config: Config,
    whitelist: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    waf: Arc<WafEngine>,
    jail: Jail
) -> Result<(), Box<dyn Error>> 
where T: AsyncRead + AsyncWrite + Unpin + Send 
{

    // 1. Read Headers (Peek) with TIMEOUT
    let mut buffer = [0; 4096];
    
    let read_result = timeout(
        Duration::from_secs(HEADER_READ_TIMEOUT), 
        client_socket.read(&mut buffer)
    ).await;

    let n = match read_result {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(Box::new(e)),
        Err(_) => {
            return Err("Slowloris Timeout".into());
        }
    };

    if n == 0 { return Ok(()); }

    // 2. Parse Headers
    let headers_end = buffer[..n].windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or("Invalid HTTP: No header terminator")?;
    
    let header_bytes = &buffer[..headers_end];
    let header_str = String::from_utf8_lossy(header_bytes);
    
    let mut lines = header_str.lines();
    let request_line = lines.next().ok_or("Invalid HTTP: Empty")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 { return Err("Invalid Request Line".into()); }
    
    let method = parts[0];
    let path = parts[1];

    // 3. ROUTING DECISION
    let decision = match_route(path, &config);
    println!("Request: {} {} -> {:?}", method, path, decision);

    match decision {
        RoutingDecision::DefaultBlock => {
            send_alert(config.clone(), format!("Blocked access to unknown route {} from {}", path, addr), AlertLevel::Warning).await;
            jail.add_strike(addr.ip()); // Strike! 
            let resp = "HTTP/1.1 403 Forbidden\r\n\r\n<h1>403 Forbidden</h1>";
            client_socket.write_all(resp.as_bytes()).await?;
            return Ok(());
        }
        RoutingDecision::Matched(rule) => {
            if rule.rule_type == "public" {
                // Public Route: Proceed (WAF Check below)
            } else if rule.rule_type == "private" {
                // Check Whitelist with Expiry
                let is_authorized = {
                    let mut list = whitelist.lock().unwrap();
                    if let Some(timestamp) = list.get(&addr.ip()) {
                        if timestamp.elapsed() < Duration::from_secs(config.security.session_timeout) {
                            true
                        } else {
                            println!("Session expired for {}", addr.ip());
                            list.remove(&addr.ip());
                            false
                        }
                    } else {
                        false
                    }
                };

                if !is_authorized {
                    println!("BLOCKED PRIVATE ROUTE: {} tried accessing {}", addr, path);
                    
                    if rule.on_fail == "honeypot" {
                        // NO STRIKE - Let them play
                        println!("Redirecting to HONEYPOT (Intelligence Mode)");
                        if let Err(e) = serve_honeypot(client_socket, config.clone(), addr.to_string(), method).await {
                             eprintln!("Honeypot error: {}", e);
                        }
                    } else {
                        // STRIKE & BLOCK
                        jail.add_strike(addr.ip()); 
                        send_alert(config.clone(), format!("🛑 Unauthorized access to {} from {}", path, addr), AlertLevel::Warning).await;
                        let resp = "HTTP/1.1 403 Forbidden\r\n\r\n<h1>Access Denied</h1>";
                        client_socket.write_all(resp.as_bytes()).await?;
                    }
                    return Ok(());
                }
            }
        }
    }

    // 4. WAF CHECK
    // If WAF triggers, we ALWAYS strike, because payloads are malicious regardless of route.
    if let Some(threat) = waf.check_request(path, &header_str) {
         println!("🔥 WAF DETECTED: {} from {}", threat, addr);
         send_alert(config.clone(), format!("🔥 WAF DETECTED ATTACK from {}: {} ({})", addr, path, threat), AlertLevel::Critical).await;
         
         jail.add_strike(addr.ip()); 
         
         let resp = "HTTP/1.1 403 Forbidden\r\n\r\n<h1>Malicious Request Detected</h1>";
         client_socket.write_all(resp.as_bytes()).await?;
         return Ok(());
    }

    // 5. Connect to Backend
    let mut backend_socket = TcpStream::connect(&config.backend.target_addr).await?;

    // 6. Rewrite Headers
    let mut new_headers = String::new();
    new_headers.push_str(request_line);
    new_headers.push_str("\r\n");
    for line in lines {
                if line.to_lowercase().starts_with("host:") {
                    new_headers.push_str(&format!("Host: {}\r\n", config.backend.target_host));
                } else {
            new_headers.push_str(line);
            new_headers.push_str("\r\n");
        }
    }
    new_headers.push_str("\r\n");

    // 7. Forward
    backend_socket.write_all(new_headers.as_bytes()).await?;
    let body_start = headers_end + 4;
    if body_start < n {
        backend_socket.write_all(&buffer[body_start..n]).await?;
    }

    tokio::io::copy_bidirectional(&mut client_socket, &mut backend_socket).await?;

    Ok(())
}