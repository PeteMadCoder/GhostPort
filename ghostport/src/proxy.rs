use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::{Instant, Duration};
use urlencoding::decode;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivateKeyDer::Pkcs8};
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};

use crate::config::Config;
use crate::router::{match_route, RoutingDecision};
use crate::waf::WafEngine;
use crate::jail::Jail;

// Constants
const HEADER_READ_TIMEOUT: u64 = 5; // seconds

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

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

use sha2::{Sha256, Digest};

// ... existing imports ...

pub async fn start_proxy(
    config: Config, 
    session_store: Arc<Mutex<HashMap<[u8; 32], (Instant, Vec<String>)>>>, 
    waf: Arc<WafEngine>,
    jail: Jail
) {
    let addr_str = format!("{}:{}", config.server.listen_ip, config.server.listen_port);
    let addr: SocketAddr = addr_str.parse().expect("Invalid Listen Address");
    
    println!("GhostPort (QUIC) listening on {}", addr);
    println!("Forwarding traffic to {}", config.backend.target_addr);

    // 1. Setup QUIC Server Config
    let certs = load_certs(Path::new(&config.server.cert_path)).expect("Failed to load certs");
    let key = load_keys(Path::new(&config.server.key_path)).expect("Failed to load key");
    
    // --- PRINT CERT FINGERPRINT ---
    if let Some(first_cert) = certs.first() {
        let mut hasher = Sha256::new();
        hasher.update(first_cert.as_ref());
        let hash = hasher.finalize();
        println!("----------------------------------------------------------");
        println!("Server Certificate SHA256 Fingerprint:");
        println!("{}", hex::encode(hash));
        println!("(Use this for --server-cert-hash on the client)");
        println!("----------------------------------------------------------");
    }
    // -----------------------------
    
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Invalid TLS config");
        
    crypto.alpn_protocols = vec![b"hq-29".to_vec()]; // Basic HTTP/0.9 ALPN for simplicity or "hq"

    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("Failed to convert rustls config")
    ));

    // Apply Transport Limits
    let mut transport_config = quinn::TransportConfig::default();
    if let Some(max_streams) = config.server.max_concurrent_bidi_streams {
        transport_config.max_concurrent_bidi_streams(max_streams.into());
    }
    if let Some(timeout_ms) = config.server.max_idle_timeout_ms {
         transport_config.max_idle_timeout(Some(quinn::IdleTimeout::try_from(Duration::from_millis(timeout_ms)).unwrap()));
    }
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = Endpoint::server(server_config, addr).expect("Failed to bind QUIC Endpoint");

    let max_conn = config.server.max_connections.unwrap_or(1000);
    let connection_limit = Arc::new(Semaphore::new(max_conn));

    // 2. Accept Loop
    while let Some(conn) = endpoint.accept().await {
        let remote_addr = conn.remote_address();
        
        // IP Check (Layer 3 Firewall)
        if !jail.check_ip(remote_addr.ip()) {
            // In Quinn 0.11, dropping the `Incoming` (conn) refuses the connection implicitly 
            // or we can accept and close. Dropping is cleaner for "Refused".
            continue; 
        }

        let permit = match connection_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Semaphore error: {}", e);
                break;
            }
        };

        let config_clone = config.clone();
        let session_store_clone = session_store.clone();
        let waf_clone = waf.clone();
        let jail_clone = jail.clone();

        tokio::spawn(async move {
            let _permit = permit; // Hold permit
            
            // Establish the QUIC connection
            let connection = match conn.await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("QUIC Handshake Error from {}: {}", remote_addr, e);
                    return;
                }
            };

            // Accept Bi-directional Streams
            while let Ok((send_stream, recv_stream)) = connection.accept_bi().await {
                let config_c = config_clone.clone();
                let store_c = session_store_clone.clone();
                let waf_c = waf_clone.clone();
                let jail_c = jail_clone.clone();
                
                tokio::spawn(async move {
                    if let Err(_e) = handle_stream(send_stream, recv_stream, remote_addr, config_c, store_c, waf_c, jail_c).await {
                         // eprintln!("Stream Error: {}", _e);
                    }
                });
            }
        });
    }
}

async fn handle_stream(
    mut send_stream: quinn::SendStream,
    mut recv_stream: quinn::RecvStream,
    addr: SocketAddr,
    config: Config,
    session_store: Arc<Mutex<HashMap<[u8; 32], (Instant, Vec<String>)>>>,
    waf: Arc<WafEngine>,
    jail: Jail
) -> Result<(), Box<dyn Error>>
{
    // 0. TOCTOU CHECK (Layer 3 Firewall per Stream)
    // Even if the connection is open, check if the IP got banned recently.
    if !jail.check_ip(addr.ip()) {
        send_stream.finish()?;
        return Ok(());
    }

    // 1. AUTHENTICATION (Token Check)
    let mut token = [0u8; 32];
    if let Err(_) = recv_stream.read_exact(&mut token).await {
         return Err("Failed to read Session Token".into());
    }

    let client_roles = {
        let mut list = match session_store.lock() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("CRITICAL: Session Store Lock Poisoned: {}", e);
                send_stream.finish()?;
                return Err("Internal Server Error (Lock Poisoned)".into());
            }
        };
        // Check if token exists and remove it (Single Use)
        if let Some((timestamp, roles)) = list.remove(&token) {
             if timestamp.elapsed() < Duration::from_secs(config.security.session_timeout) {
                 roles
             } else {
                 println!("Session Token Expired from {}", addr);
                 send_stream.finish()?;
                 return Ok(());
             }
        } else {
             println!("Invalid Session Token from {}", addr);
             jail.add_strike(addr.ip());
             send_stream.finish()?;
             return Ok(());
        }
    };

    // 2. PEEK AND BUFFER: Read initial bytes to find HTTP headers (with size limit)
    let mut buffer = [0u8; 4096]; // 4KB limit to prevent buffering DoS

    let n = match tokio::time::timeout(Duration::from_secs(HEADER_READ_TIMEOUT), recv_stream.read(&mut buffer)).await {
        Ok(Ok(Some(n))) => n,
        Ok(Ok(None)) => return Ok(()), // EOF
        Ok(Err(e)) => return Err(Box::new(e)),
        Err(_) => return Err("Timeout".into()),
    };

    let headers_end = buffer[..n].windows(4).position(|w| w == b"\r\n\r\n")
        .ok_or("Invalid HTTP: No header terminator")?;

    let header_bytes = &buffer[..headers_end];
    // Strict UTF-8 enforcement: reject request if not valid UTF-8
    let header_str = match String::from_utf8(header_bytes.to_vec()) {
        Ok(s) => s,
        Err(_) => {
            println!("Invalid UTF-8 in request headers from {}", addr);
            jail.add_strike(addr.ip());
            send_stream.finish()?;
            return Ok(());
        }
    };

    let mut lines = header_str.lines();
    let request_line = lines.next().ok_or("Invalid HTTP: Empty")?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 { return Err("Invalid Request Line".into()); }

    let method = parts[0];
    let path = parts[1];

    // Decode Path for Routing (ACL Bypass Fix)
    // We must route based on the *canonical* path, otherwise /%61dmin != /admin
    let mut canonical_path = path.to_string();
    for _ in 0..5 {
        match decode(&canonical_path) {
            Ok(cow) => {
                let next = cow.into_owned();
                if next == canonical_path { break; }
                canonical_path = next;
            },
            Err(_) => break, 
        }
    }

    // 3. ROUTING DECISION (RBAC)
    let decision = match_route(&canonical_path, &config);
    
    match decision {
        RoutingDecision::DefaultBlock => {
            jail.add_strike(addr.ip()); 
            send_stream.finish()?;
            return Ok(());
        }
        RoutingDecision::Matched(rule) => {
            if let Some(allowed) = &rule.allowed_roles {
                if !client_roles.iter().any(|r| allowed.contains(r)) {
                    println!("RBAC DENIED: {} tried accessing {}", addr, canonical_path);
                    if rule.on_fail == "honeypot" {
                        let _ = send_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n<h1>System Error</h1>").await;
                    } else {
                        jail.add_strike(addr.ip()); 
                    }
                    send_stream.finish()?;
                    return Ok(());
                }
            }
        }
    }

    // 4. WAF CHECK
    if let Some(threat) = waf.check_request(path, &header_str) {
         println!("WAF DETECTED: {} from {}", threat, addr);
         jail.add_strike(addr.ip()); 
         send_stream.finish()?;
         return Ok(());
    }

    // 5. TCP EGRESS (Forward to Backend)
    let mut backend_socket = TcpStream::connect(&config.backend.target_addr).await?;

    // Header Surgery: Handle CONNECT vs other HTTP methods differently
    let is_connect = method == "CONNECT";

    // Rewrite Headers (Host and Connection)
    let mut new_headers = String::new();
    new_headers.push_str(request_line);
    new_headers.push_str("\r\n");

    for line in lines {
        // Skip any existing Connection headers to replace them
        if line.to_lowercase().starts_with("connection:") {
            continue; // Skip existing Connection header
        } else if line.to_lowercase().starts_with("host:") {
            new_headers.push_str(&format!("Host: {}\r\n", config.backend.target_host));
        } else {
            new_headers.push_str(line);
            new_headers.push_str("\r\n");
        }
    }

    // Inject Connection: close for non-CONNECT methods (the fix for pipelining)
    if is_connect {
        // For CONNECT methods, preserve persistent behavior
        new_headers.push_str("Connection: keep-alive\r\n");
    } else {
        // For all other HTTP methods, force close to prevent pipelining
        new_headers.push_str("Connection: close\r\n");
    }

    new_headers.push_str("\r\n");

    backend_socket.write_all(new_headers.as_bytes()).await?;
    let body_start = headers_end + 4;
    if body_start < n {
        backend_socket.write_all(&buffer[body_start..n]).await?;
    }

    // 6. BRIDGE (QUIC Stream <-> TCP Socket)
    let (mut rd_tcp, mut wr_tcp) = backend_socket.split();

    if is_connect {
        // For CONNECT methods (tunnels), maintain persistent behavior
        let client_to_server = async {
            loop {
                match recv_stream.read_chunk(4096, true).await {
                    Ok(Some(chunk)) => {
                        wr_tcp.write_all(&chunk.bytes).await?;
                    }
                    Ok(None) => break, // EOF
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                }
            }
            wr_tcp.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };

        let server_to_client = async {
            let mut buf = [0u8; 4096];
            loop {
                let n = rd_tcp.read(&mut buf).await?;
                if n == 0 { break; }
                send_stream.write_all(&buf[..n]).await?;
            }
            send_stream.finish()?;
            Ok::<(), std::io::Error>(())
        };

        let _ = tokio::join!(client_to_server, server_to_client);
    } else {
        // For non-CONNECT methods, implement one-shot behavior (fix for pipelining)
        let client_to_server = async {
            // Send data from client to server once
            loop {
                match recv_stream.read_chunk(4096, true).await {
                    Ok(Some(chunk)) => {
                        wr_tcp.write_all(&chunk.bytes).await?;
                    }
                    Ok(None) => break, // EOF
                    Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                }
            }
            wr_tcp.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };

        let server_to_client = async {
            // Receive response from server and forward to client once
            let mut buf = [0u8; 4096];
            loop {
                let n = rd_tcp.read(&mut buf).await?;
                if n == 0 { break; }
                send_stream.write_all(&buf[..n]).await?;
            }
            Ok::<(), std::io::Error>(())
        };

        let _ = tokio::join!(client_to_server, server_to_client);

        // Explicitly finish the send stream after one transaction to prevent pipelining
        send_stream.finish()?;
    }

    Ok(())
}
