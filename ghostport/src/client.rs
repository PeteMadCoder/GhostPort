use snow::Builder;
use tokio::net::{UdpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::error::Error;
use std::sync::Arc;
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Sha256, Digest};
use rand::Rng;

static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

// Secure Certificate Pinner
#[derive(Debug)]
struct PinServerVerification {
    expected_hash: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for PinServerVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let actual_hash = hasher.finalize();

        if actual_hash.as_slice() == self.expected_hash.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("Certificate Pinning Mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

pub async fn start_client(
    target_addr: &str, // IP:Port of GhostPort Server (QUIC)
    knock_addr: &str,  // IP:Port of GhostPort Watcher (UDP)
    local_port: u16,   // Local TCP port to bind (e.g., 2222)
    server_pub_key_b64: &str,
    my_priv_key_b64: &str,
    server_cert_hash_hex: &str // New Arg
) -> Result<(), Box<dyn Error>> {
    
    // Parse Hash
    let expected_hash = hex::decode(server_cert_hash_hex)
        .map_err(|_| "Invalid Server Cert Hash (Hex)")?;

    // 1. Send the Knock (Noise Auth)
    println!("Initiating Noise Handshake with {}...", knock_addr);
    let token = send_knock(knock_addr, server_pub_key_b64, my_priv_key_b64).await?;
    println!("Knock sent! Connection authorized.");

    // 2. Setup Local TCP Listener
    let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port)).await?;
    println!("Local Tunnel Active: 127.0.0.1:{} -> {}", local_port, target_addr);
    println!("You can now connect via: ssh -p {} user@localhost", local_port);

    // 3. Configure QUIC Client
    let roots = rustls::RootCertStore::empty();
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    // Install Pinner
    crypto.dangerous().set_certificate_verifier(Arc::new(PinServerVerification { expected_hash }));
    crypto.alpn_protocols = vec![b"hq-29".to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("Failed to convert rustls config")
    ));
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    // 4. Accept Local Connections and Tunnel them
    loop {
        let (mut tcp_socket, _) = listener.accept().await?;
        println!("New Local Connection. Tunneling...");

        // Connect to GhostPort via QUIC
        let addr = target_addr.parse().expect("Invalid Target Address");
        
        // Connect with implicit verification via Pinner
        let connection = match endpoint.connect(addr, "localhost")?.await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to connect (Cert Pinning Failed?): {}", e);
                continue;
            }
        };
        
        // Open a Bi-directional stream
        let (mut send_stream, mut recv_stream) = match connection.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to open stream: {}", e);
                continue;
            }
        };

        // Send Session Token
        if let Err(e) = send_stream.write_all(&token).await {
            eprintln!("Failed to send token: {}", e);
            continue;
        }

        // Spawn Tunnel Logic
        tokio::spawn(async move {
            let (mut rd_tcp, mut wr_tcp) = tcp_socket.split();

            let client_to_server = async {
                let mut buf = [0u8; 4096];
                loop {
                    let n = rd_tcp.read(&mut buf).await?;
                    if n == 0 { break; }
                    send_stream.write_all(&buf[..n]).await?;
                }
                send_stream.finish()?;
                Ok::<(), std::io::Error>(())
            };

            let server_to_client = async {
                // copy_buf equivalent for QUIC stream
                loop {
                    match recv_stream.read_chunk(4096, true).await {
                        Ok(Some(chunk)) => {
                            wr_tcp.write_all(&chunk.bytes).await?;
                        }
                        Ok(None) => break, 
                        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                    }
                }
                wr_tcp.shutdown().await?;
                Ok::<(), std::io::Error>(())
            };

            let _ = tokio::join!(client_to_server, server_to_client);
            println!("Tunnel Closed.");
        });
    }
}

pub async fn send_knock(
    server_addr: &str,
    server_pub_key_b64: &str,
    my_priv_key_b64: &str
) -> Result<[u8; 32], Box<dyn Error>> {
    let server_pub = BASE64.decode(server_pub_key_b64)?;
    let my_priv = BASE64.decode(my_priv_key_b64)?;

    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let mut noise = builder
        .local_private_key(&my_priv)
        .remote_public_key(&server_pub)
        .build_initiator()?;

    // PAYLOAD: Current Timestamp (8 bytes) + Token (32 bytes)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    
    let mut rng = rand::thread_rng();
    let mut token = [0u8; 32];
    rng.fill(&mut token);

    let mut payload = Vec::with_capacity(40);
    payload.extend_from_slice(&now.to_be_bytes());
    payload.extend_from_slice(&token);

    let mut buf = [0u8; 65535];
    let len = noise.write_message(&payload, &mut buf)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&buf[..len], server_addr).await?;

    Ok(token)
}