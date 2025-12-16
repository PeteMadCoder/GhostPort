use snow::Builder;
use tokio::net::UdpSocket;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::error::Error;

static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

pub async fn send_knock(
    server_addr: &str,
    server_pub_key_b64: &str,
    my_priv_key_b64: &str
) -> Result<(), Box<dyn Error>> {
    let server_pub = BASE64.decode(server_pub_key_b64)?;
    let my_priv = BASE64.decode(my_priv_key_b64)?;

    let builder = Builder::new(NOISE_PATTERN.parse()?);
    let mut noise = builder
        .local_private_key(&my_priv)
        .remote_public_key(&server_pub)
        .build_initiator()?;

    let mut buf = [0u8; 65535];
    // Write first handshake message (payload empty)
    let len = noise.write_message(&[], &mut buf)?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&buf[..len], server_addr).await?;

    println!("Knock sent to {} ({} bytes)", server_addr, len);
    Ok(())
}
