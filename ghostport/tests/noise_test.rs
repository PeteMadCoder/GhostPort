use snow::Builder;

static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[test]
fn test_noise_handshake_flow() {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());

    // 1. Setup Identities
    let server_keys = builder.generate_keypair().unwrap();
    let client_keys = builder.generate_keypair().unwrap();

    // 2. Client: Initiator
    let mut initiator = Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(&client_keys.private)
        .remote_public_key(&server_keys.public)
        .build_initiator()
        .unwrap();

    // 3. Server: Responder
    let mut responder = Builder::new(NOISE_PATTERN.parse().unwrap())
        .local_private_key(&server_keys.private)
        .build_responder()
        .unwrap();

    // --- The Handshake ---

    let mut message_buffer = [0u8; 65535];
    let mut payload_buffer = [0u8; 65535];

    // PAYLOAD: Timestamp
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = now.to_be_bytes();

    // Step A: Client -> Server (Write)
    // "Knock" packet with timestamp
    let len = initiator.write_message(&payload, &mut message_buffer).unwrap();
    
    // Step B: Server (Read)
    let payload_len = responder.read_message(&message_buffer[..len], &mut payload_buffer).expect("Server failed to decrypt knock");
    assert_eq!(payload_len, 8);

    // Step C: Verify Timestamp
    let ts_bytes: [u8; 8] = payload_buffer[..8].try_into().unwrap();
    let received_ts = u64::from_be_bytes(ts_bytes);
    assert_eq!(received_ts, now);

    // Step D: Verify Identity
    let remote_static = responder.get_remote_static().expect("Server did not recover Client Public Key");
    assert_eq!(remote_static, &client_keys.public[..]);
}

#[test]
fn test_expired_timestamp_logic() {
    let now = 100000;
    let old_ts = 99900; // 100 seconds ago

    let _is_valid = old_ts > now + 30 || old_ts < now - 30;
    
    // We expect it to be INVALID (outside window)
    // Actually, the variable name `is_valid` is misleading in my previous code logic.
    // Let's rewrite for clarity.
    
    let is_outside_window = old_ts > now + 30 || old_ts < now - 30;
    assert!(is_outside_window, "Old timestamp should be outside the valid window");
}

