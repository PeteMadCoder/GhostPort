use snow::Builder;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

static NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[test]
fn test_keygen_format() {
    let builder = Builder::new(NOISE_PATTERN.parse().unwrap());
    let keypair = builder.generate_keypair().expect("Failed to generate keys");

    // 1. Check raw length (32 bytes for 25519)
    assert_eq!(keypair.public.len(), 32);
    assert_eq!(keypair.private.len(), 32);

    // 2. Check Base64 encoding
    let pub_b64 = BASE64.encode(&keypair.public);
    let _priv_b64 = BASE64.encode(&keypair.private);

    // Base64 of 32 bytes is always 44 chars ending in '='
    assert_eq!(pub_b64.len(), 44);
    assert!(pub_b64.ends_with('='));
    
    // 3. Verify decoding works
    let decoded_pub = BASE64.decode(&pub_b64).expect("Failed to decode pub");
    assert_eq!(decoded_pub, keypair.public);
}
