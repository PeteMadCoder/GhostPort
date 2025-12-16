use ghostport::crypto::{encrypt_private_key, decrypt_private_key};

#[test]
fn test_crypto_roundtrip() {
    let master_key = "super_secret_password";
    let original_priv_key = b"this is a 32 byte key for testing!!"; // 35 bytes actually, but fine
    
    // 1. Encrypt
    let encrypted_b64 = encrypt_private_key(master_key, original_priv_key)
        .expect("Encryption failed");
    
    assert_ne!(encrypted_b64, String::from_utf8_lossy(original_priv_key));

    // 2. Decrypt
    let decrypted = decrypt_private_key(master_key, &encrypted_b64)
        .expect("Decryption failed");
        
    assert_eq!(decrypted, original_priv_key);
}

#[test]
fn test_crypto_wrong_password() {
    let master_key = "correct_password";
    let wrong_key = "wrong_password";
    let original_priv_key = b"data";
    
    let encrypted = encrypt_private_key(master_key, original_priv_key).unwrap();
    
    let result = decrypt_private_key(wrong_key, &encrypted);
    assert!(result.is_err());
}
