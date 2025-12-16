use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce}; // Or `XChaCha20Poly1305`
use chacha20poly1305::aead::{Aead, AeadCore, OsRng};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::error::Error;

/// Derives a 32-byte key from the master password using SHA256.
fn derive_key(master_key: &str) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(master_key.as_bytes());
    let result = hasher.finalize();
    *Key::from_slice(&result)
}

/// Encrypts the private key bytes using the master key.
/// Returns a Base64 string: "nonce(12) + ciphertext"
pub fn encrypt_private_key(master_key: &str, private_key: &[u8]) -> Result<String, Box<dyn Error>> {
    let key = derive_key(master_key);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    
    let ciphertext = cipher.encrypt(&nonce, private_key)
        .map_err(|e| format!("Encryption failure: {}", e))?;
    
    // Combine nonce and ciphertext
    let mut combined = nonce.to_vec();
    combined.extend(ciphertext);
    
    Ok(BASE64.encode(combined))
}

/// Decrypts the Base64 string using the master key.
pub fn decrypt_private_key(master_key: &str, encrypted_base64: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let encrypted_bytes = BASE64.decode(encrypted_base64)?;
    
    if encrypted_bytes.len() < 12 {
        return Err("Invalid encrypted data: too short".into());
    }
    
    let key = derive_key(master_key);
    let cipher = ChaCha20Poly1305::new(&key);
    
    let nonce = Nonce::from_slice(&encrypted_bytes[..12]);
    let ciphertext = &encrypted_bytes[12..];
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failure: {}", e))?;
        
    Ok(plaintext)
}
