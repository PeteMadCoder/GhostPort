use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce}; // Or `XChaCha20Poly1305`
use chacha20poly1305::aead::{Aead, AeadCore, OsRng};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::error::Error;
use argon2::{
    password_hash::{
        rand_core::OsRng as ArgonRng,
        SaltString
    },
    Argon2
};

/// Derives a 32-byte key from the master password using Argon2id.
/// Note: Since we need to reproduce the key for decryption, we usually need a Salt.
/// However, for this simple implementation where the "Master Key" acts as the sole secret,
/// we will use a static salt (derived from the application name) OR store the salt with the encrypted data.
/// Best practice: Store salt with data.
///
/// UPDATED STRATEGY: 
/// `encrypt_private_key` will generate a random Salt, derive the Key, encrypt the data.
/// Output format: Base64(Salt(16) + Nonce(12) + Ciphertext)
fn derive_key(master_key: &str, salt: &[u8]) -> Result<Key, Box<dyn Error>> {
    let mut key_buf = [0u8; 32];
    Argon2::default().hash_password_into(
        master_key.as_bytes(),
        salt,
        &mut key_buf
    ).map_err(|e| format!("Argon2 Error: {}", e))?;
    Ok(*Key::from_slice(&key_buf))
}

/// Encrypts the private key bytes using the master key.
/// Returns a Base64 string: "Salt(16) + Nonce(12) + Ciphertext"
pub fn encrypt_private_key(master_key: &str, private_key: &[u8]) -> Result<String, Box<dyn Error>> {
    // 1. Generate Salt
    let salt = SaltString::generate(&mut ArgonRng);
    
    // 2. Derive Key
    let key = derive_key(master_key, salt.as_str().as_bytes())?;
    
    // 3. Encrypt
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits
    
    let ciphertext = cipher.encrypt(&nonce, private_key)
        .map_err(|e| format!("Encryption failure: {}", e))?;
    
    // 4. Combine: Salt + Nonce + Ciphertext
    // We store the raw bytes of the salt string (usually 22 chars for B64 salt)
    // To make parsing easier, let's fix the salt length or format.
    // Simpler: Just use raw bytes for salt if Argon2 allows, but `SaltString` is better.
    // Let's stick to a fixed size structure. 
    // Format: [SaltLen(1 byte)] [SaltBytes] [Nonce(12)] [Ciphertext]
    
    let salt_bytes = salt.as_str().as_bytes();
    let salt_len = salt_bytes.len() as u8;
    
    let mut combined = Vec::new();
    combined.push(salt_len);
    combined.extend_from_slice(salt_bytes);
    combined.extend_from_slice(&nonce);
    combined.extend(ciphertext);
    
    Ok(BASE64.encode(combined))
}

/// Decrypts the Base64 string using the master key.
pub fn decrypt_private_key(master_key: &str, encrypted_base64: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let encrypted_bytes = BASE64.decode(encrypted_base64)?;
    
    if encrypted_bytes.len() < 14 { // Min: 1 len + 1 salt + 12 nonce
        return Err("Invalid encrypted data: too short".into());
    }
    
    let salt_len = encrypted_bytes[0] as usize;
    if encrypted_bytes.len() < 1 + salt_len + 12 {
         return Err("Invalid encrypted data: malformed structure".into());
    }
    
    let salt_bytes = &encrypted_bytes[1..1+salt_len];
    let nonce_start = 1 + salt_len;
    let nonce_end = nonce_start + 12;
    
    let nonce = Nonce::from_slice(&encrypted_bytes[nonce_start..nonce_end]);
    let ciphertext = &encrypted_bytes[nonce_end..];
    
    let key = derive_key(master_key, salt_bytes)?;
    let cipher = ChaCha20Poly1305::new(&key);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failure: {}", e))?;
        
    Ok(plaintext)
}
