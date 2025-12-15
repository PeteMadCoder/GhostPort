use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use totp_rs::{Algorithm, TOTP};
use std::time::Duration;
use crate::config::UserConfig;

pub struct AuthManager {
    users: HashMap<String, (TOTP, Vec<String>)>,
    used_codes: Arc<Mutex<HashSet<String>>>,
}

impl AuthManager {
    pub fn new(user_configs: &[UserConfig]) -> Self {
        let mut users = HashMap::new();
        
        for u in user_configs {
            let secret_str = u.secret.clone().unwrap_or_else(|| "JBSWY3DPEHPK3PXP".to_string());
            
            // Fix 1: RFC4648 -> Rfc4648
            let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret_str)
                .expect("Invalid Base32 Secret");

            // Fix 2: TOTP::new signature
            let totp = TOTP::new(
                Algorithm::SHA1,
                6,  // digits
                1,  // skew
                30, // step
                secret_bytes,
            ).unwrap();

            users.insert(u.username.clone(), (totp, u.roles.clone()));
        }

        let manager = AuthManager {
            users,
            used_codes: Arc::new(Mutex::new(HashSet::new())),
        };
        
        manager.start_cleaner();
        
        manager
    }

    fn start_cleaner(&self) {
        let cache_ref = self.used_codes.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(90)).await;
                let mut cache = cache_ref.lock().unwrap();
                cache.clear(); 
            }
        });
    }

    pub fn verify(&self, username: &str, code: &str) -> Option<Vec<String>> {
        let (totp, roles) = self.users.get(username)?;

        let replay_key = format!("{}:{}", username, code);
        {
            let cache = self.used_codes.lock().unwrap();
            if cache.contains(&replay_key) {
                println!("REPLAY ATTACK BLOCKED: {} used code {} again.", username, code);
                return None;
            }
        }

        let valid = totp.check_current(code).unwrap_or(false);
        if !valid {
            println!("Invalid Code for {}", username);
            return None;
        }

        {
            let mut cache = self.used_codes.lock().unwrap();
            cache.insert(replay_key);
            println!("Code burned for {}", username);
        }

        println!("Access Granted: {} {:?}", username, roles);
        Some(roles.clone())
    }
}