use std::collections::HashMap;
use crate::config::UserConfig;

pub struct AuthManager {
    // Map: PublicKey (Base64) -> (Username, Roles)
    users: HashMap<String, (String, Vec<String>)>,
}

impl AuthManager {
    pub fn new(user_configs: &[UserConfig]) -> Self {
        let mut users = HashMap::new();
        
        for u in user_configs {
            users.insert(u.public_key.clone(), (u.username.clone(), u.roles.clone()));
        }

        AuthManager {
            users,
        }
    }

    pub fn verify_key(&self, pub_key: &str) -> Option<(String, Vec<String>)> {
        self.users.get(pub_key).cloned()
    }
}