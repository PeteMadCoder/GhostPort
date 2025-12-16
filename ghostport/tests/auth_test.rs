use ghostport::auth::AuthManager;
use ghostport::config::UserConfig;

#[test]
fn test_auth_manager() {
    let users = vec![
        UserConfig {
            username: "alice".to_string(),
            roles: vec!["admin".to_string()],
            public_key: "PublicKeyA=".to_string(),
        },
        UserConfig {
            username: "bob".to_string(),
            roles: vec!["dev".to_string()],
            public_key: "PublicKeyB=".to_string(),
        },
    ];

    let auth = AuthManager::new(&users);

    // Test Valid Key
    let result = auth.verify_key("PublicKeyA=");
    assert!(result.is_some());
    let (user, roles) = result.unwrap();
    assert_eq!(user, "alice");
    assert_eq!(roles, vec!["admin"]);

    // Test Invalid Key
    assert!(auth.verify_key("UnknownKey=").is_none());
}
