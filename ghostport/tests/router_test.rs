use ghostport::router::{match_route, RoutingDecision};
use ghostport::config::{Config, RuleConfig, ServerConfig, BackendConfig, SecurityConfig, ReportingConfig, BanConfig};

fn mock_config() -> Config {
    let config = Config {
        server: ServerConfig { 
            listen_ip: "0.0.0.0".into(), 
            listen_port: 0, 
            knock_port: 0,
            tls_enabled: false, 
            cert_path: "".into(), 
            key_path: "".into(),
            max_connections: None,
            max_concurrent_bidi_streams: None,
            max_idle_timeout_ms: None,
        },
        backend: BackendConfig { target_addr: "".into(), target_host: "".into() },
        security: SecurityConfig { 
            enable_deep_analysis: false, 
            session_timeout: 0, 
            honeypot_file: None,
            ban: BanConfig { enabled: false, ban_duration: 0, max_violations: 0 },
            encrypted_private_key: Some("mock".into()),
            authorized_keys: None
        },
        reporting: ReportingConfig { webhook_url: "".into(), log_all_requests: false },
        rules: vec![
            RuleConfig { path: "/".into(), allowed_roles: Some(vec!["admin".into()]), on_fail: "block".into() },
            RuleConfig { path: "/admin".into(), allowed_roles: Some(vec!["superadmin".into()]), on_fail: "honeypot".into() },
            RuleConfig { path: "/api/v1".into(), allowed_roles: None, on_fail: "block".into() }, // None means "Any authenticated user"
        ],
        users: None,
    };
    config
}

#[test]
fn test_root_route() {
    let config = mock_config();
    let result = match_route("/", &config);
    
    if let RoutingDecision::Matched(rule) = result {
        assert_eq!(rule.path, "/");
        assert_eq!(rule.allowed_roles, Some(vec!["admin".to_string()]));
    } else {
        panic!("Should match root rule");
    }
}

#[test]
fn test_admin_route() {
    let config = mock_config();
    let result = match_route("/admin/dashboard", &config);
    
    if let RoutingDecision::Matched(rule) = result {
        assert_eq!(rule.path, "/admin");
        assert_eq!(rule.on_fail, "honeypot");
    } else {
        panic!("Should match admin rule");
    }
}

#[test]
fn test_longest_prefix_match() {
    let config = mock_config();
    // Should match /api/v1 not /
    let result = match_route("/api/v1/users", &config);
    
    if let RoutingDecision::Matched(rule) = result {
        assert_eq!(rule.path, "/api/v1");
        assert!(rule.allowed_roles.is_none());
    } else {
        panic!("Should match api rule");
    }
}

#[test]
fn test_no_match_defaults_block() {
    let mut config = mock_config();
    config.rules.clear(); // Remove all rules
    assert_eq!(match_route("/unknown", &config), RoutingDecision::DefaultBlock);
}
