use ghostport::router::{match_route, RouteAction};
use ghostport::config::{Config, RuleConfig, ServerConfig, BackendConfig, SecurityConfig, ReportingConfig};

fn mock_config() -> Config {
    Config {
        server: ServerConfig { listen_ip: "0.0.0.0".into(), listen_port: 0, tls_enabled: false, cert_path: "".into(), key_path: "".into() },
        backend: BackendConfig { target_addr: "".into(), target_host: "".into() },
        security: SecurityConfig { enable_deep_analysis: false, knock_token: "".into(), session_timeout: 0, honeypot_file: None },
        reporting: ReportingConfig { webhook_url: "".into(), log_all_requests: false },
        rules: vec![
            RuleConfig { path: "/".into(), rule_type: "public".into(), strict_waf: false, on_fail: "block".into() },
            RuleConfig { path: "/admin".into(), rule_type: "private".into(), strict_waf: true, on_fail: "honeypot".into() },
            RuleConfig { path: "/api/v1".into(), rule_type: "public".into(), strict_waf: false, on_fail: "block".into() },
        ],
    }
}

#[test]
fn test_public_route() {
    let config = mock_config();
    assert_eq!(match_route("/", &config), RouteAction::Allow);
    assert_eq!(match_route("/about", &config), RouteAction::Allow);
}

#[test]
fn test_private_route() {
    let config = mock_config();
    assert_eq!(match_route("/admin", &config), RouteAction::RequireKnock);
    assert_eq!(match_route("/admin/users", &config), RouteAction::RequireKnock);
}

#[test]
fn test_longest_prefix_match() {
    let config = mock_config();
    assert_eq!(match_route("/api/v1/users", &config), RouteAction::Allow);
}

#[test]
fn test_no_match_defaults_block() {
    let mut config = mock_config();
    config.rules.retain(|r| r.path != "/");
    assert_eq!(match_route("/unknown", &config), RouteAction::Block);
}
