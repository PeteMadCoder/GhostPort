use ghostport::waf::WafEngine;

#[test]
fn test_waf_sqli() {
    let waf = WafEngine::new();
    assert!(waf.check_request("/search?q=union select", "").is_some());
    assert!(waf.check_request("/login?u=admin' OR 1=1", "").is_some());
}

#[test]
fn test_waf_xss() {
    let waf = WafEngine::new();
    assert!(waf.check_request("/comment?msg=<script>alert(1)</script>", "").is_some());
    assert!(waf.check_request("/link?url=javascript:evil()", "").is_some());
}

#[test]
fn test_waf_traversal() {
    let waf = WafEngine::new();
    assert!(waf.check_request("/../../etc/passwd", "").is_some());
}

#[test]
fn test_clean_request() {
    let waf = WafEngine::new();
    assert!(waf.check_request("/home", "Host: example.com").is_none());
}

#[test]
fn test_header_attack() {
    let waf = WafEngine::new();
    assert!(waf.check_request("/", "User-Agent: <script>").is_some());
}
