use std::process::{Command, Child, Stdio};
use std::thread;
use std::time::Duration;
use std::fs;
use std::path::PathBuf;
use std::io::{BufRead, BufReader};

// Basic test to ensure the HTTP pipelining fix doesn't break core functionality
#[test]
fn test_http_pipelining_fix_basic_functionality() {
    // This test verifies that the HTTP pipelining fix doesn't break basic functionality
    // by running the existing happy path test which exercises the proxy functionality
    
    let mut ctx = TestContext::new("pipelining_basic");
    ctx.gen_certs();
    let backend_port = get_free_port();
    let quic_port = get_free_port();
    let knock_port = get_free_port();
    let local_port = get_free_port();

    ctx.start_backend(backend_port);
    let bin = TestContext::get_binary_path();

    let output = Command::new(&bin).args(&["keygen", "--master-key", "secret123"]).output().unwrap();
    let (server_pub, server_priv_enc, _) = parse_keygen_output(&String::from_utf8_lossy(&output.stdout));

    let output = Command::new(&bin).args(&["keygen", "--master-key", "temp"]).output().unwrap();
    let (client_pub, _, client_priv_raw) = parse_keygen_output(&String::from_utf8_lossy(&output.stdout));

    ctx.write_config(&server_priv_enc, &client_pub, backend_port, quic_port, knock_port);

    let mut server_child = Command::new(&bin)
        .args(&["server"])
        .env("GHOSTPORT_MASTER_KEY", "secret123")
        .current_dir(&ctx.work_dir)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start server");

    let cert_hash = wait_for_server_hash(&mut server_child);
    ctx.server = Some(server_child);

    let client_child = Command::new(&bin)
        .args(&[
            "connect",
            "--target", &format!("127.0.0.1:{}", quic_port),
            "--knock", &format!("127.0.0.1:{}", knock_port),
            "--local-port", &local_port.to_string(),
            "--server-pub", &server_pub,
            "--my-priv", &client_priv_raw,
            "--server-cert-hash", &cert_hash
        ])
        .spawn()
        .expect("Failed to start client");
    ctx.client = Some(client_child);

    thread::sleep(Duration::from_secs(2));

    // Test that basic access still works with our HTTP pipelining fix in place
    let output = Command::new("curl")
        .args(&["-s", "-f", &format!("http://127.0.0.1:{}/", local_port)])
        .output()
        .expect("Curl failed");

    assert!(output.status.success(), "Basic functionality should still work with HTTP pipelining fix");
    
    println!("HTTP Pipelining Fix Basic Functionality Test Passed");
}

// --- Test Context Manager (RAII) - copied from e2e_system.rs ---
struct TestContext {
    server: Option<Child>,
    client: Option<Child>,
    backend: Option<Child>,
    work_dir: PathBuf,
}

impl TestContext {
    fn new(name: &str) -> Self {
        let work_dir = std::env::temp_dir().join("ghostport_test").join(name);
        if work_dir.exists() {
            fs::remove_dir_all(&work_dir).unwrap();
        }
        fs::create_dir_all(&work_dir).unwrap();
        fs::create_dir_all(work_dir.join("certs")).unwrap();

        let status = Command::new("cargo")
            .args(&["build"])
            .status()
            .expect("Failed to build project");
        if !status.success() {
            panic!("Build failed");
        }

        TestContext {
            server: None,
            client: None,
            backend: None,
            work_dir,
        }
    }

    fn get_binary_path() -> PathBuf {
        let mut path = std::env::current_dir().unwrap();
        path.push("target");
        path.push("debug");
        path.push("ghostport");
        path
    }

    fn gen_certs(&self) {
        let status = Command::new("openssl")
            .args(&["req", "-x509", "-newkey", "rsa:2048", "-keyout", "server.key", "-out", "server.crt", "-days", "1", "-nodes", "-subj", "/CN=localhost"])
            .current_dir(self.work_dir.join("certs"))
            .output()
            .expect("Failed to call openssl");

        if !status.status.success() {
            panic!("OpenSSL failed: {}", String::from_utf8_lossy(&status.stderr));
        }
    }

    fn start_backend(&mut self, port: u16) {
        let child = Command::new("python3")
            .args(&["-m", "http.server", &port.to_string()])
            .current_dir(&self.work_dir)
            .spawn()
            .expect("Failed to start backend");
        self.backend = Some(child);
        thread::sleep(Duration::from_secs(1));
    }

    fn write_config(&self, server_priv_enc: &str, client_pub: &str, backend_port: u16, quic_port: u16, knock_port: u16) {
        let toml = format!(r#"
[server]
listen_ip = "127.0.0.1"
listen_port = {}
knock_port = {}
tls_enabled = true
cert_path = "./certs/server.crt"
key_path = "./certs/server.key"

[backend]
target_addr = "127.0.0.1:{}"
target_host = "localhost"

[security]
enable_deep_analysis = true
session_timeout = 10
encrypted_private_key = "{}"

[security.ban]
enabled = true
ban_duration = 10
max_violations = 2

[[users]]
username = "tester"
roles = ["admin"]
public_key = "{}"

[[rules]]
path = "/"
allowed_roles = ["admin"]
on_fail = "block"

[reporting]
webhook_url = "http://localhost/webhook"
log_all_requests = false
"#, quic_port, knock_port, backend_port, server_priv_enc, client_pub);

        fs::write(self.work_dir.join("GhostPort.toml"), toml).unwrap();
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        if let Some(mut c) = self.server.take() { let _ = c.kill(); }
        if let Some(mut c) = self.client.take() { let _ = c.kill(); }
        if let Some(mut c) = self.backend.take() { let _ = c.kill(); }
    }
}

fn parse_keygen_output(output: &str) -> (String, String, String) {
    let lines: Vec<&str> = output.lines().collect();
    let pub_key = lines.iter().skip_while(|l| !l.contains(">> Public Key:")).nth(1).unwrap().trim().to_string();
    let enc_key = lines.iter().skip_while(|l| !l.contains(">> Encrypted Private Key")).nth(1).unwrap().trim().to_string();
    let raw_key = lines.iter().skip_while(|l| !l.contains(">> Raw Private Key")).nth(1).unwrap().trim().to_string();
    (pub_key, enc_key, raw_key)
}

fn wait_for_server_hash(child: &mut Child) -> String {
    let stdout = child.stdout.as_mut().expect("Failed to capture server stdout");
    let reader = BufReader::new(stdout);

    for line in reader.lines() {
        let l = line.expect("Failed to read line");
        let trimmed = l.trim();
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return trimmed.to_string();
        }
    }
    panic!("Server exited or did not print hash");
}

fn get_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}