use std::process::Command;
use std::time::Duration;
use std::thread;

#[test]
#[ignore]
fn test_server_startup() {
    // 1. Start Server
    let mut child = Command::new("cargo")
        .arg("run")
        .spawn()
        .expect("Failed to spawn server");

    thread::sleep(Duration::from_secs(5));

    // 2. Check /admin (Should be unauthorized -> Honeypot -> 200 OK)
    // We use -k for self-signed certs.
    // We check if curl exits with 0 (success HTTP code if -f is used, but by default it returns 0 on 200 OK)
    let status = Command::new("curl")
        .arg("-k")
        .arg("-f") // Fail on HTTP error codes (4xx/5xx)
        .arg("https://127.0.0.1:8443/admin")
        .status()
        .expect("Failed to run curl");

    // 3. Kill Server
    let _ = child.kill();

    assert!(status.success());
}