use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use crate::config::Config;
use crate::reporting::{send_alert, AlertLevel};
use std::time::Duration;

const DEFAULT_HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Secure Gateway Access</title>
    <style>
        body { background-color: #2b2b2b; color: #e0e0e0; font-family: 'Courier New', Courier, monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .container { border: 1px solid #444; padding: 2rem; background: #333; width: 400px; box-shadow: 0 0 10px rgba(0,0,0,0.5); }
        h2 { text-align: center; margin-bottom: 1.5rem; color: #fff; }
        .input-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; }
        input { width: 100%; padding: 0.5rem; background: #444; border: 1px solid #555; color: white; box-sizing: border-box; }
        button { width: 100%; padding: 0.7rem; background: #007bff; color: white; border: none; cursor: pointer; font-weight: bold; margin-top: 1rem; }
        button:hover { background: #0056b3; }
        .banner { font-size: 0.8rem; color: #888; margin-top: 2rem; text-align: center; border-top: 1px solid #444; padding-top: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Secure Infrastructure Gateway</h2>
        <form method="POST" action="/auth/v1/session">
            <div class="input-group">
                <label>Identity Key</label>
                <input type="text" name="key" required>
            </div>
            <div class="input-group">
                <label>Passphrase</label>
                <input type="password" name="passphrase" required>
            </div>
            <button type="submit">Authenticate</button>
        </form>
        <div class="banner">
            UNAUTHORIZED ACCESS IS PROHIBITED.<br>
            ALL ACTIVITY IS LOGGED AND MONITORED.
        </div>
    </div>
</body>
</html>
"#;

pub async fn serve_honeypot<T>(mut socket: T, config: Config, client_ip: String, method: &str) -> Result<(), Box<dyn Error>> 
where T: AsyncRead + AsyncWrite + Unpin + Send
{
    // 1. Capture Payload (Only if POST)
    // We use a timeout to ensure we never hang if the client is slow or done sending.
    if method == "POST" {
        let mut buffer = [0; 4096];
        // Wait max 500ms for body data
        match tokio::time::timeout(Duration::from_millis(500), socket.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let payload = String::from_utf8_lossy(&buffer[..n]);
                let log_msg = format!("HONEYPOT CAPTURE from {}:\nPayload: {}", client_ip, payload);
                send_alert(config.clone(), log_msg, AlertLevel::Critical).await;
            },
            Ok(Ok(_)) => { /* EOF, empty body */ },
            Ok(Err(e)) => eprintln!("Honeypot Read Error: {}", e),
            Err(_) => { /* Timeout, assume no body or slow client */ }
        }
    } else {
        let log_msg = format!("HONEYPOT VISIT from {}", client_ip);
        send_alert(config.clone(), log_msg, AlertLevel::Warning).await;
    }

    // 2. The Deception (Fake Response)
    let html_body = if let Some(path) = &config.security.honeypot_file {
        match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => {
                DEFAULT_HTML.to_string()
            }
        }
    } else {
        DEFAULT_HTML.to_string()
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Type: text/html\r\n\
        Content-Length: {}\r\n\
        Server: Apache/2.4.49 (Unix)\r\n\
        Connection: close\r\n\
        \r\n\
        {}",
        html_body.len(),
        html_body
    );

    // 3. Send the trap
    socket.write_all(response.as_bytes()).await?;
    
    // 4. Sleep to waste time (Tarpit)
    tokio::time::sleep(Duration::from_secs(2)).await;

    Ok(())
}