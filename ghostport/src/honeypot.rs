use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::sync::Arc;
use crate::config::Config;
use crate::reporting::{send_alert, AlertLevel};
use std::time::Duration;

const DEFAULT_HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login</title>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; font-size: 0.9em; display: none; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2 style="text-align: center; color: #333;">Administration</h2>
        <form method="POST" action="/login_check">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
            <div class="error" id="err">Invalid credentials</div>
        </form>
    </div>
    <script>
        document.querySelector('form').onsubmit = function(e) {
            // We let the form submit naturally so the POST request hits our server again
            // which allows us to capture the password in the logs above.
        };
    </script>
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