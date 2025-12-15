use crate::config::Config;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

pub async fn send_alert(config: Config, message: String, level: AlertLevel) {
    let url = &config.reporting.webhook_url;
    if url.is_empty() || url == "https://discord.com/api/webhooks/12345/abcde" {
        // Don't send if URL is empty or default placeholder
        return;
    }

    // Basic JSON payload for Discord/Slack
    // Discord format: { "content": "message" }
    // We'll format it manually to avoid serde_json dependency if possible, 
    // or just use format! since we have serde.
    
    let color = match level {
        AlertLevel::Info => 3066993, // Green
        AlertLevel::Warning => 16776960, // Yellow
        AlertLevel::Critical => 15158332, // Red
    };

    // Discord specific payload (embeds are nicer)
    let json_payload = format!(
        r#"{{
            "content": null,
            "embeds": [
                {{
                    "title": "GhostPort Alert: {:?}",
                    "description": "{}",
                    "color": {}
                }}
            ]
        }}"#,
        level, message, color
    );

    let url_clone = url.clone();
    
    // Spawn a fire-and-forget task
    tokio::spawn(async move {
        let child = Command::new("curl")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(&json_payload)
            .arg(&url_clone)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();

        match child {
            Ok(_) => {}, // Success spawning
            Err(e) => eprintln!("Failed to send webhook: {}", e),
        }
    });
}
