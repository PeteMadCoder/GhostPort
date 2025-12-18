use regex::Regex;
use urlencoding::decode;

pub struct WafEngine {
    rules: Vec<Regex>,
}

impl WafEngine {
    pub fn new() -> Self {
        let patterns = vec![
            // SQL Injection
            r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from|update\s+\w+\s+set)",
            r"(?i)(\s+or\s+1\s*=\s*1)", // Simple OR 1=1
            r"(?i)(--\s|#\s)",          // Comments in SQL (require space)
            
            // XSS (Cross Site Scripting)
            r"(?i)(<script|javascript:|vbscript:|on\w+\s*=)",
            
            // Path Traversal / LFI
            r"(\.\./|\.\.\\|/etc/passwd|c:\\windows)",
        ];

        let rules = patterns.into_iter()
            .map(|p| Regex::new(p).expect("Invalid WAF Regex"))
            .collect();

        WafEngine { rules }
    }

    pub fn check_request(&self, path: &str, headers: &str) -> Option<String> {
        // Recursively Decode Inputs (Anti-Evasion)
        let mut decoded_path = path.to_string();
        for _ in 0..5 {
            match decode(&decoded_path) {
                Ok(cow) => {
                    let next = cow.into_owned();
                    if next == decoded_path { break; } // Stopped changing
                    decoded_path = next;
                },
                Err(_) => break, // Decoding failed, stop
            }
        }
        
        // Check Path
        for rule in &self.rules {
            if rule.is_match(&decoded_path) {
                return Some(format!("Pattern detected in PATH: {:?}", rule));
            }
        }

        // Check Headers (e.g., User-Agent or Referer attacks)
        if self.rules.iter().any(|r| r.is_match(headers)) {
             return Some("Pattern detected in HEADERS".to_string());
        }

        None
    }
}
