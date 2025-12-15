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
        // Decode Inputs
        let decoded_path = match decode(path) {
            Ok(cow) => cow.into_owned(),
            Err(_) => path.to_string(),
        };
        
        // We probably don't want to full URL decode headers as they might contain binary data or special chars that matter,
        // but for WAF purposes, decoding might reveal hidden attacks. 
        // Let's decode headers too, but be careful. 
        // Actually, headers are usually not URL encoded in the same way, but parameters inside them might be.
        // Let's stick to decoding path for now as that's the primary vector for URL encoding attacks.
        
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
