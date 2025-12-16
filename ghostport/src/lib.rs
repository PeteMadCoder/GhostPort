pub mod config;
pub mod proxy;
pub mod udp;
pub mod waf;
pub mod router;
pub mod reporting;
pub mod honeypot;
pub mod jail;
pub mod auth;
pub mod crypto;
pub mod knocker;

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use std::error::Error;

// Re-export key functions for main.rs
pub use config::load_config;
pub use udp::start_watcher;
pub use proxy::start_proxy;
pub use waf::WafEngine;
pub use jail::Jail;
pub use auth::AuthManager;