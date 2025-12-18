use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use std::net::IpAddr;

// Thread-safe Jail
#[derive(Clone)]
pub struct Jail {
    state: Arc<RwLock<JailState>>,
    ban_duration: Duration,
    max_strikes: u32,
}

struct JailState {
    banned_ips: HashMap<IpAddr, Instant>, // IP -> When is the ban over?
    strikes: HashMap<IpAddr, u32>,        // IP -> Count of bad actions
}

impl Jail {
    pub fn new(ban_duration_secs: u64, max_strikes: u32) -> Self {
        Jail {
            state: Arc::new(RwLock::new(JailState {
                banned_ips: HashMap::new(),
                strikes: HashMap::new(),
            })),
            ban_duration: Duration::from_secs(ban_duration_secs),
            max_strikes,
        }
    }

    /// Returns TRUE if the IP is allowed, FALSE if banned.
    pub fn check_ip(&self, ip: IpAddr) -> bool {
        // Read lock is fast
        let state = match self.state.read() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("CRITICAL: Jail Lock Poisoned: {}", e);
                return false; // Fail-Closed
            }
        };
        
        if let Some(expiry) = state.banned_ips.get(&ip) {
            if Instant::now() < *expiry {
                return false; // STILL BANNED
            }
        }
        true // ALLOWED (or ban expired)
    }

    /// Adds a "strike" to an IP. If they hit the limit, BAN THEM.
    pub fn add_strike(&self, ip: IpAddr) {
        let mut state = match self.state.write() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("CRITICAL: Jail Lock Poisoned during add_strike: {}", e);
                return;
            }
        };
        
        // 1. Increment strikes
        let count = state.strikes.entry(ip).or_insert(0);
        *count += 1;

        println!("Strike {}/{} for IP: {}", count, self.max_strikes, ip);

        // 2. Check if we should ban
        if *count >= self.max_strikes {
            let expiry = Instant::now() + self.ban_duration;
            state.banned_ips.insert(ip, expiry);
            state.strikes.remove(&ip); // Reset strikes
            println!("BANNED IP: {} for {:?}", ip, self.ban_duration);
        }
    }

    /// Immediate Ban (Manual or Critical WAF trigger)
    pub fn ban_immediately(&self, ip: IpAddr) {
        let mut state = match self.state.write() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("CRITICAL: Jail Lock Poisoned during ban_immediately: {}", e);
                return;
            }
        };
        let expiry = Instant::now() + self.ban_duration;
        state.banned_ips.insert(ip, expiry);
        state.strikes.remove(&ip);
        println!("INSTANT BAN: IP {}", ip);
    }

    /// Removes expired bans to prevent memory leaks.
    pub fn cleanup(&self) {
        let mut state = match self.state.write() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("CRITICAL: Jail Lock Poisoned during cleanup: {}", e);
                return;
            }
        };
        let now = Instant::now();
        // Retain only bans that are in the future
        state.banned_ips.retain(|_, expiry| *expiry > now);
    }
}
