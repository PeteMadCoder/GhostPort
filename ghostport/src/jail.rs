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
    strike_timeout: Duration, // How long to keep strike counts before clearing them
}

struct JailState {
    banned_ips: HashMap<IpAddr, Instant>, // IP -> When is the ban over?
    strikes: HashMap<IpAddr, (u32, Instant)>, // IP -> (Count of bad actions, Last strike time)
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
            strike_timeout: Duration::from_secs(3600), // 1 hour timeout for strikes
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

        let now = Instant::now();

        // 1. Increment strikes or create new entry
        let (count, last_strike_time) = state.strikes.entry(ip).or_insert((0, now));
        *count += 1;
        *last_strike_time = now; // Update the time of the last strike

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

    /// Removes expired bans and old strikes to prevent memory leaks.
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

        // Retain only strikes that are newer than the timeout
        state.strikes.retain(|_, (_, last_strike_time)| {
            *last_strike_time + self.strike_timeout > now
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jail_strikes_cleanup() {
        // Create a jail with a short strike timeout for testing
        let jail = Jail {
            state: Arc::new(RwLock::new(JailState {
                banned_ips: HashMap::new(),
                strikes: HashMap::new(),
            })),
            ban_duration: Duration::from_secs(3600), // 1 hour ban
            max_strikes: 3,
            strike_timeout: Duration::from_secs(1), // 1 second for testing
        };

        let test_ip = "192.168.1.1".parse().unwrap();

        // Add a strike - need to make jail mutable for this
        let mut jail_mut = jail;
        jail_mut.add_strike(test_ip);

        {
            let state = jail_mut.state.read().unwrap();
            assert_eq!(state.strikes.get(&test_ip).unwrap().0, 1); // Strike count should be 1
        }

        // Wait for the strike to expire (more than 1 second)
        std::thread::sleep(Duration::from_secs(2));

        // Perform cleanup
        jail_mut.cleanup();

        {
            let state = jail_mut.state.read().unwrap();
            // The expired strike should be cleaned up
            assert!(!state.strikes.contains_key(&test_ip));
        }
    }

    #[test]
    fn test_jail_strikes_cleanup_preserves_recent() {
        // Create a jail with a short strike timeout for testing
        let jail = Jail {
            state: Arc::new(RwLock::new(JailState {
                banned_ips: HashMap::new(),
                strikes: HashMap::new(),
            })),
            ban_duration: Duration::from_secs(3600), // 1 hour ban
            max_strikes: 3,
            strike_timeout: Duration::from_secs(1), // 1 second for testing
        };

        let old_ip = "192.168.1.1".parse().unwrap();
        let recent_ip = "192.168.1.2".parse().unwrap();

        // Add strikes to both IPs - need to make jail mutable
        let mut jail_mut = jail;
        jail_mut.add_strike(old_ip);
        jail_mut.add_strike(recent_ip);

        // Wait for the old IP's strike to expire
        std::thread::sleep(Duration::from_secs(2));

        // Add another strike to the recent IP (making it recent again)
        jail_mut.add_strike(recent_ip);

        // Perform cleanup
        jail_mut.cleanup();

        {
            let state = jail_mut.state.read().unwrap();
            // The old IP's strike should be cleaned up
            assert!(!state.strikes.contains_key(&old_ip));
            // The recent IP's strike should still be there
            assert!(state.strikes.contains_key(&recent_ip));
            assert_eq!(state.strikes.get(&recent_ip).unwrap().0, 2); // Should have 2 strikes
        }
    }
}
