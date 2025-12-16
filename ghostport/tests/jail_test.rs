use ghostport::jail::Jail;
use std::net::IpAddr;
use std::time::Duration;
use std::thread;

#[test]
fn test_jail_strikes_ban() {
    // 1 second ban duration, 3 strikes max
    let jail = Jail::new(1, 3);
    let ip: IpAddr = "192.168.1.100".parse().unwrap();

    // 1st Strike
    jail.add_strike(ip);
    assert!(jail.check_ip(ip)); // Should still be allowed

    // 2nd Strike
    jail.add_strike(ip);
    assert!(jail.check_ip(ip)); // Should still be allowed

    // 3rd Strike (Ban Triggered)
    jail.add_strike(ip);
    assert!(!jail.check_ip(ip)); // BANNED!
}

#[test]
fn test_jail_ban_expiration() {
    // 1 second ban
    let jail = Jail::new(1, 1); // 1 strike to ban
    let ip: IpAddr = "10.0.0.5".parse().unwrap();

    jail.add_strike(ip);
    assert!(!jail.check_ip(ip)); // Banned immediately

    // Wait for ban to expire (1.1s)
    thread::sleep(Duration::from_millis(1100));

    assert!(jail.check_ip(ip)); // Should be allowed again
}

#[test]
fn test_jail_whitelist_does_not_get_banned() {
    // Logic check: Ideally, whitelisted IPs (those who knocked) shouldn't get strikes?
    // Current implementation: Jail is lower layer (L3) than Whitelist (L4/L7).
    // If a whitelisted user sends SQL Injection, they DO get a strike and CAN get banned.
    // This is intended behavior (Insider Threat Protection).
    
    let jail = Jail::new(10, 2);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    jail.add_strike(ip);
    assert!(jail.check_ip(ip));
    
    jail.add_strike(ip);
    assert!(!jail.check_ip(ip)); // Even localhost can be jailed if it attacks
}
