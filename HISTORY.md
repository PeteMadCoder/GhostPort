# GhostPort Development History

This document tracks the evolution of GhostPort, detailing the strategic shifts, feature additions, and architectural changes for each major version.

---

## v1.0: The Prototype
**Goal:** Create a minimal, high-performance TCP proxy in Rust to replace heavier solutions like Nginx for simple forwarding tasks.

### Key Features
*   **Async Core:** Built on `tokio` for non-blocking I/O.
*   **Simple Proxying:** Used `tokio::io::copy_bidirectional` to bridge client TCP streams to backend services.
*   **HTTP Parsing:** Implemented basic HTTP 1.1 header parsing to understand `Host` and `Method`.
*   **Virtual Hosts:** Added support for Host Header Spoofing (routing traffic based on the `Host` header).

---

## v2.0: The Security Gateway
**Goal:** Transform the proxy into a security tool capable of defending against scanning and automated attacks.

### Key Features
*   **Single Packet Authorization (SPA):** Introduced the concept of the "Invisible Server". Services remain hidden until a specific UDP packet is received.
*   **Honeypot (v1):** First implementation of the deception module. Unauthorized users were redirected to a fake "Admin Panel" to capture credentials.
*   **Hot-Swappable Config:** Introduced `GhostPort.toml` to replace hardcoded constants, allowing configuration changes without recompilation.
*   **Webhooks:** Integrated Discord and Slack webhooks for real-time security alerts.

---

## v2.1: The Hardened Edition
**Goal:** Improve resilience against Denial of Service (DoS) attacks and active exploitation.

### Key Features
*   **The Jailkeeper:** An active ban system.
    *   Logic: 3 Strikes (Failed Auth or WAF triggers) = 1 Hour IP Ban.
    *   Implementation: Drops packets from banned IPs immediately at the socket level.
*   **DoS Protection:**
    *   **Slowloris Defense:** Enforced strict 5-second timeouts on HTTP header reading.
    *   **Connection Limits:** Added Semaphore-based concurrency limiting (Default: 1000 simultaneous connections).
*   **WAF Improvements:** Added URL-decoding to the WAF engine to catch encoded attacks (e.g., `%27` vs `'`).

---

## v3.0: Identity & Access Management (IAM)
**Goal:** Move from "IP-based Trust" to "Identity-based Trust".

### Key Features
*   **TOTP Integration:** Replaced static passwords/strings in the UDP knock with Time-based One-Time Passwords (`HMAC-SHA1`).
*   **Replay Protection:** Implemented a "Burnt Code" cache. Once a TOTP code is used, it cannot be reused, preventing replay attacks.
*   **RBAC (Role-Based Access Control):**
    *   Users are assigned roles (e.g., `["admin", "dev"]`).
    *   Routing rules enforce role requirements (e.g., `/admin` requires `superadmin`).
*   **Deep Packet Inspection:** WAF now inspects both Headers and Path for SQL Injection and XSS signatures.

---

## v4.0: The Crypto-Identity Edition
**Goal:** Eliminate "Security by Obscurity" and introduce mathematical security for authentication and configuration.

### Key Features
*   **Noise Protocol:** Replaced TOTP with `Noise_IK_25519_ChaChaPoly_BLAKE2s`. The "Knock" is now an encrypted cryptographic handshake.
*   **Mutual Authentication:** Both Client and Server verify each other's identities using static public keys.
*   **Encrypted Configuration:** The Server's Private Key is stored as an encrypted Base64 blob in `GhostPort.toml`, decrypted only at runtime via an environment variable (`GHOSTPORT_MASTER_KEY`).
*   **Zero Plaintext Secrets:** Removed all plaintext secrets from the configuration file.
*   **New CLI Tools:** Added `knock` (client) and `keygen` (utility) commands to the binary.

---

## v5.0: The Stealth Bunker
**Goal:** A strategic pivot from a generic web proxy to a specialized, invisible gateway for critical internal infrastructure.

### The Paradigm Shift
In v5.0, GhostPort abandoned the idea of being a "better Nginx". It is no longer designed to serve public web traffic. It is designed to be a black hole to everyone except authorized admins.

### Major Architectural Changes
1.  **Protocol Migration (TCP &rarr; UDP/QUIC):**
    *   **Change:** Removed all `TcpListener` logic.
    *   **Reason:** TCP is noisy (SYN/ACK) and easy to scan. UDP allows for "Silence" (Packet Drops).
    *   **Benefit:** Enables **Session Roaming**. Clients can switch networks (Wi-Fi &rarr; 4G) without dropping connections due to QUIC Connection IDs.

2.  **Local Tunneling:**
    *   **Change:** Users can no longer connect directly with a browser or SSH client.
    *   **Feature:** Introduced `ghostport connect`. This CLI command starts a local TCP listener (e.g., `localhost:2222`) that bridges traffic into the encrypted QUIC tunnel.

3.  **Safety Systems:**
    *   **Anti-Lockout Watchdog:** A script (`watchdog.sh`) monitors the process. If it crashes repeatedly, it automatically opens standard SSH (Port 22) via UFW/Iptables to prevent admin lockout.
    *   **Safe Mode:** Added `--safe-mode` flag to force binding to `127.0.0.1` for debugging.

4.  **Feature Reductions (Hardening):**
    *   **Removed Public Routes:** The `type="public"` config was removed. All routes are now strictly private.
    *   **Removed Strict WAF Toggle:** The WAF is now "Always On" and set to maximum strictness.
    *   **Updated Honeypot:** Replaced the generic login page with a "Secure Infrastructure Gateway" fake portal to better match the new use case.

---

## v5.1: Security Hardening
**Goal:** Address critical vulnerabilities found in v5.0 audits and establish a rigorous testing baseline.

### Key Features
*   **Certificate Pinning:** Addressed a critical MITM vulnerability in the QUIC tunnel. The client now strictly verifies the server's certificate SHA256 fingerprint (`--server-cert-hash`) before sending data.
*   **Timestamp Replay Protection:** Addressed a replay vulnerability in the Noise handshake. The UDP "Knock" now contains a signed timestamp, and the server rejects packets older than 30 seconds.
*   **Comprehensive Test Suite:** Added `tests/e2e_system.rs` for full end-to-end regression testing (Server + Client + Backend + Keys + Config), along with unit tests for Jail, Router, and WAF.

---

## v5.2: The Hardened Core & Client Experience
**Goal:** Fix critical architectural flaws (Session Hijacking) and improve production usability.

### Security Fixes (Critical)
*   **Session Tokens:** Removed IP-based authorization (which failed behind NATs). Implemented a cryptographically secure **Session Token** system.
    *   Clients generate a random 32-byte token during the UDP knock.
    *   This token is validated and consumed by the QUIC server to authorize the stream.
    *   This eliminates the risk of IP spoofing or shared-NAT hijacking.
*   **Fail-Closed Architecture:** Removed the dangerous "Fail-Open" logic from the watchdog. If GhostPort crashes, ports remain closed, maintaining the stealth posture.
*   **Argon2 KDF:** Upgraded private key encryption from SHA256 to **Argon2id** (memory-hard) to prevent brute-force attacks on the master key.

### Operational Improvements
*   **Client Profiles:** Added support for `Client.toml` and the `--profile` flag. Users can now save connection details for multiple environments (Production, Staging) instead of typing long CLI flags.
*   **QUIC Resource Limits:** Enforced strict limits on `max_concurrent_bidi_streams` and `max_idle_timeout` in the server configuration to prevent DoS attacks via resource exhaustion.
*   **Systemd Integration:** Added a production-ready `ghostport.service` file with hardening directives.

### Testing
*   **Negative Testing:** Added regression tests for Certificate Pinning failures and Replay Attacks to ensure security controls are active.

---

## v5.3: DoS Resilience
**Goal:** Address Critical Denial-of-Service vulnerabilities identified in the 5.2 security audit.

### Security Fixes
*   **VULN-001 (UDP CPU Exhaustion):** Implemented a "Pre-Auth IP Check". The UDP Watcher now checks if an IP is banned **before** attempting to process/decrypt the Noise handshake. This prevents banned IPs from exhausting server CPU with garbage packets.
*   **VULN-002 (Token Leak):** Implemented a "Housekeeper" background task that periodically scans the Session Store and removes expired tokens to prevent memory exhaustion.
*   **VULN-003 (Jail Leak):** The Housekeeper now also cleans up expired bans from the Jail memory, preventing infinite growth of the ban list.

---

## v5.3.1: Security Patch (Current)
**Goal:** Emergency fixes for residual DoS vectors found in 5.3 post-release audit.

### Security Fixes
*   **VULN-017 (UDP Decryption DoS):** Fixed a logical flaw in VULN-001 where invalid packets (bad key/decrypt fail) did not trigger a strike/ban, allowing attackers to bypass the Jail and exhaust CPU. Now, any Noise handshake failure immediately strikes the source IP.
*   **VULN-018 (Lock Poisoning):** Removed all `unwrap()` calls on internal locks (`Mutex`/`RwLock`). The system now handles lock poisoning gracefully (failing closed for the specific request) instead of panicking the entire server process.