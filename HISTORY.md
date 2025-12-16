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

## v5.0: The Stealth Bunker (Current)
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
