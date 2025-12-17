# Vulnerability Report Template

### [VULN-001] UDP CPU Exhaustion (Pre-Auth DoS)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Critical`
* **CVSS Score:** `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)`
* **Affected Component:** `UDP Listener (src/udp.rs)`
* **Affected Versions:** `v5.0.0 - v5.2.0`
* **Patched Version:** `v5.3.0`
* **Date Found:** `2025-12-17`
* **Date Fixed:** `2025-12-17`

## 2. Description

**Summary:**
The application fails to validate the source IP against the blacklist (Jail) *before* processing the incoming UDP packet. This allows a banned attacker to force the server to perform expensive cryptographic operations (Curve25519 scalar multiplication and ChaCha20 decryption) on garbage data.

**Root Cause:**
The `noise.read_message()` function, which performs the decryption, was called immediately after `socket.recv_from()`. The `jail.check_ip()` call was missing at the start of the loop.

**Attack Vector:**
An attacker sends a flood of random UDP packets (e.g., 1Gbps) to port 9000. Even if the attacker's IP is banned, the server burns CPU cycles attempting to decrypt every single packet.

**Technical Impact:**
The server reaches 100% CPU usage processing invalid packets, causing a Denial of Service (DoS) for legitimate users trying to authenticate.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (Trivial to exploit with standard packet generators).
* **Business Impact:** Loss of availability for critical infrastructure access. Admin lockout during attacks.
* **Risk:** Critical (High Likelihood + High Availability Impact).

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Determine the GhostPort server IP.
2. Ban a test client IP (by sending 3 invalid knocks).
3. From the banned IP, launch a UDP flood: `hping3 --udp -p 9000 --flood <SERVER_IP>`.
4. Monitor server CPU usage (`htop`). It will spike to 100%.

## 5. Remediation & Status Tracking

### Current Status
Fixed in v5.3.

### Solution / Controls

* **Fix Implemented:** Added a "Pre-Auth IP Check" in `src/udp.rs`. The server now checks `jail.check_ip()` immediately upon packet receipt. If the IP is banned, the packet is silently dropped *before* any cryptography occurs.

### Verification

* **Method:** Code Review and E2E Test (`tests/jail_test.rs` confirms logic).
* **Verified By:** Automated Suite on 2025-12-17.

## 6. Classification & References

* **Category:** Denial of Service
* **CWE ID:** CWE-400 (Uncontrolled Resource Consumption)
