# Vulnerability Report Template

### [VULN-009] Noise Handshake Replay Attack

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `High`
* **CVSS Score:** `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)`
* **Affected Component:** `UDP Listener (src/udp.rs)`
* **Affected Versions:** `v4.0.0 - v5.0.0`
* **Patched Version:** `v5.1.0`
* **Date Found:** `2025-12-15`
* **Date Fixed:** `2025-12-16`

## 2. Description

**Summary:**
The initial Noise Protocol implementation authenticated the key but did not prevent replay attacks. A captured UDP knock packet could be replayed by an attacker to open the port again (in the IP-based auth model).

**Root Cause:**
The payload inside the encrypted Noise packet was static or empty.

**Attack Vector:**
1. Admin knocks to open port.
2. Attacker sniffs the UDP packet (Port 9000).
3. Attacker waits for the session to close.
4. Attacker replays the UDP packet.
5. Server re-authorizes the IP.

**Technical Impact:**
Unauthorized access to the system.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium (Requires sniffing).
* **Business Impact:** Unauthorized access.
* **Risk:** High.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Capture a valid UDP knock using `tcpdump`.
2. Wait 5 minutes.
3. Replay packet using `tcpreplay`.
4. Observe server logs accepting the knock.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Added a signed **Timestamp** (8 bytes) to the Noise payload. The server now rejects any packet with a timestamp older than 30 seconds.

### Verification

* **Method:** E2E Test (`test_e2e_replay_attack`).
* **Verified By:** Automated Suite on 2025-12-16.

## 6. Classification & References

* **Category:** Broken Authentication
* **CWE ID:** CWE-294 (Authentication Bypass by Capture-replay)