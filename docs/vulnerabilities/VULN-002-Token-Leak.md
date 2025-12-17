# Vulnerability Report Template

### [VULN-002] Token Store Memory Leak

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `High`
* **CVSS Score:** `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)`
* **Affected Component:** `Session Store (src/main.rs, src/proxy.rs)`
* **Affected Versions:** `v5.2.0`
* **Patched Version:** `v5.3.0`
* **Date Found:** `2025-12-17`
* **Date Fixed:** `2025-12-17`

## 2. Description

**Summary:**
The application stores authenticated session tokens in an in-memory `HashMap`. Tokens are only removed when they are successfully redeemed by a QUIC connection. If a client generates a token (UDP Knock) but never connects (QUIC), the token remains in memory indefinitely.

**Root Cause:**
Lack of a background cleanup process ("Garbage Collection") for the `session_store` HashMap.

**Attack Vector:**
An attacker with a valid key (or a compromised low-privilege key) can send millions of valid UDP knocks without following up with a QUIC connection.

**Technical Impact:**
The server's RAM is slowly exhausted by 32-byte tokens until the process crashes (OOM Kill), causing a Denial of Service.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium (Requires valid key).
* **Business Impact:** Service crash requiring manual restart; Potential for repeated crashes if attack persists.
* **Risk:** High.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Configure a client with valid keys.
2. Modify the client code to loop `send_knock` infinitely but **never** call `connect`.
3. Run the modified client against the server.
4. Monitor server memory usage (`htop` or `ps`). Observe memory climbing steadily until OOM.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented a `start_housekeeper` background task in `src/main.rs`. It scans the `session_store` every 60 seconds and removes any tokens older than the configured session timeout.

### Verification

* **Method:** Code Review.
* **Verified By:** Automated Suite on 2025-12-17.

## 6. Classification & References

* **Category:** Denial of Service (Memory Exhaustion)
* **CWE ID:** CWE-401 (Missing Release of Memory after Effective Lifetime)