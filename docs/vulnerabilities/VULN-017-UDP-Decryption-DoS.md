# Vulnerability Report Template

### [VULN-017] UDP Decryption DoS (Incomplete VULN-001 Fix)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `High`
* **CVSS Score:** `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)`
* **Affected Component:** `UDP Listener (src/udp.rs)`
* **Affected Versions:** `v5.3.0`
* **Patched Version:** `v5.3.1`
* **Date Found:** `2025-12-18`
* **Date Fixed:** `2025-12-18`

## 2. Description

**Summary:**
While VULN-001 added a pre-check for banned IPs, it failed to penalize IPs that sent invalid packets which failed the cryptographic decryption phase. An attacker could flood the server with garbage packets; the server would perform expensive Noise handshakes (Curve25519) and fail decryption, but never ban the attacker, leading to CPU exhaustion.

**Root Cause:**
The `jail.add_strike()` call was missing in the `Err` branch of `noise.read_message()` in `src/udp.rs`.

**Attack Vector:**
An attacker sends a high volume of random UDP packets. The server checks the Jail (allowed), then attempts to decrypt (expensive). The decryption fails, but the IP receives no strike. The attacker continues indefinitely.

**Technical Impact:**
High CPU usage (DoS) as the server attempts to decrypt millions of invalid packets without ever banning the source.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (Trivial to exploit).
* **Business Impact:** Service unavailability.
* **Risk:** High.

## 4. Proof of Concept (PoC)

1. Send UDP packets with random payload (not valid Noise protocol) to port 9000.
2. Observe server logs: "Decryption Failed" (if enabled) or just no output.
3. Observe `jail` state: The IP is never banned.
4. Scale up attack to flood CPU.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Added `jail.add_strike(addr.ip())` to the `else` block of the decryption check in `src/udp.rs`. Now, sending garbage packets results in an immediate strike and subsequent ban.

### Verification

* **Method:** Code Audit.
* **Verified By:** Security Audit on 2025-12-18.

## 6. Classification & References

* **Category:** Denial of Service
* **CWE ID:** CWE-400
