# Vulnerability Report Template

### [VULN-012] TOTP Replay Attack

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `High`
* **CVSS Score:** `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)`
* **Affected Component:** `TOTP Verifier`
* **Affected Versions:** `v3.0.0 (Initial Beta)`
* **Patched Version:** `v3.0.0 (Release)`
* **Date Found:** `2025-12-12`
* **Date Fixed:** `2025-12-13`

## 2. Description

**Summary:**
During the initial implementation of TOTP (Time-based One-Time Passwords), the server did not track used codes. Since TOTP codes are valid for a 30-second window (plus/minus clock skew), an attacker could capture a valid code and replay it immediately within that window to gain access.

**Root Cause:**
Missing "Used Code Cache" (Nonce mechanism) for the TOTP window.

**Attack Vector:**
1. User sends TOTP `123456`.
2. Attacker sniffs packet.
3. Attacker immediately sends `123456` (within the same 30s window).
4. Server accepts the second code.

**Technical Impact:**
Authentication Bypass / Session Hijacking.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium.
* **Business Impact:** Unauthorized Access.
* **Risk:** High.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Generate valid TOTP.
2. Send it twice within 5 seconds.
3. Observe both are accepted (in vulnerable version).

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented a **Burnt Code Cache**. The server now stores every successfully used TOTP code (and its timestamp) in memory. If the same code is received again within its validity window, it is rejected.

## 6. Classification & References

* **Category:** Broken Authentication
* **CWE ID:** CWE-294 (Authentication Bypass by Capture-replay)