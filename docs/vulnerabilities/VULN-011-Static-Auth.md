# Vulnerability Report Template

### [VULN-011] Static Credentials (Weak Authentication)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Critical`
* **CVSS Score:** `9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)`
* **Affected Component:** `Authentication Module`
* **Affected Versions:** `v1.0.0 - v2.1.0`
* **Patched Version:** `v3.0.0`
* **Date Found:** `2025-12-12`
* **Date Fixed:** `2025-12-13`

## 2. Description

**Summary:**
Early versions of GhostPort used static strings (passwords) sent in the UDP packet for Single Packet Authorization (SPA).

**Root Cause:**
Use of static shared secrets without rotation or challenge-response mechanisms.

**Attack Vector:**
1. Attacker performs packet capture (Wireshark) on the network.
2. User authenticates.
3. Attacker sees the static string in the payload.
4. Attacker reuses the string to authenticate from their own machine.

**Technical Impact:**
Authentication Bypass.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (Cleartext on wire).
* **Business Impact:** Total System Compromise.
* **Risk:** Critical.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Capture UDP traffic on v2.0.
2. Observe cleartext password string.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Replaced static passwords with **Time-based One-Time Passwords (TOTP)** in v3.0, and subsequently with **Noise Protocol (Curve25519)** in v4.0. Credentials are now ephemeral or mathematically proven, never sent as static plaintext.

## 6. Classification & References

* **Category:** Broken Authentication
* **CWE ID:** CWE-287 (Improper Authentication)