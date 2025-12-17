# Vulnerability Report Template

### [VULN-007] Weak Key Derivation (SHA256)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `4.8 (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N)`
* **Affected Component:** `Crypto (src/crypto.rs)`
* **Affected Versions:** `v4.0.0 - v5.1.0`
* **Patched Version:** `v5.2.0`
* **Date Found:** `2025-12-16`
* **Date Fixed:** `2025-12-16`

## 2. Description

**Summary:**
The master key (password) used to encrypt the server's private key was processed using a single iteration of SHA256. This is computationally cheap and vulnerable to GPU-based brute-force attacks if the config file is stolen.

**Root Cause:**
Use of a fast hashing algorithm (SHA256) instead of a Key Derivation Function (KDF) for password hashing.

**Technical Impact:**
If an attacker gains access to `GhostPort.toml` (e.g., via LFI or backup leak), they can crack the master password rapidly.

## 3. Business Impact & Risk Factors

* **Likelihood:** Low (Requires file access).
* **Business Impact:** Compromise of master key allowing decryption of private keys.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Generate a key with a weak password.
2. Extract the encrypted blob.
3. Use `hashcat` to brute-force SHA256. Observe high crack rates (Billions/sec).

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Upgraded the KDF to **Argon2id** (v19) with random salts. This makes brute-force attacks computationally infeasible on modern hardware.

### Verification

* **Method:** Integration Test (`tests/integration.rs`).
* **Verified By:** Automated Suite on 2025-12-16.

## 6. Classification & References

* **Category:** Cryptographic Failure
* **CWE ID:** CWE-916 (Use of Password Hash with Insufficient Computational Effort)