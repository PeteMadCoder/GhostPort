# Vulnerability Report Template

### [VULN-010] Plaintext Storage of Secrets

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `High`
* **CVSS Score:** `6.5 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)`
* **Affected Component:** `Configuration (GhostPort.toml)`
* **Affected Versions:** `v1.0.0 - v3.0.0`
* **Patched Version:** `v4.0.0`
* **Date Found:** `2025-12-13`
* **Date Fixed:** `2025-12-14`

## 2. Description

**Summary:**
Previous versions of GhostPort stored sensitive configuration data, including the server's private key and authentication secrets, in plaintext within the `GhostPort.toml` file.

**Root Cause:**
Lack of encryption-at-rest mechanism for configuration artifacts.

**Attack Vector:**
1. Attacker gains Local File Inclusion (LFI) or read access to the server via a backup leak.
2. Attacker reads `GhostPort.toml`.
3. Attacker extracts the `private_key` and can impersonate the server or decrypt past traffic (if non-PFS).

**Technical Impact:**
Complete compromise of the server's identity and confidentiality of past sessions.

## 3. Business Impact & Risk Factors

* **Likelihood:** Low (Requires FS access).
* **Business Impact:** Identity theft of the server.
* **Risk:** High.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Install v3.0.
2. Open `GhostPort.toml`.
3. Observe plaintext private key.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented **Encrypted Configuration** in v4.0. Secrets are now stored as Base64-encoded encrypted blobs (`encrypted_private_key`). The decryption key is supplied via an environment variable (`GHOSTPORT_MASTER_KEY`) at runtime, ensuring secrets are never written to disk in plaintext.

### Verification

* **Method:** Manual Review.
* **Verified By:** Developer on 2025-12-14.

## 6. Classification & References

* **Category:** Cryptographic Failure
* **CWE ID:** CWE-312 (Cleartext Storage of Sensitive Information)