# Vulnerability Report Template

### [VULN-008] Missing Certificate Pinning (MITM)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `High`
* **CVSS Score:** `7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)`
* **Affected Component:** `QUIC Client (src/client.rs)`
* **Affected Versions:** `v5.0.0`
* **Patched Version:** `v5.1.0`
* **Date Found:** `2025-12-15`
* **Date Fixed:** `2025-12-16`

## 2. Description

**Summary:**
The v5.0 client did not verify the server's TLS certificate. Since GhostPort uses self-signed certificates, the client blindly accepted any certificate, making it vulnerable to active Man-in-the-Middle (MITM) attacks.

**Root Cause:**
Default `rustls` configuration disabled verification for self-signed certs without implementing an alternative check.

**Attack Vector:**
An attacker on the path (e.g., compromised router) intercepts the QUIC handshake and presents their own certificate. The client accepts it and sends data through the attacker.

**Technical Impact:**
Loss of confidentiality and integrity of the tunneled traffic.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium (Requires network positioning).
* **Business Impact:** Total compromise of data in transit.
* **Risk:** High.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Setup a standard GhostPort server.
2. Setup a malicious proxy that terminates TLS with its own cert.
3. Point client to malicious proxy.
4. Client v5.0 connects successfully.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented **Certificate Pinning**. The client now requires the `--server-cert-hash` flag. It calculates the SHA256 fingerprint of the received certificate and terminates the connection if it does not match the expected hash.

### Verification

* **Method:** E2E Test (`test_e2e_bad_cert_hash`).
* **Verified By:** Automated Suite on 2025-12-16.

## 6. Classification & References

* **Category:** Cryptographic Failure
* **CWE ID:** CWE-295 (Improper Certificate Validation)