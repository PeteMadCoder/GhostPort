# Vulnerability Report Template

### [VULN-020] WAF Bypass via Double URL Encoding

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)`
* **Affected Component:** `WAF Engine (src/waf.rs)`
* **Affected Versions:** `< v5.3.2`
* **Patched Version:** `v5.3.2`
* **Date Found:** `2025-12-18`
* **Date Fixed:** `2025-12-18`

## 2. Description

**Summary:**
The WAF engine decoded URL-encoded characters only once before applying signature detection (Regex). Attackers could bypass these signatures by "Double Encoding" malicious characters. For example, encoding `.` as `%2e` is standard, but encoding `%` as `%25` allows sending `%252e`, which decodes to `%2e` (safe to WAF), and then to `.` (harmful to backend).

**Root Cause:**
The `check_request` function in `src/waf.rs` called `urlencoding::decode` exactly once.

**Attack Vector:**
1.  Attacker wants to send `../etc/passwd` (Path Traversal).
2.  Standard WAF blocks `../`.
3.  Attacker encodes `.` as `%2e` -> `..` becomes `%2e%2e`. WAF decodes this to `..` and blocks it.
4.  Attacker **Double Encodes**: `%` becomes `%25`. Payload: `%252e%252e`.
5.  **Vulnerable WAF:** Decodes `%25` -> `%`. Result: `%2e%2e`. This does *not* match `..` regex. Request passes.
6.  **Backend:** Decodes `%2e%2e` -> `..`. Attack succeeds.

**Technical Impact:**
Complete bypass of the Web Application Firewall for Path Traversal, SQL Injection, and XSS attacks if the attacker obfuscates the payload.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (Double encoding is a standard evasion technique included in tools like OWASP ZAP and Burp Suite).
* **Business Impact:** Backend applications assumed to be protected by GhostPort are exposed to raw attacks.
* **Risk:** Medium (Depends on the vulnerability of the protected backend).

## 4. Proof of Concept (PoC)

**Steps to Reproduce:**
1.  **Setup:** Run GhostPort protecting a dummy backend.
2.  **Attack:** Send a request to `GET /%252e%252e/etc/passwd`.
3.  **Observation (Vulnerable):** WAF logs nothing. Request is forwarded.
4.  **Observation (Fixed):** WAF loop decodes `%252e%252e` -> `%2e%2e` -> `..`. Regex `\.\./` matches. Connection dropped and IP banned.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented a **Recursive Decoding Loop** in `src/waf.rs`. The WAF now repeatedly decodes the path (up to 5 iterations) until the string stabilizes (stops changing). This ensures the "Canonically Decoded" path is checked against the signatures.

### Verification

* **Method:** Code Audit.
* **Verified By:** Security Audit on 2025-12-18.

## 6. Classification & References

* **Category:** Input Validation / Evasion
* **CWE ID:** CWE-174 (Double Encoding)
* **CAPEC ID:** CAPEC-120 (Double Encoding)