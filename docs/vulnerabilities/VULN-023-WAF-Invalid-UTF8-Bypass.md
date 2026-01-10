# Vulnerability Report Template

### [VULN-023] WAF Bypass via Invalid UTF-8

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N)`
* **Affected Component:** `Proxy (src/proxy.rs)`
* **Affected Versions:** `< 5.3.4`
* **Patched Version:** `5.3.4`
* **Date Found:** `2026-01-09`
* **Date Fixed:** `2026-01-09`

## 2. Description

**Summary:**
The proxy component used `String::from_utf8_lossy` to convert raw HTTP header bytes to strings. This function replaces invalid UTF-8 bytes with the replacement character (U+FFFD), allowing attackers to bypass WAF protections by inserting invalid bytes into malicious payloads. For example, an attacker could send `SELE\xFFCT` which would become `SELE?CT` after lossy conversion, bypassing SQL injection filters that look for `SELECT`.

**Root Cause:**
Using `String::from_utf8_lossy` instead of strict UTF-8 validation allowed invalid byte sequences to be converted to valid strings with replacement characters, potentially bypassing pattern-matching security controls.

**Attack Vector:**
1.  **Configuration:** GhostPort server with WAF enabled
2.  **Attack:** Attacker sends HTTP request with invalid UTF-8 bytes in the path or headers (e.g., `GET /SELE\xFFCT HTTP/1.1`)
3.  **Vulnerable Logic:**
    *   Proxy processes headers using `String::from_utf8_lossy`
    *   Invalid bytes replaced with replacement character
    *   WAF analysis operates on sanitized string (`SELE?CT`)
    *   Malicious payload bypasses detection
4.  **Result:** WAF bypass allowing malicious requests to reach backend

**Technical Impact:**
WAF bypass allowing malicious requests to reach backend services.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium (Requires knowledge of WAF rules).
* **Business Impact:** Potential bypass of security controls allowing malicious requests to reach backend.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

**Steps to Reproduce:**
1.  **Setup:** Configure GhostPort with SQL injection detection rules in WAF
2.  **Attack:** Send request with invalid UTF-8: `GET /SELE\xFFCT HTTP/1.1`
3.  **Observation (Vulnerable):** WAF sees `SELE?CT`, bypasses filter, request reaches backend
4.  **Observation (Fixed):** GhostPort now rejects requests with invalid UTF-8 bytes, preventing bypass

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Replaced `String::from_utf8_lossy` with strict `String::from_utf8` validation. Requests with invalid UTF-8 bytes are now rejected with a connection close and IP strike.

### Verification

* **Method:** Code Audit and Unit Tests.
* **Verified By:** Code review and test execution on 2026-01-09.

## 6. Classification & References

* **Category:** Input Validation / WAF Bypass
* **CWE ID:** CWE-178 (Improper Handling of Case Sensitivity) and CWE-180 (Incorrect Behavior Order: Validate Before Canonicalize)