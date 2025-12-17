# Vulnerability Report Template

### [VULN-015] WAF Bypass (Double Encoding)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)`
* **Affected Component:** `WAF (Web Application Firewall)`
* **Affected Versions:** `v2.0.0`
* **Patched Version:** `v2.1.0`
* **Date Found:** `2025-12-11`
* **Date Fixed:** `2025-12-12`

## 2. Description

**Summary:**
The initial WAF implementation checked for attack signatures (e.g., `<script>`, `SELECT`) in the raw request path. It failed to decode URL-encoded characters before inspection, allowing attackers to bypass rules.

**Root Cause:**
WAF inspected `raw_path` instead of `decoded_path`.

**Attack Vector:**
1. WAF blocks `/admin`.
2. Attacker requests `/%61dmin` (URL-encoded 'a').
3. WAF sees `/%61dmin`, which doesn't match `/admin`.
4. Backend receives request, decodes it to `/admin`, and processes it.

**Technical Impact:**
Bypass of security controls, potentially leading to XSS or SQL Injection execution on the backend.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium.
* **Business Impact:** Security Control Bypass.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Configure WAF to block `alert`.
2. Send request with `%61lert`.
3. Verify WAF allows it.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented **Canonicalization** in v2.1. The WAF now fully URL-decodes the path (up to 2 passes) before matching against attack signatures or routing rules.

## 6. Classification & References

* **Category:** Injection
* **CWE ID:** CWE-150 (Improper Neutralization of Escape, Meta, or Control Sequences)