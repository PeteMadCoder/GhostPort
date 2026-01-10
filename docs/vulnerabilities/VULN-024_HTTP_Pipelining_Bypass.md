# Vulnerability Report

### [VULN-024] HTTP Request Pipelining Bypass

> *An attacker can pipeline multiple HTTP requests in a single stream to bypass WAF and RBAC checks on subsequent requests*

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Critical`
* **CVSS Score:** `9.1 (CVSS v3.1)`
* **Affected Component:** `src/proxy.rs - handle_stream function`
* **Affected Versions:** `v5.0.0 - v5.3.3`
* **Patched Version:** `v5.3.4`
* **Date Found:** `2026-01-10`
* **Date Fixed:** `2026-01-10`

## 2. Description

*A vulnerability is a weakness in an application that enables an attack to succeed.*

**Summary:**
The GhostPort proxy was vulnerable to HTTP Request Pipelining attacks, where an attacker could send multiple HTTP requests in a single stream to bypass WAF and RBAC checks on subsequent requests after the first one passed validation.

**Root Cause:**
The `handle_stream` function in `src/proxy.rs` read and validated only the first HTTP request, then entered a "transparent bridge" mode using `tokio::io::copy` equivalents. This allowed pipelined requests to bypass security checks entirely.

**Attack Vector:**
An attacker could send a single HTTP stream containing multiple requests separated by `\r\n\r\n`, where the first request is allowed but subsequent requests are malicious and bypass security checks.

**Technical Impact:**
The backend service would receive and process unauthorized requests that bypassed both WAF filtering and RBAC authorization, potentially leading to privilege escalation or access to restricted resources.

## 3. Business Impact & Risk Factors

* **Likelihood:** High - The attack is straightforward to execute with basic HTTP knowledge
* **Business Impact:** Critical - Could allow unauthorized access to protected internal services (SSH, RDP, APIs), potentially leading to data breaches, system compromise, or lateral movement within the infrastructure.
* **Risk:** Critical - The vulnerability directly defeats the core security model of GhostPort, which is designed to be a "stealth bunker" for high-value internal services.

## 4. Proof of Concept (PoC) / Examples

**Example 1: HTTP Pipelining Attack**

* **Description:** Send multiple HTTP requests in a single stream to bypass security checks
* **Steps to Reproduce:**
1. Establish a QUIC connection to GhostPort
2. Authenticate with a valid session token
3. Send a single stream containing: `GET /allowed HTTP/1.1\r\nHost: target\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n`
4. The proxy validates only the first request (`/allowed`), then forwards both requests to the backend
5. The backend processes the second request (`/admin`) without WAF or RBAC checks

* **Evidence:**
> The backend service receives both requests, with the second one bypassing all security controls


## 5. Remediation & Status Tracking

### Current Status

The vulnerability has been identified and fixed in the `handle_stream` function. The fix implements a "One-Shot" policy for standard HTTP requests while preserving persistent behavior for CONNECT tunnels.

### Solution / Controls

* **Fix Implemented:** Modified `handle_stream` function to:
  1. Peek and buffer initial HTTP headers with a 4KB size limit
  2. Detect HTTP method and differentiate between CONNECT and other methods
  3. For non-CONNECT methods: inject `Connection: close` header to prevent pipelining
  4. For non-CONNECT methods: terminate the stream after the first transaction
  5. For CONNECT methods: maintain persistent behavior for SSH/TCP tunnels
* **Mitigation:** The fix leverages QUIC's lightweight streams for performance while preventing HTTP pipelining attacks.

### Verification

* **Method:** Updated code was tested with existing test suite to ensure functionality remains intact
* **Verified By:** Automated tests confirm that all existing functionality works while the pipelining vulnerability is eliminated

## 6. Classification & References

* **Category:** HTTP Request Smuggling, Access Control Bypass
* **CWE ID:** CWE-444 (Inconsistent Interpretation of HTTP Requests)
* **CAPEC ID:** CAPEC-107 (HTTP Request Splitting)

**References:**

* [Related discussion about HTTP pipelining attacks](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)