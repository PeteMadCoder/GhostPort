# Vulnerability Report Template

### [VULN-019] Connection Persistence Bypassing Jail (TOCTOU)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `5.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L)`
* **Affected Component:** `QUIC Proxy (src/proxy.rs)`
* **Affected Versions:** `< v5.3.2`
* **Patched Version:** `v5.3.2`
* **Date Found:** `2025-12-18`
* **Date Fixed:** `2025-12-18`

## 2. Description

**Summary:**
The IP Ban check was only performed upon accepting a new QUIC **connection**. However, QUIC supports multiple **streams** within a single connection. If an attacker's IP was banned (e.g., due to malicious activity on Stream 1), they could continue to open new streams on the *same* underlying connection, bypassing the ban for the duration of that connection.

**Root Cause:**
Missing `jail.check_ip()` call in the `handle_stream` function in `src/proxy.rs`. The check was only present in the outer `endpoint.accept()` loop.

**Attack Vector:**
1. Attacker establishes a valid QUIC connection.
2. Attacker sends a malicious request on Stream 1 (e.g., SQL Injection), triggering the WAF.
3. The Jail bans the IP.
4. Attacker keeps the QUIC connection open and opens Stream 2, Stream 3, etc.
5. The server accepts these new streams because the IP check was not re-evaluated for existing connections.

**Technical Impact:**
An attacker can continue to probe or exploit the system for minutes (or until the connection times out) even after being "banned", reducing the immediate effectiveness of the active defense system.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium (Requires the attacker to use a custom client that maintains persistent connections; standard browsers might close connections on some errors, but scripts won't).
* **Business Impact:** Reduced efficacy of the WAF/IPS; delayed mitigation of active attacks.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

**Steps to Reproduce:**
1.  **Setup:** Run GhostPort locally.
2.  **Attack:** Use a custom QUIC client (or modified `client.rs`).
3.  **Step 1:** Establish connection.
4.  **Step 2:** Send `GET /union+select` (triggers WAF strike -> Ban).
5.  **Step 3:** Immediately send `GET /secret_data` on a **new stream** within the **same connection**.
6.  **Observation (Vulnerable):** The server processes the second request.
7.  **Observation (Fixed):** The server immediately closes the second stream (or the connection) as `jail.check_ip` returns `false`.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Added an explicit `jail.check_ip(addr.ip())` check at the very start of the `handle_stream` function in `src/proxy.rs`. This ensures every single request (stream) is validated against the current Jail state, regardless of when the connection was established.

### Verification

* **Method:** Code Audit & Logic Verification.
* **Verified By:** Security Audit on 2025-12-18.

## 6. Classification & References

* **Category:** Time-of-Check Time-of-Use (TOCTOU)
* **CWE ID:** CWE-367 (Time-of-check Time-of-use Race Condition)