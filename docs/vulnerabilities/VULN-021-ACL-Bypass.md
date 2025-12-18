# Vulnerability Report Template

### [VULN-021] ACL Bypass via URL Encoding

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Critical`
* **CVSS Score:** `8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)`
* **Affected Component:** `Router (src/router.rs, src/proxy.rs)`
* **Affected Versions:** `< v5.3.3`
* **Patched Version:** `v5.3.3`
* **Date Found:** `2025-12-18`
* **Date Fixed:** `2025-12-18`

## 2. Description

**Summary:**
The routing logic performed access control checks on the raw, encoded URL path. An attacker could bypass path-based restrictions (ACLs) by URL-encoding characters in the path. For example, if access to `/admin` was restricted, an attacker could request `/%61dmin`. The router would fail to match the `/admin` rule and fall back to a less restrictive rule (e.g., `/` which allows all authenticated users), effectively granting unauthorized access to the protected resource.

**Root Cause:**
Failure to canonicalize (URL-decode) the path before passing it to the `match_route` function.

**Attack Vector:**
1.  **Configuration:**
    *   `/admin` -> Requires `superadmin`.
    *   `/` -> Requires `user`.
2.  **Attack:** Authenticated attacker (role: `user`) requests `GET /%61dmin`.
3.  **Vulnerable Logic:**
    *   Router checks: `/%61dmin` starts with `/admin`? -> **False**.
    *   Router checks: `/%61dmin` starts with `/`? -> **True**.
    *   Rule `/` matched. Access Granted.
4.  **Backend:** Receives `/%61dmin`, decodes it to `/admin`, and serves the admin panel.

**Technical Impact:**
Complete bypass of Role-Based Access Control (RBAC) for specific routes.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (Trivial to execute).
* **Business Impact:** Unauthorized access to sensitive administrative interfaces or data.
* **Risk:** Critical.

## 4. Proof of Concept (PoC)

**Steps to Reproduce:**
1.  **Setup:** Configure GhostPort with a restricted `/admin` route and an open `/` route.
2.  **Attack:** Send a request to `GET /%61dmin`.
3.  **Observation (Vulnerable):** Request is allowed.
4.  **Observation (Fixed):** GhostPort decodes `/%61dmin` to `/admin`, matches the `/admin` rule, checks for `superadmin` role, and denies access (RBAC DENIED).

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented recursive URL decoding in `src/proxy.rs` before routing decisions are made. The router now decides based on the **canonical** path (e.g., `/admin`) regardless of how it was encoded in the request.

### Verification

* **Method:** Code Audit.
* **Verified By:** Security Audit on 2025-12-18.

## 6. Classification & References

* **Category:** Broken Access Control
* **CWE ID:** CWE-177 (Improper Handling of URL Encoding (Hex Encoding))
