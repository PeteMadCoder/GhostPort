# Vulnerability Report Template

### [VULN-013] Missing Role-Based Access Control (BAC)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)`
* **Affected Component:** `Router`
* **Affected Versions:** `v1.0.0 - v2.1.0`
* **Patched Version:** `v3.0.0`
* **Date Found:** `2025-12-12`
* **Date Fixed:** `2025-12-13`

## 2. Description

**Summary:**
Prior to v3.0, GhostPort operated on a binary trust model: a user was either "Authenticated" or "Not". Once authenticated, a user could access *any* configured route, including sensitive admin panels intended only for super-users.

**Root Cause:**
Lack of authorization granularity (Vertical Privilege Escalation).

**Attack Vector:**
1. A developer with valid credentials logs in.
2. The developer requests `/admin/delete-database`.
3. The server permits the request because the developer is "Authenticated".

**Technical Impact:**
Unauthorized access to sensitive functions by lower-privileged valid users.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (for internal users).
* **Business Impact:** Privilege Escalation.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Login as standard user.
2. Access `/admin`.
3. Verify access granted.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented **RBAC (Role-Based Access Control)** in v3.0. Configuration now supports `allowed_roles` per route. Example: `/admin` now explicitly requires the `superadmin` role, denying access to generic `dev` users.

## 6. Classification & References

* **Category:** Broken Access Control
* **CWE ID:** CWE-269 (Improper Privilege Management)