# Vulnerability Report Template

### [VULN-006] Fail-Open Watchdog Configuration

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Critical`
* **CVSS Score:** `9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)`
* **Affected Component:** `Watchdog Script (scripts/watchdog.sh)`
* **Affected Versions:** `v5.0.0 - v5.1.0`
* **Patched Version:** `v5.2.0`
* **Date Found:** `2025-12-16`
* **Date Fixed:** `2025-12-16`

## 2. Description

**Summary:**
The watchdog script was designed to open SSH Port 22 to the public internet if the GhostPort binary crashed more than 3 times.

**Root Cause:**
Insecure "Fail-Safe" design logic intended to prevent admin lockout.

**Attack Vector:**
An attacker sends malformed packets to crash the GhostPort binary (e.g., via a fuzzing attack). Once the service crashes 3 times, the firewall rules are flushed, exposing the underlying SSH service to brute-force attacks.

**Technical Impact:**
Complete loss of "Stealth" protection and exposure of the core management port.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium (Requires ability to crash the server).
* **Business Impact:** Exposure of SSH to public internet, potentially leading to system compromise.
* **Risk:** Critical.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Run `watchdog.sh`.
2. Kill the ghostport process manually 3 times (`killall -9 ghostport`).
3. Observe `watchdog.sh` executing `ufw allow 22`.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Removed the `emergency_mode` function. The system now "Fails Closed". If the binary crashes, no ports are opened.

### Verification

* **Method:** Code Review.
* **Verified By:** Automated Suite on 2025-12-16.

## 6. Classification & References

* **Category:** Security Misconfiguration
* **CWE ID:** CWE-636 (Not Failing Securely)