# Vulnerability Report Template

### [VULN-016] Unrestricted Network Access (Public Exposure)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Critical`
* **CVSS Score:** `9.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)`
* **Affected Component:** `TCP Listener`
* **Affected Versions:** `v1.0.0 (Prototype)`
* **Patched Version:** `v2.0.0`
* **Date Found:** `2025-12-10`
* **Date Fixed:** `2025-12-11`

## 2. Description

**Summary:**
The prototype version of GhostPort (v1.0) acted as a standard reverse proxy. It listened on a public TCP port and forwarded traffic to the backend without any pre-authentication or "Knock".

**Root Cause:**
Design choice (Proof of Concept) lacking Zero-Trust principles.

**Attack Vector:**
1. Attacker scans internet.
2. Attacker finds open port 80/443.
3. Attacker exploits vulnerability in the *backend* application (e.g., Wordpress) directly through the proxy.

**Technical Impact:**
Full exposure of the backend attack surface to the public internet.

## 3. Business Impact & Risk Factors

* **Likelihood:** High.
* **Business Impact:** Full Exposure.
* **Risk:** Critical.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Run v1.0.
2. `curl http://server-ip`.
3. Request succeeds without auth.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented **Single Packet Authorization (SPA)** in v2.0. The server now drops all TCP packets unless a specific UDP packet is received first, effectively hiding the service from port scanners (Shodan/Censys).

## 6. Classification & References

* **Category:** Security Misconfiguration
* **CWE ID:** CWE-284 (Improper Access Control)