# Vulnerability Report Template

### [VULN-005] IP-Based Session Hijacking (NAT Issue)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Critical`
* **CVSS Score:** `8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)`
* **Affected Component:** `Authorization Logic (src/main.rs)`
* **Affected Versions:** `v2.0.0 - v5.1.0`
* **Patched Version:** `v5.2.0`
* **Date Found:** `2025-12-16`
* **Date Fixed:** `2025-12-16`

## 2. Description

**Summary:**
GhostPort authorized sessions based on the source IP address after a successful UDP knock. This created a race condition where any other user sharing the same public IP (e.g., behind a Corporate NAT or Cafe Wi-Fi) could access the open port without authentication.

**Root Cause:**
Trusting Layer 3 (IP Address) as an identity token.

**Attack Vector:**
1. Attacker joins the same Wi-Fi as the Admin.
2. Admin runs `ghostport connect`.
3. Attacker runs `nmap` against the Server IP and finds the port open (authorized for the shared IP).

**Technical Impact:**
Complete bypass of authentication for attackers co-located on the network.

## 3. Business Impact & Risk Factors

* **Likelihood:** Medium (Requires attacker to be on same NAT).
* **Business Impact:** Unauthorized access to internal systems.
* **Risk:** High.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Setup a Server.
2. Put Client A (Admin) and Client B (Attacker) behind the same NAT router.
3. Client A performs the UDP Knock.
4. Client B immediately attempts to connect to the Server's QUIC port.
5. In vulnerable versions, Client B connects successfully.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Replaced IP Whitelisting with **Session Tokens**. The UDP knock now exchanges a random 32-byte token. The QUIC connection must present this token to open a stream. This decouples authorization from the IP address.

### Verification

* **Method:** E2E Test (Unauth Access Test).
* **Verified By:** Automated Suite on 2025-12-16.

## 6. Classification & References

* **Category:** Broken Access Control
* **CWE ID:** CWE-290 (Authentication Bypass by Spoofing)