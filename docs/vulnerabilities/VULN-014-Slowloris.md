# Vulnerability Report Template

### [VULN-014] Slow HTTP Header DoS (Slowloris)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)`
* **Affected Component:** `TCP Proxy`
* **Affected Versions:** `v1.0.0 - v2.0.0`
* **Patched Version:** `v2.1.0`
* **Date Found:** `2025-12-11`
* **Date Fixed:** `2025-12-12`

## 2. Description

**Summary:**
The server allowed clients to send HTTP headers byte-by-byte with infinite pauses between bytes. This allowed a single attacker to tie up all available connection slots (threads/tasks) by holding them open indefinitely without completing a request.

**Root Cause:**
Missing read timeouts during the header parsing phase.

**Attack Vector:**
1. Attacker opens 1000 connections.
2. Attacker sends `GET / HTTP/1.1\r\n`.
3. Attacker waits 10 seconds, sends `X-Header: 1`, waits 10 seconds...
4. Server keeps connections open, rejecting new legitimate users.

**Technical Impact:**
Denial of Service (DoS).

## 3. Business Impact & Risk Factors

* **Likelihood:** High.
* **Business Impact:** Service Unavailability.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Run `slowloris.py` against server.
2. Observe successful connection holding.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Implemented a strict **5-second timeout** for the entire header reading process in v2.1. If the full request headers are not received within 5 seconds, the connection is forcibly dropped.

## 6. Classification & References

* **Category:** Denial of Service
* **CWE ID:** CWE-400 (Uncontrolled Resource Consumption)