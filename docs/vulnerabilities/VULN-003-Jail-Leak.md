# Vulnerability Report Template

### [VULN-003] Jail Memory Leak

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)`
* **Affected Component:** `Jail (src/jail.rs)`
* **Affected Versions:** `v2.1.0 - v5.2.0`
* **Patched Version:** `v5.3.0`
* **Date Found:** `2025-12-17`
* **Date Fixed:** `2025-12-17`

## 2. Description

**Summary:**
The IP Banning system (`Jail`) retains banned IP addresses in memory even after the ban duration has expired.

**Root Cause:**
The `check_ip()` function checked for expiration to allow access but did not remove the expired entry from the `banned_ips` HashMap.

**Attack Vector:**
Passive accumulation over time. No specific active attack is needed, but an attacker rotating IPs could accelerate the leak.

**Technical Impact:**
Slow memory growth over months of operation, eventually leading to increased memory footprint or OOM.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (Natural occurrence over time).
* **Business Impact:** increased operational costs (RAM), potential instability after long uptimes.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Set `ban_duration` to 1 second in config.
2. Trigger a ban for `127.0.0.1`.
3. Wait 2 seconds.
4. Trigger a ban for `127.0.0.2`.
5. Inspect memory or internal state (debugger). The entry for `127.0.0.1` remains in the HashMap despite being expired.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Added a `cleanup()` method to `Jail` and integrated it into the `start_housekeeper` task to remove expired bans every 60 seconds.

### Verification

* **Method:** Unit Test (`tests/jail_test.rs`).
* **Verified By:** Automated Suite on 2025-12-17.

## 6. Classification & References

* **Category:** Resource Management
* **CWE ID:** CWE-772 (Missing Release of Resource after Effective Lifetime)