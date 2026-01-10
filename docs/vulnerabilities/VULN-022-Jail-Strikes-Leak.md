# Vulnerability Report Template

### [VULN-022] Memory Leak in Jail Strikes Map

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `High`
* **CVSS Score:** `7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)`
* **Affected Component:** `Jail (src/jail.rs)`
* **Affected Versions:** `< 5.3.4`
* **Patched Version:** `5.3.4`
* **Date Found:** `2026-01-09`
* **Date Fixed:** `2026-01-09`

## 2. Description

**Summary:**
The Jail component in GhostPort maintains a `strikes` map to track the number of violations per IP address. While the cleanup function properly removes expired bans from the `banned_ips` map, it never cleans the `strikes` map. This creates a memory leak vulnerability where an attacker can cause unbounded memory growth by sending invalid packets from many different IP addresses.

**Root Cause:**
The `cleanup()` method in `src/jail.rs` only removes expired bans from the `banned_ips` map but does not clean up old entries from the `strikes` map. The `strikes` map was implemented as `HashMap<IpAddr, u32>` which only tracks the count but not when the last strike occurred, making it impossible to determine which entries are stale.

**Attack Vector:**
1.  **Configuration:** GhostPort server running with Jail enabled
2.  **Attack:** Attacker sends 1 bad packet from 1,000,000 different IP addresses (e.g., spoofed UDP packets, or using a botnet)
3.  **Vulnerable Logic:**
    *   Each invalid request increments the strike counter for that IP address
    *   The `strikes` map grows indefinitely as entries are never cleaned up
    *   Eventually, system runs out of memory (OOM) causing DoS
4.  **Result:** System crashes due to memory exhaustion, making protected services unavailable

**Technical Impact:**
Memory exhaustion leading to Denial of Service through unbounded memory growth in the strikes map.

## 3. Business Impact & Risk Factors

* **Likelihood:** High (Easy to execute with botnet or IP spoofing).
* **Business Impact:** Service unavailability due to memory exhaustion and system crashes.
* **Risk:** High.

## 4. Proof of Concept (PoC)

**Steps to Reproduce:**
1.  **Setup:** Configure and run GhostPort server with default Jail settings
2.  **Attack:** Send invalid packets from many different IP addresses to trigger strikes
3.  **Observation (Vulnerable):** `strikes` map grows indefinitely without cleanup
4.  **Observation (Fixed):** GhostPort now tracks timestamps for strikes and cleans up old entries during housekeeping, preventing unbounded growth

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Modified the `strikes` map to track both the count and the timestamp of the last strike: `HashMap<IpAddr, (u32, Instant)>`. Updated the `cleanup()` method to also remove strike entries that are older than a configurable threshold (1 hour).

### Verification

* **Method:** Code Audit and Unit Tests.
* **Verified By:** Code review and test execution on 2026-01-09.

## 6. Classification & References

* **Category:** Memory Leak / Denial of Service
* **CWE ID:** CWE-770 (Allocation of Resources Without Limits or Throttling)