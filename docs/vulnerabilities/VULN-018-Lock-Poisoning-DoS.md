# Vulnerability Report Template

### [VULN-018] Lock Poisoning Denial of Service

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)`
* **Affected Component:** `Core (src/jail.rs, src/proxy.rs, src/udp.rs)`
* **Affected Versions:** `< v5.3.1`
* **Patched Version:** `v5.3.1`
* **Date Found:** `2025-12-18`
* **Date Fixed:** `2025-12-18`

## 2. Description

**Summary:**
The application pervasively used `.unwrap()` on `std::sync::Mutex` and `RwLock`. If a thread panicked while holding a lock (e.g., due to an unrelated bug or resource exhaustion), the lock would become "poisoned". Subsequent threads attempting to access the lock would also panic upon unwrapping the `PoisonError`, leading to a cascading failure and total application crash.

**Root Cause:**
Unsafe error handling pattern: `lock().unwrap()`.

**Attack Vector:**
Difficult to trigger intentionally without a secondary bug that causes a panic while holding a lock. However, if such a condition exists, it turns a single thread crash into a full service DoS.

**Technical Impact:**
Complete application termination requiring a restart.

## 3. Business Impact & Risk Factors

* **Likelihood:** Low (Requires a precursor panic).
* **Business Impact:** Service unavailability.
* **Risk:** Medium (High Impact, Low Likelihood).

## 4. Proof of Concept (PoC)

1. Modify source code to force a panic inside a locked section of `Jail`.
2. Send a request that triggers that path.
3. Send a *second* request.
4. Observe the second request panics the entire server due to `PoisonError`.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Replaced all instances of `lock().unwrap()` with `match lock() { Ok(g) => g, Err(e) => ... }`. The application now logs the poisoning event and returns a safe "fail-closed" default (e.g., denying access) or an internal server error, allowing other threads to continue (if the lock allows recovery) or at least failing gracefully without crashing the process.

### Verification

* **Method:** Static Analysis.
* **Verified By:** AI Security Audit on 2025-12-18.

## 6. Classification & References

* **Category:** Denial of Service
* **CWE ID:** CWE-662 (Improper Synchronization)
