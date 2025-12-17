# Vulnerability Report Template

### [VULN-004] Panic Risk (Lock Poisoning)

## 1. Executive Summary / Metadata

* **Status:** `Fixed`
* **Severity:** `Medium`
* **CVSS Score:** `5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)`
* **Affected Component:** `Core Locks (src/main.rs, src/proxy.rs)`
* **Affected Versions:** `v5.0.0 - v5.2.0`
* **Patched Version:** `v5.3.0`
* **Date Found:** `2025-12-17`
* **Date Fixed:** `2025-12-17`

## 2. Description

**Summary:**
The application used `.unwrap()` on `Mutex::lock()` results. If a thread panic occurred while holding a lock (e.g., due to an unrelated bug), the lock would become "poisoned," causing all subsequent requests to panic and crash the server.

**Root Cause:**
Unsafe error handling of `std::sync::Mutex`.

**Attack Vector:**
Attacker triggers a specific edge case (bug) that causes a panic inside a critical section (e.g., inside the Token Store lock).

**Technical Impact:**
A single recoverable error in one thread could cascade into a full application crash due to lock poisoning.

## 3. Business Impact & Risk Factors

* **Likelihood:** Low (Requires triggering another bug first).
* **Business Impact:** Reduced reliability and resilience.
* **Risk:** Medium.

## 4. Proof of Concept (PoC)

* **Steps to Reproduce:**
1. Insert a manual `panic!()` inside the `session_store` lock scope in the code.
2. Compile and run.
3. Trigger the panic with a request.
4. Send a *second* request.
5. Observe that the second request also panics with "PoisonError", crashing the handler.

## 5. Remediation & Status Tracking

### Solution / Controls

* **Fix Implemented:** Replaced `.unwrap()` with `if let Ok(guard) = lock()` in background tasks (Housekeeper) to prevent propagation of poisoning errors.

### Verification

* **Method:** Code Review.
* **Verified By:** Automated Suite on 2025-12-17.

## 6. Classification & References

* **Category:** Error Handling
* **CWE ID:** CWE-248 (Uncaught Exception)