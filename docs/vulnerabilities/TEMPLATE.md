# Vulnerability Report Template

### [VULN-ID] Vulnerability Name

> *Example: [AUTH-01] Broken Object Level Authorization on API Endpoint*

## 1. Executive Summary / Metadata

* **Status:** `[Open / In Progress / Fixed / Won't Fix / False Positive]`
* **Severity:** `[Critical / High / Medium / Low / Info]`
* **CVSS Score:** `[e.g., 7.5 (CVSS v3.1)]`
* **Affected Component:** `[e.g., User Login Module, Payment API, database-x]`
* **Affected Versions:** `[e.g., v1.0.0 - v1.2.4]`
* **Patched Version:** `[e.g., v1.2.5]` *(Leave blank if open)*
* **Date Found:** `[YYYY-MM-DD]`
* **Date Fixed:** `[YYYY-MM-DD]`

## 2. Description

*A vulnerability is a weakness in an application that enables an attack to succeed.*

**Summary:**
[Start with a one-sentence high-level description of the vulnerability. Example: The application fails to validate user input on the comment section, allowing for the injection of arbitrary JavaScript.]

**Root Cause:**
[What is the specific coding error or configuration issue? Example: The `user_input` variable is passed directly to the DOM without sanitization.]

**Attack Vector:**
[How does an attacker exploit this? Example: An attacker sends a crafted URL containing a malicious script to a victim.]

**Technical Impact:**
[What technically happens? Example: The attacker's script executes in the victim's browser context, allowing access to session cookies and local storage.]

## 3. Business Impact & Risk Factors

*Talk about the factors that make this exploit likely and the real-world damage.*

* **Likelihood:** [Low/Medium/High - How hard is it to exploit?]
* **Business Impact:** [Example: Loss of customer trust, regulatory fines (GDPR/CCPA), financial theft, unauthorized access to proprietary data.]
* **Risk:** [Combine likelihood and impact. Example: High risk because the exploit is public and the data is sensitive.]

## 4. Proof of Concept (PoC) / Examples

*Provide step-by-step instructions to reproduce the issue.*

**Example 1: [Short Name]**

* **Description:** [Brief description of this specific test case]
* **Steps to Reproduce:**
1. Navigate to `https://example.com/login`
2. Enter payload `' OR 1=1 --` into the username field.
3. Observe that the application logs you in as Administrator.


* **Evidence:**
> [Insert Screenshot, Logs, or Code Snippet Here]



## 5. Remediation & Status Tracking

### Current Status

[Provide a narrative of the current state. Example: The vulnerability has been identified in the development environment. A patch has been created but is currently pending QA review.]

### Solution / Controls

* **Fix Implemented:** [Describe the actual fix. Example: Implemented `DOMPurify` library to sanitize all inputs before rendering.]
* **Mitigation:** [If a full fix isn't possible, what stops the bleeding? Example: WAF rules added to block `<script>` tags.]

### Verification

* **Method:** [How did you verify the fix? Example: Retested with the original PoC payload.]
* **Verified By:** [Name of tester] on [Date]

## 6. Classification & References

* **Category:** [e.g., Injection, Broken Access Control, XSS]
* **CWE ID:** [e.g., CWE-79]
* **CAPEC ID:** [e.g., CAPEC-63]

**References:**

* [Link to internal Jira Ticket]
* [Link to Commit/PR]
* [Link to OWASP/CWE Article]
