# Web Application Security Checklist
*Based on OWASP Top 10 - 2021*

**Usage:**  
- Tick each item when implementing new features, code review, PRs, or audits.  
- P0 = Critical, P1 = High, P2 = Medium, P3 = Low.  
- Run all scans / tests only in **dev/staging environment** unless explicitly allowed.

---

## A01 — Broken Access Control
**Goal:** Prevent users from accessing resources/functions they are not authorized to.  

**Checklist**
- [ ] Server-side access checks implemented on all endpoints (P0)  
- [ ] No client-side-only checks for security (P0)  
- [ ] Object references (IDs) are secured, not guessable (P1)  
- [ ] Roles/permissions not trusted from client input (P0)  
- [ ] Rate-limit sensitive APIs (change password, role updates) (P1)  

**Testing**
- [ ] Test horizontal & vertical privilege escalation (P0)  
- [ ] Test IDOR by modifying IDs in URLs/JSON (P0)  

---

## A02 — Cryptographic Failures
**Goal:** Properly protect sensitive data at rest and in transit.  

**Checklist**
- [ ] TLS 1.2+ enforced; disable TLS 1.0/1.1 (P0)  
- [ ] Passwords hashed with bcrypt / Argon2 / scrypt (P0)  
- [ ] Sensitive data encrypted at rest (AES-GCM) (P1)  
- [ ] Secrets managed securely (env vars, vaults) (P0)  
- [ ] Weak algorithms (MD5/SHA1) not used (P0)  
- [ ] Key rotation and audit policies in place (P2)  

**Testing**
- [ ] Check security headers: `Strict-Transport-Security`, `Content-Security-Policy` (P1)  
- [ ] Verify no secrets in logs/config (P0)  

---

## A03 — Injection
**Goal:** Prevent SQL, NoSQL, command, LDAP, OS injection.  

**Checklist**
- [ ] Use prepared statements / parameterized queries (P0)  
- [ ] Validate & encode input according to context (P0)  
- [ ] Avoid concatenating user input into commands/queries (P0)  
- [ ] Use ORM query builder safely (P1)  

**Testing**
- [ ] Inject payloads into forms, params, headers (P0)  
- [ ] Use SAST (semgrep, Bandit) to detect unsafe patterns (P0)  

---

## A04 — Insecure Design
**Goal:** Ensure security is integrated into architecture.  

**Checklist**
- [ ] Threat modeling (STRIDE/PASTA) done for new features (P0)  
- [ ] Identify assets, trust boundaries, attack surfaces (P0)  
- [ ] Security requirements defined before dev (P0)  
- [ ] Apply secure design patterns (least privilege, defense in depth) (P0)  

**Testing**
- [ ] Review architecture diagrams for gaps (P0)  

---

## A05 — Security Misconfiguration
**Goal:** Prevent insecure defaults and misconfigurations.  

**Checklist**
- [ ] Disable debug mode in production (P0)  
- [ ] Change default accounts/passwords (P0)  
- [ ] Harden web server (disable directory listing, add secure headers) (P1)  
- [ ] CORS properly restricted, no `*` with credentials (P0)  
- [ ] Configs & secrets not in code (P0)  
- [ ] Keep dependencies & OS patched (P1)  

**Testing**
- [ ] Run scanner (staging only) (P2)  
- [ ] Apply CIS hardening checks (P2)  

---

## A06 — Vulnerable and Outdated Components
**Goal:** Avoid using libraries with known vulnerabilities.  

**Checklist**
- [ ] Dependency scanning in CI (Dependabot, npm audit, pip-audit) (P0)  
- [ ] Patch critical CVEs promptly (P0)  
- [ ] Lockfile & reproducible builds (P1)  
- [ ] Remove unused dependencies (P1)  

**Testing**
- [ ] Triage CVEs by exploitability & impact (P0)  

---

## A07 — Identification and Authentication Failures
**Goal:** Protect authentication & session management.  

**Checklist**
- [ ] Strong password policy + rate limiting + lockout (P1)  
- [ ] Secure session cookies (`HttpOnly`, `Secure`, `SameSite`) (P0)  
- [ ] JWT: validate signature, check `alg`, `exp`, `iat`, implement revocation (P0)  
- [ ] MFA for admin/sensitive accounts (P1)  
- [ ] Short-lived tokens + refresh token rotation (P1)  

**Testing**
- [ ] Test session fixation, logout, token reuse (P0)  
- [ ] Brute-force login test with rate-limits (P0)  

---

## A08 — Software and Data Integrity Failures
**Goal:** Ensure code/artifacts are not tampered with.  

**Checklist**
- [ ] Sign artifacts; pin package versions (P1)  
- [ ] CI pipeline access restricted & reviewed (P1)  
- [ ] Use provenance/SBOM for artifacts (P2)  
- [ ] Validate 3rd-party CI/CD actions (P1)  

**Testing**
- [ ] Review release & deployment process (P1)  

---

## A09 — Security Logging and Monitoring Failures
**Goal:** Ensure attacks are detected promptly.  

**Checklist**
- [ ] Log auth attempts, privilege changes, errors (P0)  
- [ ] Centralize logs (ELK, Splunk, Datadog) (P1)  
- [ ] Retention policy + alerts on anomalies (P0)  
- [ ] Logs protected from tampering (P1)  
- [ ] Test alerts trigger correctly (P0)  

---

## A10 — Server-Side Request Forgery (SSRF)
**Goal:** Prevent server from making arbitrary requests controlled by attacker.  

**Checklist**
- [ ] Validate/sanitize user-controlled URLs (P0)  
- [ ] Block requests to private IP ranges (P0)  
- [ ] Network-level egress control / allowlist (P0)  
- [ ] Limit response size and set timeouts (P1)  

**Testing**
- [ ] Test SSRF payloads to internal endpoints / cloud metadata (P0)  

---

## PR / Release Checklist (Quick)
- [ ] Auth & Access checked server-side  
- [ ] Input validation & encoding done  
- [ ] Secrets not in code/config  
- [ ] Dependencies scanned/updated  
- [ ] Sensitive info not in logs  
- [ ] Secure headers / CORS checked  
- [ ] Unit/integration tests for auth & critical flows  
- [ ] Threat model updated if data flow/trust boundaries changed  

---

## Recommended Tools
- **SAST:** `semgrep`, `Bandit` (Python)  
- **Dependency scanning:** `npm audit`, `pip-audit`, OWASP Dependency-Check  
- **Secret scanning:** `trufflehog`, `git-secrets`  
- **DAST (dev/staging):** `OWASP ZAP`, `Burp Suite`  
- **CI integration:** Dependabot, Snyk, GitHub Security Alerts  
- **Misc:** `nmap`, `openssl` (staging only)

---

**Note:** Always test in a safe environment first, follow internal policies, and escalate critical findings immediately.
