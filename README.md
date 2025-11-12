# Top10OWASP - SAST

Enterprise-grade web application security checklist based on OWASP Top 10 (2021), designed for secure development, code review, audit, and vulnerability management in corporate environments.

## Usage

1. Review `SECURITY_CHECKLIST.md` for guidance on OWASP Top 10 security controls.
2. Use `tools/` configs to scan your codebase - SAST (Static Application Security Testing) :
   - `semgrep.yml` for JavaScript
   - `bandit_config.yaml` for Python
3. Refer to `examples/` for demo output from scans.
4. Integrate CI workflow in `.github/workflows/security.yml` for automated security checks on PRs.
5. Use PR template `.github/PULL_REQUEST_TEMPLATE.md` to ensure security steps are verified before merging.
