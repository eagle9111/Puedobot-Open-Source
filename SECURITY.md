# Security Policy

## Reporting Security Issues in PuedoBot

We take the security of PuedoBot seriously. If you discover a vulnerability within PuedoBot itself (such as authorization bypass, remote code execution, or path traversal), please report it responsibly.

### How to Report
- **Email**: Send vulnerability reports directly to the repository maintainer or open a GitHub Private Security Advisory via the repository's **Security** tab.
- **Do NOT open public GitHub issues** for zero-day vulnerabilities in PuedoBot.
- Include detailed reproduction steps, proof of concept scripts or curl payloads, and environment details.
- We will acknowledge receipt within 48 hours and work toward a coordinated disclosure plan.

---

## Responsible Disclosure & Ethical Auditing Guidelines

PuedoBot is an automated security audit companion designed for defensive analysis of repositories you own or have explicit authorization to inspect.

When operating PuedoBot, operators must abide by the following security practices:

### 1. No Autonomous Public Shaming / Issue Spam
- Autonomous discovery (`puedobot auto`) operates in dry-run mode by default.
- `auto --run --report` (alias `--publish`) enables one consolidated public issue per audit, with agent and owner profile links. Without reporting enabled, findings stay in the database.
- Automatic revisits require at least six calendar months and new pushes since the last audit. Repository leases prevent concurrent audits of the same cached checkout.
- The private advisory service remains available for **GitHub Private Vulnerability Reporting (PVR)** or confidential local reports under `reports/`.

### 2. Secret Redaction & Content Sanitization
- All detected tokens, passwords, and API keys are automatically redacted (masking all but the first 4 characters).
- All generated advisory reports neutralize `@mentions`, external markdown images, HTML injection tags, and hyperlinks to prevent harassment, beacon tracking, or malicious payload execution.

### 3. Path Containment & Local Safety
- Server scans are strictly constrained to roots configured in `PUEDOBOT_ALLOWED_ROOTS`.
- Symlink escapes and directory traversal attempts outside authorized project boundaries are rejected with HTTP 403.
- All temporary repository clones are cleaned up after auditing unless explicitly retained with `--keep`.

### 4. API Authentication
- API and dashboard servers bind to `127.0.0.1` by default.
- Remote exposure (`0.0.0.0`) requires setting `PUEDOBOT_ALLOW_REMOTE=true`.
- All administrative and audit routes require `PUEDOBOT_API_KEY` via `X-API-Key` or `Authorization: Bearer <token>`.
