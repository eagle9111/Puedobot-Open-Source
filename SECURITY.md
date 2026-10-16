# Security Policy

## Reporting Security Issues in PuedoBot

We take the security of PuedoBot seriously. If you discover a security vulnerability within PuedoBot itself (such as an authorization bypass, remote code execution, or path traversal), please report it responsibly.

### How to Report
- **GitHub Private Vulnerability Reporting**: Open a private report via the repository's [**Security > Report a vulnerability**](https://github.com/eagle9111/Puedobot-Open-Source/security/advisories/new) tab.
- **Email**: Alternatively, send vulnerability reports directly to the maintainer at `alhassan.khalilnew@gmail.com`.
- **Please do NOT open public GitHub issues** for unpatched vulnerabilities in PuedoBot.
- Include detailed reproduction steps, proof of concept payloads or commands, and environment details.
- We will acknowledge receipt within 48 hours and coordinate a timely fix and advisory.

---

## Defensive Security Architecture & Guidelines

PuedoBot is an automated security audit tool designed for defensive static analysis of repositories and codebases you own or have explicit authorization to inspect.

### 1. Secret Redaction
- All detected API keys, passwords, database URIs, and private certificates in code or git commit histories are automatically redacted (masking all but the first 4 characters).
- Redaction runs before any context reaches AI triage models or log outputs.

### 2. Context Sanitization & Prompt Injection Defense
- Untrusted code contexts sent to LLM triage chains are quarantined inside strict delimiters.
- Delimiter tags (e.g., `</untrusted_code_context>`) inside audited files are automatically escaped to prevent prompt injection and breakout attacks.
- Advisory outputs neutralize `@mentions`, external images, raw HTML tags, and hyperlinks to prevent notification spam or beacon tracking.

### 3. Path Containment & Local Confinement
- Scans are strictly confined to authorized directory boundaries configured in `PUEDOBOT_ALLOWED_ROOTS`.
- Symlink escapes, directory traversal attempts (`../`), and references outside authorized project roots are rejected with HTTP 403.
- Directory walks enforce strict file count, depth, and byte consumption limits to prevent denial-of-service from directory loops or oversized files.

### 4. API Authentication & Network Hardening
- By default, the API server binds strictly to `127.0.0.1`. Remote exposure (`0.0.0.0`) requires setting `PUEDOBOT_ALLOW_REMOTE=true`.
- All administrative and audit routes require authentication via `PUEDOBOT_API_KEY` (minimum 32 characters, non-placeholder) supplied through the `X-API-Key` or `Authorization: Bearer <token>` header.
