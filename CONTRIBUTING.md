# Contributing to PuedoBot Core 🛡️

Thank you for your interest in contributing to PuedoBot Core! PuedoBot is an open-source, developer-first static analysis security auditor built to help developers and security teams discover vulnerabilities, verify dependencies, and eliminate false positives through skeptical AI triage.

---

## 🧭 Defensive Security & Ethical Principles

PuedoBot is built strictly for **defensive security auditing and code defense**.
- **No weaponization**: Pull requests that add automated exploitation payloads or malicious capabilities will be rejected.
- **Privacy & safety**: Default behavior must always respect user confidentiality—no scanned code or secrets should ever be transmitted to external services without explicit user configuration.
- **Responsible disclosure**: If you discover a security vulnerability within PuedoBot itself, please review our [SECURITY.md](SECURITY.md) and report it via GitHub Private Vulnerability Reporting or via email.

---

## 🛠️ Development Setup

### 1. Prerequisites
- **Python**: Version 3.11 or 3.12+
- **PostgreSQL**: Version 14+ (Local service or Docker container)
- **Git**

### 2. Fork and Clone
```bash
git clone https://github.com/eagle9111/Puedobot-Open-Source.git
cd Puedobot-Open-Source
```

### 3. Set Up Environment
```bash
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode with development and semgrep extras:
pip install -e ".[dev,semgrep]"
```

### 4. Local Database
Start a local PostgreSQL instance via Docker:
```bash
docker run -d --name puedobot-db -p 5432:5432 \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=puedobot \
  postgres:16-alpine
```

### 5. Configure Local Settings
```bash
cp .env.example .env
```
Generate an API key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```
Paste this token into `.env` as `PUEDOBOT_API_KEY`.

---

## 🧪 Running Tests & Validation

Before submitting any changes, verify that the test suite passes:

```bash
# Run all unit and integration tests (excluding live network checks):
pytest -m "not network"

# Run tests with coverage:
pytest --cov=app -m "not network"
```

---

## 📐 Coding Standards & Guidelines

1. **Python Standards**:
   - Python 3.11+ modern idioms (`str | None`, `list[str]`, `from __future__ import annotations`).
   - Strict Pydantic v2 schemas for all API payloads and internal state.
   - Clear exception hierarchies inheriting from base app exceptions.
2. **Determinism**:
   - File traversal, scan ordering, and report generation must be deterministic across operating systems (e.g., sort directory and file lists).
3. **Prompt Injection Defense**:
   - Any untrusted user code or AST snippets passed to LLM triage must be quarantined within `<untrusted_code_context>` tags and escaped against delimiter breakout.

---

## 🚀 Submitting a Pull Request

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Commit your changes with clear, descriptive commit messages following Conventional Commits (e.g., `feat:`, `fix:`, `docs:`, `test:`).
3. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
4. Open a Pull Request against the `main` branch. Provide a concise summary of the problem, the solution, and test coverage.

We review pull requests promptly and appreciate your help making open-source software more secure!
