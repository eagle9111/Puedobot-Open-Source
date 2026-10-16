# PuedoBot Test Suites & Quality Assurance

Comprehensive automated testing suites for the PuedoBot security analysis platform, covering static analysis, triage agents, API security, database persistence, and browser interface interactivity.

---

## Test Directory Structure

```
tests/
├── browser/
│   └── dashboard_browser.cjs      # Headless Chrome integration tests for web console
├── test_agent_scout.py            # Agent scout repository analysis & surface mapping
├── test_ast_and_bandit.py         # Python AST visitor and Bandit scanner rules
├── test_auth.py                   # API token validation and session signatures
├── test_auto_execution.py         # Autonomous discovery & scanning pipeline
├── test_batch1_security.py        # Core security scanning & injection guard tests
├── test_batch2_correctness.py     # Configuration, schemas, and operational correctness
├── test_batch3_scanner_correctness.py # Scanners & triage subpackage correctness
├── test_dashboard_api.py          # Dashboard endpoints & REST routing
├── test_dashboard_session.py      # Session cookies, lock/unlock & authentication
├── test_dependency_osv.py         # Dependency scanner & OSV vulnerability queries
├── test_llm_triage_mocked.py      # LLM triage verification & confidence scoring
├── test_path_containment.py       # Path traversal prevention & sandbox confinement
├── test_scan_stream.py            # NDJSON event streaming across scan phases
├── test_secrets_redaction.py      # Secret scanner & redaction regex rules
├── check_build.py                 # Build and dependency sanity checker
├── dashboard_browser.cjs          # Compatibility forwarder for browser integration tests
├── run_isolated.py                # Isolated test execution wrapper
└── README.md                      # Test suite documentation
```

---

## Running Tests

### 1. Python Unit & Integration Tests (pytest)
Runs all unit tests, scanner validations, and API integration suites:
```bash
./.venv/bin/pytest
```
*Expected: 298 passed.*

### 2. Headless Chrome Browser Integration Tests
Spawns an isolated mock server and headless Google Chrome instance via the Chrome DevTools Protocol (CDP) to validate:
- Zero horizontal overflow across viewports (320px, 390px, 533px, 768px, 1440px)
- Private access-code authentication and workspace locking
- Virtual terminal logging, command history, and shortcut handling
- Live NDJSON event stream reattachment
- Real-time review, deletion, and GitHub issue publication

```bash
node tests/browser/dashboard_browser.cjs
```
*(or via the forwarder: `node tests/dashboard_browser.cjs`)*
*Expected: PASS (all 19 checks passing).*

### 3. Build & Packaging Sanity Check
Validates package metadata, dependencies, and environment:
```bash
python tests/check_build.py
```
