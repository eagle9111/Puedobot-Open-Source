# PuedoBot Detection Engine Architecture

The detection engine combines deterministic static analysis with dual-pass AI reasoning.

## Directory Structure

```
app/engine/
├── scanners/         # Deterministic static analysis tools (zero LLM calls)
│   ├── ast_visitor   # Python AST sink inspection (eval, exec, subprocess, SQL)
│   ├── bandit        # Bandit static analyzer (40+ CWE vulnerability rules)
│   ├── semgrep       # Multi-language rules (JS/TS, Go, Java, PHP, etc.)
│   ├── secrets       # High-entropy regex and git-aware credential scanning
│   ├── dependencies  # OSV.dev published CVE matching for pinned requirements
│   ├── git_history   # Historical commit scanner for deleted/leaked secrets
│   └── discovery     # Unified generator orchestrating all deterministic tools
├── triage/           # AI Reasoning & Agentic Verification
│   ├── scout         # Agent Scout: LLM-driven architectural tree reconnaissance
│   ├── context_builder # Deterministic caller/enclosing function graph expansion
│   ├── llm_triage    # Primary triage pass with calibrated confidence scoring
│   └── verification  # Skeptical second-pass refuter and false positive filter
├── orchestrator.py   # LangGraph execution pipeline connecting scanners to triage
└── scanner.py        # Central scan facade and path filtering rules
```

## Data Flow Pipeline

1. **Reconnaissance (Scout)**:
   `app.engine.triage.scout` analyzes the directory tree and selects attack surfaces.
2. **Deterministic Discovery (Scanners)**:
   `app.engine.scanners.discovery` runs AST, Bandit, Semgrep, and Secret scanners.
   Every candidate is encapsulated as a `SuspiciousNode` (`app.schemas.node`).
3. **Context Enrichment**:
   `app.engine.triage.context_builder` builds function call trees and entrypoint hints.
4. **AI Triage & Verification**:
   Pass 1: `evaluate_hotspot` analyzes taint flows and reaches a verdict.
   Pass 2: `challenge_finding` attempts to refute the finding with adversarial skepticism.
5. **Persistence**:
   Confirmed findings exceeding `MIN_CONFIDENCE` are saved to PostgreSQL as `Vulnerability` records.
