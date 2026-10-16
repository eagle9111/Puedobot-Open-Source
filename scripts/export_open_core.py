#!/usr/bin/env python3
"""Export script: Generates the clean, standalone Open-Source repository ('puedobot-core').

Extracts only the safe, local defensive auditing components (AST, Semgrep, Bandit,
OSV dependency scanner, git secret detector, dual-pass AI triage, and CLI).
Excludes the proprietary web dashboard, 24/7 autonomous crawler, and GitHub advisory publisher.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

# Paths to strictly exclude from the open-source distribution
EXCLUDED_PATTERNS = {
    # Proprietary Autonomous Crawler & 24/7 Daemon
    "app/services/auto_scanner.py",
    "app/server/routes/auto.py",
    "tests/test_auto_execution.py",

    # Proprietary GitHub Security Advisory Publishing
    "app/services/github_service.py",
    "app/services/github_formatter.py",
    "tests/test_batch1_security.py",
    "tests/test_batch2_correctness.py",

    # Web Dashboard & Frontend Assets
    "dashboard",
    "app/server/dashboard_login.py",
    "scripts/legacy_redirect.py",
    "tests/browser",
    "tests/dashboard_browser.cjs",
    "tests/check_dashboard_pagination.cjs",
    "tests/test_dashboard_api.py",
    "tests/test_dashboard_session.py",

    # Local secrets & databases
    ".env",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".cache",
    ".venv",
    "logs",
    "reports",
    "scratch",
    "dist",
    ".vscode",
    ".idea",

    # Internal planning & agent context
    "AGENTS.md",
    "PROJECT_ABOUT.md",
    "REMAINING_BATCHES_PROPOSAL.md",
    "WORKFLOW.md",
}

OPEN_CORE_README = r"""# PuedoBot Core 🛡️

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://python.org)
[![Security: Multi-Engine SAST](https://img.shields.io/badge/Security-Multi--Engine_SAST-red.svg)](#-key-capabilities)
[![AI: Model Agnostic](https://img.shields.io/badge/AI-Universal_LLM_Support-purple.svg)](#-quick-start)

**Developer-first static analysis security auditor (SAST) with dual-pass skeptical AI false-alarm elimination.**

Traditional static security tools can flood engineering teams with false alarms, while running an entire repository through an LLM is costly, slow, and context-constrained. 

**PuedoBot Core** combines deterministic static analysis with intelligent AI verification:
1. **Deterministic Speed**: Pinpoints suspicious sinks using AST traversal, Bandit patterns, Semgrep security rules, OSV CVE advisories, and git commit history secret scans.
2. **Dual-Pass AI Triage**: Quarantines suspicious code snippets and evaluates them through a two-phase challenger pipeline — a **Triage Scout** assesses exploitability, followed by a **Skeptical Verifier** acting as a defense attorney to refute false alarms.
3. **Bring Your Own AI**: Connect **ANY** cloud LLM (DeepSeek, OpenAI, Google Gemini, Groq, Mistral, OpenRouter) or run **100% offline & private** with local models (Ollama, vLLM, LM Studio).

---

## ⚡ Key Capabilities

- **🔍 Multi-Engine SAST Scanner**: Simultaneously checks AST syntax patterns, Bandit security flaws, Semgrep rules, and OSV.dev dependency advisories in a single pass.
- **🔑 Git History Secret Redaction**: Detects exposed API keys, private certificates, and database secrets across active files and historical git commits with automatic regex redaction.
- **🧠 Dual-Pass Skeptical AI Triage**:
  - *Pass 1 (Exploitation Analysis)*: Traces data sources to sinks, identifies missing sanitizers, and estimates blast radius.
  - *Pass 2 (Challenger Refutation)*: Actively searches for framework protections, defensive guards, and dead code to eliminate false positives before presenting findings.
- **🌐 Universal Model Compatibility**: Completely model-agnostic. Plug in DeepSeek, OpenAI, Gemini, Groq, or self-host open-weights models (Qwen 2.5 Coder, Llama 3, DeepSeek-R1) via Ollama or vLLM.
- **💻 Rich Interactive CLI**: Terminal dashboards with highlighted code proof dossiers, confidence scores, and review workflows.
- **🔒 Privacy First & Air-Gapped Ready**: When configured with local inference, zero code or tokens leave your environment.

---

## 🏗️ How It Works

```mermaid
flowchart TD
    A[Target Codebase / Repository] --> B[Deterministic Engine]
    
    subgraph Sinks ["Multi-Engine Static Detection"]
        B --> B1[Python AST Traversal]
        B --> B2[Bandit Rules]
        B --> B3[Semgrep Configs]
        B --> B4[OSV Dependency CVEs]
        B --> B5[Git Secret Scanner]
    end

    Sinks --> C{Findings Detected?}
    C -->|No| D[Clean Audit Report]
    C -->|Yes| E[Quarantined Code Context]

    subgraph AI ["Dual-Pass AI Verification (Any LLM)"]
        E --> F[Pass 1: Triage Scout<br/>Analyzes Flow & Exploitability]
        F --> G[Pass 2: Skeptical Verifier<br/>Challenges & Refutes False Positives]
    end

    AI --> H[Verified Security Findings Dossier]
    H --> I[Interactive Terminal Review CLI]
```

---

## 🚀 Quick Start

### 1. Installation

```bash
git clone https://github.com/eagle9111/Puedobot-Open-Source.git
cd Puedobot-Open-Source
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configuration

Copy the sample environment file:
```bash
cp .env.example .env
```

Set your database and AI preference in `.env`:

#### Option A: Cloud AI (DeepSeek, OpenAI, Groq, Gemini, OpenRouter)
```dotenv
# Use any OpenAI-compatible API:
AI_API_URL=https://api.deepseek.com/v1     # Or OpenAI, Groq, OpenRouter, etc.
AI_API_KEY=your_api_key_here
MODEL_NAME=deepseek-chat

# Or use Google Gemini directly:
# AI_API_URL=
# AI_API_KEY=your_gemini_api_key_here
# MODEL_NAME=gemini-2.5-flash
```

#### Option B: 100% Offline / Local (Ollama, vLLM, LM Studio)
```dotenv
LOCAL_AI_URL=http://localhost:11434/v1
LOCAL_AI_MODEL=qwen2.5-coder:7b
AI_PRIORITY=local
```

### 3. Initialize Database & Run

```bash
# 1. Initialize DB tables
python -m scripts.init_db

# 2. Start the background scan service
uvicorn app.server.main:app --host 127.0.0.1 --port 8000 &

# 3. Audit any project or repository
puedobot scan /path/to/target/project
```

---

## 📖 CLI Commands

| Command | Description |
| :--- | :--- |
| `puedobot scan <path>` | Run a comprehensive multi-engine audit against target code |
| `puedobot show-errors` | Display interactive table of all verified security findings |
| `puedobot show <id>` | Inspect detailed vulnerability dossier and syntax-highlighted code proof |
| `puedobot review <id> <approve\|reject>` | Mark a finding as verified or dismissed |
| `puedobot repos` | List audited repositories and status |
| `puedobot activity` | Stream active audit jobs and status |

---

## 🛡️ Responsible Disclosure & Security Ethics

PuedoBot Core is created for authorized, defensive security auditing, pre-commit CI/CD quality gates, and code hardening.

## 📄 License

Apache 2.0. See [LICENSE](LICENSE) for details.
"""

OPEN_CORE_ENV_EXAMPLE = """# ==============================================================================
# PuedoBot Core — Environment Configuration Template
# ==============================================================================

# Database Configuration (PostgreSQL)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=replace_with_secure_password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=puedobot

# Primary Cloud / Remote AI (DeepSeek, OpenAI, Gemini, Groq, OpenRouter)
# For OpenAI-compatible endpoints (DeepSeek, Groq, OpenAI, etc.):
# AI_API_URL=https://api.deepseek.com/v1
# AI_API_KEY=your_cloud_ai_api_key_here
# MODEL_NAME=deepseek-chat
#
# For direct Google Gemini:
# AI_API_URL=
# AI_API_KEY=your_gemini_api_key_here
# MODEL_NAME=gemini-2.5-flash
AI_API_KEY=your_cloud_ai_api_key_here
AI_API_URL=
MODEL_NAME=gemini-2.5-flash

# Local / Self-Hosted AI (Ollama / vLLM / LM Studio)
LOCAL_AI_URL=http://localhost:11434/v1
LOCAL_AI_MODEL=qwen2.5-coder:7b
LOCAL_AI_API_KEY=ollama

# Model Priority: "cloud" (Cloud first, Local fallback) or "local" (Local first, Cloud fallback)
AI_PRIORITY=cloud

# Server & API Authentication
SERVER_URL=http://127.0.0.1:8000
PUEDOBOT_API_KEY=generate_a_strong_random_secret_here
"""

OPEN_CORE_LICENSE = """                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

   Copyright 2026 AL Hassan Khalil

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

OPEN_CORE_GITATTRIBUTES = """# GitHub Linguist language statistics overrides
benchmarks/corpus/* linguist-vendored
tests/* linguist-documentation
"""

OPEN_CORE_CLI_DOCS = '''"""Command guide, help text, and terminal visualizers for PuedoBot Core."""
from rich.console import Console
from rich.table import Table

console = Console()

CLI_HEADER = """
================================================================================
PUEDOBOT CORE // LOCAL CODEBASE SECURITY AUDITOR
================================================================================
  scan <target_path>            Audit a local codebase or directory
  show-errors                   Display table of detected security findings
  show <id>                     Inspect finding dossier and code proof
  review <id> <approve|reject>  Confirm or dismiss finding in local database
  repos                         List all audited repositories and vulnerability counts
================================================================================
"""

SCAN_HELP = "Audit target directory for security flaws and leaked secrets."
SHOW_ERRORS_HELP = "Display table of security findings in database."
SHOW_ERROR_HELP = "Inspect full dossier, code proof, and remediation for one finding."
SHOW_HELP = "Inspect detailed vulnerability dossier with syntax-highlighted code proof."
REVIEW_HELP = "Review and confirm or dismiss a finding (approve/reject)."
REPOS_HELP = "List all audited local repositories."
ACTIVITY_HELP = "Display active repository scans and status."


def render_cli_help() -> None:
    """Print the formatted command reference table."""
    table = Table(
        title="🤖 PuedoBot Core — Command Reference",
        title_style="bold green",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Command", style="bold white", width=30)
    table.add_column("Description", style="white")

    table.add_row("puedobot scan <path>", "Audit a local codebase or directory")
    table.add_row("puedobot show-errors", "List all findings across audited codebases")
    table.add_row("puedobot show <id>", "Display complete vulnerability dossier & code snippet")
    table.add_row("puedobot review <id> <verdict>", "Mark finding as verified ('approve') or false positive ('reject')")
    table.add_row("puedobot repos", "List all tracked codebases and finding tallies")

    console.print()
    console.print(table)
    console.print()
'''


OPEN_CORE_GITIGNORE = """# Byte-compiled / optimized files
__pycache__/
*.py[cod]
*$py.class

# Distribution / packaging
build/
dist/
*.egg-info/

# Virtual Environments
.venv/
env/
venv/

# Environment variables & secrets (keep .env.example tracked)
.env
.env.*
*.env
!.env.example

# Databases
*.sqlite
*.sqlite3
*.db

# Cache & Temporary files
.cache/
.pytest_cache/
.mypy_cache/
.ruff_cache/
*.log
logs/
scratch/
reports/

# IDE & Editor files
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
"""


def should_exclude(rel_path: str) -> bool:
    """Check if relative path matches any exclusion rule."""
    parts = Path(rel_path).parts
    for exc in EXCLUDED_PATTERNS:
        exc_parts = Path(exc).parts
        # Prefix or exact match
        if len(parts) >= len(exc_parts) and parts[:len(exc_parts)] == exc_parts:
            return True
        # Match standalone directory/file name anywhere in path
        if len(exc_parts) == 1 and exc_parts[0] in parts:
            return True
    return False


def export_open_core(src_root: Path, dest_root: Path, dry_run: bool = False) -> None:
    """Build the standalone Open-Source repository tree."""
    print(f"📦 Exporting PuedoBot Open Core...")
    print(f"   Source:      {src_root.resolve()}")
    print(f"   Destination: {dest_root.resolve()}")
    print(f"   Dry run:     {dry_run}\n")

    if not dry_run:
        if dest_root.exists():
            for item in dest_root.iterdir():
                if item.name == ".git":
                    continue
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
        else:
            dest_root.mkdir(parents=True, exist_ok=True)

    copied_files = 0
    excluded_files = 0

    # 1. Walk and copy allowed files
    for root, dirs, files in os.walk(src_root):
        rel_dir = os.path.relpath(root, src_root)
        if rel_dir == ".":
            rel_dir = ""

        # Filter dirs in-place
        dirs[:] = [d for d in dirs if not should_exclude(os.path.join(rel_dir, d))]

        for f in files:
            rel_file = os.path.join(rel_dir, f) if rel_dir else f
            if should_exclude(rel_file):
                excluded_files += 1
                continue

            src_file = src_root / rel_file
            dest_file = dest_root / rel_file

            if not dry_run:
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src_file, dest_file)
            copied_files += 1

    # 2. Write custom tailored open-core files
    if not dry_run:
        (dest_root / "README.md").write_text(OPEN_CORE_README, encoding="utf-8")
        (dest_root / ".env.example").write_text(OPEN_CORE_ENV_EXAMPLE, encoding="utf-8")
        (dest_root / "LICENSE").write_text(OPEN_CORE_LICENSE, encoding="utf-8")
        (dest_root / ".gitignore").write_text(OPEN_CORE_GITIGNORE, encoding="utf-8")
        (dest_root / ".gitattributes").write_text(OPEN_CORE_GITATTRIBUTES, encoding="utf-8")
        (dest_root / "app" / "cli" / "docs.py").write_text(OPEN_CORE_CLI_DOCS, encoding="utf-8")

        # Tailor app/server/main.py (strip auto router)
        server_main = dest_root / "app" / "server" / "main.py"
        if server_main.exists():
            content = server_main.read_text(encoding="utf-8")
            # Remove auto import and include_router
            content = content.replace("from app.server.routes import activity, auto, findings, repositories, scan",
                                      "from app.server.routes import activity, findings, repositories, scan")
            content = content.replace("app.include_router(auto.router)\n", "")
            # Remove daemon thread
            content = content.replace(
                "    if settings.AUTO_SCAN_DAEMON:\n        import threading\n        threading.Thread(target=auto.start_daemon_loop, daemon=True, name=\"AutoScanDaemon\").start()\n    yield\n    auto._daemon_stop_event.set()",
                "    yield"
            )
            server_main.write_text(content, encoding="utf-8")

        # Tailor app/cli/main.py (strip push and auto commands)
        cli_main = dest_root / "app" / "cli" / "main.py"
        if cli_main.exists():
            cli_lines = cli_main.read_text(encoding="utf-8").splitlines()
            open_cli_lines = []
            skip = False
            for line in cli_lines:
                if "@app.command(\"push-error\"" in line or "@app.command(\"auto\"" in line or "@app.command(\"stop-auto\"" in line or "@app.command(\"candidates\"" in line or "@app.command(\"push-repo\"" in line:
                    skip = True
                elif skip and line.startswith("@app.command("):
                    skip = False

                if not skip:
                    open_cli_lines.append(line)
            cli_main.write_text("\n".join(open_cli_lines) + "\n", encoding="utf-8")

        # Provide lightweight sanitizer shim for github_service in open-core
        gh_service_shim = dest_root / "app" / "services" / "github_service.py"
        gh_service_shim.write_text(
            '"""Lightweight compatibility shim: exports text sanitization utilities."""\n'
            'from app.services.github_sanitizer import sanitize_issue_content\n\n'
            '__all__ = ["sanitize_issue_content"]\n',
            encoding="utf-8",
        )

    print(f"✨ Export Summary:")
    print(f"   Files Copied:   {copied_files}")
    print(f"   Files Excluded: {excluded_files} (Dashboard, Auto-crawler, GitHub publisher)")
    print(f"   Destination:    {dest_root.resolve()}")
    print("\n🚀 Next Steps to initialize your public repository:")
    print(f"   1. cd {dest_root.resolve()}")
    print(f"   2. git status && git diff")
    print(f"   3. git add .")
    print(f"   4. git commit -m 'feat: update open-source core release'")
    print(f"   5. git push\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export PuedoBot safe open-source core.")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent / "Puedobot-Open-Source",
        help="Target directory for open-source repository",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate file extraction without creating files",
    )
    args = parser.parse_args()
    src_root = Path(__file__).resolve().parent.parent
    export_open_core(src_root, args.output, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
