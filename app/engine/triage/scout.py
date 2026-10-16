"""Agent Scout: LLM-driven architectural reconnaissance and dynamic file selection."""
from __future__ import annotations

import fnmatch
import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.prompts import ChatPromptTemplate

from app.core.scan_budget import bounded_walk
from app.core.config import settings
from app.core.constants import IGNORED_DIRS, NON_FEATURE_DIRS, is_scannable_file
from app.core.paths import is_safe_file, open_text_under
from app.engine.triage.llm_triage import _routed_llm
from app.schemas.scout import FileScoutPlan

logger = logging.getLogger(__name__)

# Prompt for the Architectural Security Scout
scout_prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        "You are an elite Senior Application Security Architect acting as the reconnaissance scout for PuedoBot SAST.\n"
        "Your mission is to analyze the complete repository directory tree and dynamically select the highest-risk files and modules to audit.\n\n"
        "WHY DYNAMIC AGENT SELECTION MATTERS:\n"
        "Real-world and large repositories do NOT use uniform or fixed folder names. A project might organize its external attack surface in:\n"
        "- 'gateway/', 'transport/', 'inbound/', 'delivery/', 'rpc/', 'webhooks/', or 'interfaces/http/'\n"
        "- Custom domain packages such as 'billing/', 'authz/', 'orders/', 'identity/', 'vault/', or 'payments/'\n"
        "- Kernel/subsystem directories like 'subsystems/', 'workers/', 'pipeline/', 'tasks/', or 'controllers/'\n"
        "Hardcoded keyword matching ('api', 'routes', 'models') fails on non-standard architectures. You must read the repository tree "
        "and determine where attacker-facing entrypoints, authentication flows, and dangerous execution sinks reside.\n\n"
        "WHAT TO PRIORITIZE (Attack Surfaces & High-Risk Logic):\n"
        "1. External Entrypoints: HTTP/REST/GraphQL/gRPC handlers, WebSockets, CLI command parsers, webhook receivers, message queue consumers.\n"
        "2. Authentication & Authorization: Login, password hashing, token validation, OAuth, session management, permissions, cryptography.\n"
        "3. Data Flow & Execution Sinks: Database interactions, raw SQL construction, user file uploads, file parsers, shell/subprocess calls, deserialization (pickle, yaml.load).\n"
        "4. Sensitive Configuration & Secrets: Environment variable loaders, settings, secret managers, container/compose configs, database credentials.\n"
        "5. Core Business Logic: Financial flows, permission checks, tenant isolation, admin operations.\n\n"
        "WHAT TO DELIBERATELY SKIP (Low Risk / Noise):\n"
        "- Unit and integration test suites (tests/, test/, testing/, fixtures/, mocks/)\n"
        "- Documentation generators (docs/, doc/, sphinx/, mkdocs/, tutorials/)\n"
        "- Benchmarks, build tooling, packaging scripts, CI configs, static frontend assets, translations\n\n"
        "SELECTION FLEXIBILITY:\n"
        "- You may specify exact file paths (e.g., 'transport/grpc/server.py') OR entire directory modules (e.g., 'gateway/', 'delivery/http', 'domain/billing/').\n"
        "- Directory paths will be automatically expanded to audit all scannable files within them.\n"
        "- Return relative paths matching the provided repository tree.\n"
        "- Provide a concise architectural rationale explaining your selections and why skipped areas were omitted."
    ),
    (
        "human",
        "REPOSITORY CONTEXT:\n"
        "Repository Root: {root_name}\n"
        "Total Scannable Files: {total_count}\n"
        "Project Overview:\n{project_info}\n\n"
        "REPOSITORY SCANNABLE TREE:\n"
        "{repo_tree}\n\n"
        "Analyze this tree and select the critical files and directories to audit."
    )
])


@lru_cache(maxsize=1)
def get_scout_chain():
    """Builds and caches the structured Agent Scout routing chain."""
    return scout_prompt | _routed_llm(FileScoutPlan)


def _extract_project_info(target_path: str) -> str:
    """Extract brief project metadata from README, pyproject.toml, or requirements."""
    notes: list[str] = []

    for readme_name in ("README.md", "README.rst", "README.txt", "readme.md"):
        readme_path = os.path.join(target_path, readme_name)
        if os.path.isfile(readme_path):
            try:
                with open_text_under(Path(target_path).absolute(), Path(readme_path).absolute()) as f:
                    lines = [line.strip() for line in f.readlines()[:25] if line.strip() and not line.strip().startswith("[!")]
                    excerpt = " ".join(lines[:6])[:600]
                    if excerpt:
                        notes.append(f"README excerpt: {excerpt}")
                        break
            except (OSError, ValueError):
                pass

    for req_file in ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py"):
        req_path = os.path.join(target_path, req_file)
        if os.path.isfile(req_path):
            try:
                with open_text_under(Path(target_path).absolute(), Path(req_path).absolute()) as f:
                    content = f.read().lower()
                    frameworks = [
                        fw for fw in ("fastapi", "flask", "django", "tornado", "celery", "sqlalchemy", "starlette", "drf", "click", "typer")
                        if fw in content
                    ]
                    if frameworks:
                        notes.append(f"Detected frameworks/libraries: {', '.join(sorted(set(frameworks)))}")
                        break
            except (OSError, ValueError):
                pass

    return "\n".join(notes) if notes else "Standard Python codebase"


def _count_nested_files(node: dict) -> int:
    """Helper to count total files in a nested directory branch."""
    count = len(node.get("__files__", []))
    for k, v in node.items():
        if k != "__files__":
            count += _count_nested_files(v)
    return count


def format_hierarchical_tree(
    scannable_paths: list[str],
    summarize_non_feature: bool = True,
    max_files_per_dir: int = 15,
) -> str:
    """Build a visual, hierarchical directory tree representation of the codebase."""
    tree: dict[str, Any] = {}
    for p in scannable_paths:
        parts = p.split("/")
        curr = tree
        for part in parts[:-1]:
            curr = curr.setdefault(part, {})
        curr.setdefault("__files__", []).append(parts[-1])

    def _render(node: dict, prefix: str = "") -> list[str]:
        lines: list[str] = []
        dirs = [k for k in sorted(node.keys()) if k != "__files__"]
        files = sorted(node.get("__files__", []))
        total_entries = len(dirs) + len(files)
        entry_idx = 0

        for d in dirs:
            entry_idx += 1
            is_last = (entry_idx == total_entries)
            connector = "└── " if is_last else "├── "
            child_prefix = "    " if is_last else "│   "

            if summarize_non_feature and d.lower() in NON_FEATURE_DIRS:
                file_count = _count_nested_files(node[d])
                lines.append(f"{prefix}{connector}{d}/ [{file_count} non-feature/test file(s) omitted]")
            else:
                lines.append(f"{prefix}{connector}{d}/")
                lines.extend(_render(node[d], prefix + child_prefix))

        for f in files[:max_files_per_dir]:
            entry_idx += 1
            is_last = (entry_idx == total_entries)
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{f}")

        if len(files) > max_files_per_dir:
            rem = len(files) - max_files_per_dir
            lines.append(f"{prefix}└── ... [{rem} more files in this directory]")

        return lines

    lines = ["."] + _render(tree)
    return "\n".join(lines)


def resolve_scout_paths(
    selected_items: list[str],
    all_candidates: list[str],
    target_path: str,
) -> list[str]:
    """Resolve file paths, directory modules, and globs chosen by the LLM against disk."""
    candidate_lookup = {p.lower(): p for p in all_candidates}
    dir_lookup: set[str] = set()
    for p in all_candidates:
        parts = p.split("/")
        for i in range(1, len(parts)):
            dir_lookup.add("/".join(parts[:i]).lower())

    resolved: list[str] = []

    for item in selected_items:
        clean = item.strip().replace("\\", "/").rstrip("/")
        if Path(clean).is_absolute() or ".." in Path(clean).parts:
            continue
        clean = clean.removeprefix("./")
        if not clean:
            continue

        clean_lower = clean.lower()

        # 1. Direct file match
        if clean in all_candidates:
            resolved.append(clean)
            continue
        if clean_lower in candidate_lookup:
            resolved.append(candidate_lookup[clean_lower])
            continue

        # 2. Directory match: expand to all scannable files inside this directory
        is_dir = (
            clean_lower in dir_lookup
            or os.path.isdir(os.path.join(target_path, clean))
            or any(p.lower().startswith(clean_lower + "/") for p in all_candidates)
        )
        if is_dir:
            matched_files = [p for p in all_candidates if p.lower().startswith(clean_lower + "/")]
            resolved.extend(matched_files)
            continue

        # 3. Wildcard / Glob pattern (e.g. gateway/*.py or *.toml)
        if any(c in clean for c in "*?[]"):
            matched_files = [
                p for p in all_candidates
                if fnmatch.fnmatch(p, clean) or fnmatch.fnmatch(p.lower(), clean_lower)
            ]
            resolved.extend(matched_files)
            continue

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for f in resolved:
        if f not in seen:
            seen.add(f)
            deduped.append(f)

    return [f for f in deduped if is_safe_file(Path(target_path).absolute(), Path(f))]


def build_repo_tree_context(
    target_path: str,
    max_tree_lines: int = 400,
) -> tuple[str, list[str], dict[str, Any]]:
    """Walk target directory and build a token-efficient visual tree representation."""
    if os.path.isfile(target_path):
        rel = os.path.basename(target_path)
        return f".\n└── {rel}", [rel], {"total_files": 1, "is_single_file": True}

    scannable_paths: list[str] = []

    for root, dirs, files in bounded_walk(target_path, topdown=True):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRS
            and not (d.startswith(".") and d != ".env")
            and not d.endswith(".egg-info")
            and not Path(root, d).is_symlink()
        ]

        rel_root = os.path.relpath(root, target_path)

        for file in sorted(files):
            if not is_scannable_file(file) or not is_safe_file(Path(target_path).absolute(), Path(root, file).absolute()):
                continue

            rel_file = file if rel_root == "." else os.path.join(rel_root, file)
            normalized_rel = rel_file.replace("\\", "/")
            scannable_paths.append(normalized_rel)

    scannable_paths.sort()
    total_count = len(scannable_paths)

    tree_text = format_hierarchical_tree(scannable_paths)
    project_info = _extract_project_info(target_path)
    meta = {
        "total_files": total_count,
        "is_single_file": False,
        "project_info": project_info,
    }

    return tree_text, scannable_paths, meta


def scout_repository(
    target_path: str,
    force_agent: bool = False,
    max_selection: int = 80,
) -> FileScoutPlan:
    """Analyze target codebase and dynamically choose high-risk attack surface files."""
    if os.path.isfile(target_path):
        rel = os.path.basename(target_path)
        return FileScoutPlan(
            selected_files=[rel],
            rationale="Single target file specified directly by user.",
            identified_attack_surfaces=["Explicit file target"],
            skipped_areas=[],
        )

    tree_text, all_candidates, meta = build_repo_tree_context(target_path)
    total_count = meta["total_files"]

    if total_count == 0:
        return FileScoutPlan(
            selected_files=[],
            rationale="No scannable code or configuration files found in repository.",
            identified_attack_surfaces=[],
            skipped_areas=[],
        )

    if total_count <= 10 and not force_agent:
        logger.info(f"Agent Scout: Small codebase ({total_count} files). Auditing all files directly.")
        return FileScoutPlan(
            selected_files=all_candidates,
            rationale=f"Small codebase ({total_count} files); auditing entire attack surface directly.",
            identified_attack_surfaces=["Entire repository (compact surface)"],
            skipped_areas=[],
        )

    if not settings.ENABLE_AGENT_SCOUT and not force_agent:
        logger.info("Agent Scout: Disabled by configuration. Using all scannable files.")
        return FileScoutPlan(
            selected_files=all_candidates[:max_selection],
            rationale="Agent Scout disabled; scanned default file candidate set.",
            identified_attack_surfaces=["Default file walk"],
            skipped_areas=[],
        )

    root_name = os.path.basename(os.path.abspath(target_path))
    logger.info(f"Agent Scout: Analyzing {total_count} scannable files in '{root_name}' via LLM...")

    try:
        chain = get_scout_chain()
        plan: FileScoutPlan = chain.invoke({
            "root_name": root_name,
            "total_count": total_count,
            "project_info": meta.get("project_info", ""),
            "repo_tree": tree_text,
        })
    except Exception as exc:
        logger.warning(f"Agent Scout LLM call failed: {exc}. Falling back to default scannable file walk.")
        return FileScoutPlan(
            selected_files=all_candidates[:max_selection],
            rationale=f"LLM scouting encountered an error ({exc}); fell back to default file walk.",
            identified_attack_surfaces=["Default heuristic scan"],
            skipped_areas=[],
        )

    validated_files = resolve_scout_paths(plan.selected_files, all_candidates, target_path)

    if not validated_files:
        logger.warning("Agent Scout: LLM returned no valid file paths. Falling back to default scannable files.")
        return FileScoutPlan(
            selected_files=all_candidates[:max_selection],
            rationale="LLM scout returned no valid matching paths; fallback to default scannable files.",
            identified_attack_surfaces=plan.identified_attack_surfaces or ["Fallback surface"],
            skipped_areas=plan.skipped_areas,
        )

    final_files = validated_files[:max_selection]
    logger.info(f"Agent Scout: Successfully selected {len(final_files)} target files out of {total_count} candidates.")

    return FileScoutPlan(
        selected_files=final_files,
        rationale=plan.rationale,
        identified_attack_surfaces=plan.identified_attack_surfaces,
        skipped_areas=plan.skipped_areas,
    )
