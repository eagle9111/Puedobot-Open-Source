import os
import logging
from typing import TypedDict, Generator, Any
from langgraph.graph import StateGraph, START, END

from app.engine.ast_parser import SuspiciousNode
from app.core.scan_budget import CURRENT_BUDGET
from app.engine.analysis import Outcome, analyze_hotspot, save_finding
from app.engine.context_builder import RepoIndex
from app.engine.discovery import Discovery, run_discovery
from app.engine.scout import scout_repository

logger = logging.getLogger(__name__)


# 1. State Definition
class AgentState(TypedDict):
    target_path: str
    repo_id: int
    scan_history: bool
    smart_scan: bool
    selected_files: list[str] | None
    scout_plan: dict[str, Any] | None
    hotspots: list[SuspiciousNode]
    reviewed_findings: list[tuple[SuspiciousNode, Outcome]]


# 2. Graph Node: Agent Scout (LLM architectural tree analysis)
def scout_scope_node(state: AgentState):
    """Analyzes the repository tree and selects high-risk attack surface files."""
    target_path = state["target_path"]
    smart_scan = state.get("smart_scan", True)
    if not smart_scan or os.path.isfile(target_path):
        return {"selected_files": None, "scout_plan": None}

    logger.info(f"Agent Scout: Initiating architectural reconnaissance on target: {target_path}")
    plan = scout_repository(target_path)
    return {
        "selected_files": plan.selected_files,
        "scout_plan": plan.model_dump(),
    }


# 3. Graph Node: Discovery (AST, Bandit, secrets, Semgrep, dependencies, optional history)
def scan_directory_node(state: AgentState):
    """Runs every detection engine on selected files and merges their hotspots."""
    target_path = state["target_path"]
    selected_files = state.get("selected_files")
    logger.info(f"Starting security scan on target: {target_path} (Agent files: {len(selected_files) if selected_files else 'all'})")
    sink = Discovery()
    for _event in run_discovery(
        target_path,
        sink,
        scan_history=state.get("scan_history", False),
        selected_files=selected_files,
    ):
        pass  # the detached path has no live UI; events are only needed by the streamer
    logger.info(f"Scan complete: {sink.total_files} files checked, {len(sink.hotspots)} hotspots found.")
    return {"hotspots": sink.hotspots}


# 4. Graph Node: AI triage + skeptical verification + confidence gate
def triage_hotspots_node(state: AgentState):
    """Keep confirmed findings and candidates whose verification needs manual review."""
    logger.info(f"Triaging {len(state['hotspots'])} hotspots via LLM...")
    index = RepoIndex(state["target_path"])
    reviewed: list[tuple[SuspiciousNode, Outcome]] = []
    for hotspot in state["hotspots"]:
        budget = CURRENT_BUDGET.get()
        if budget:
            budget.consume("triage")
        try:
            outcome = analyze_hotspot(hotspot, index)
        except Exception as exc:
            logger.error(f"Error triaging {hotspot.function_name}: {exc}")
            continue
        if outcome.verdict in {"confirmed", "unverified"}:
            reviewed.append((hotspot, outcome))
    return {"reviewed_findings": reviewed}


# 5. Graph Node: Database Saver
def save_to_db_node(state: AgentState):
    """Persist confirmed findings and unverified candidates in pending review."""
    findings = state["reviewed_findings"]
    if not findings:
        return {}

    logger.info(f"Saving {len(findings)} reviewed findings to database for Repo #{state['repo_id']}...")
    for hotspot, outcome in findings:
        save_finding(state["repo_id"], hotspot, outcome)
    return {}


# 6. Build LangGraph Assembly Line
workflow = StateGraph(AgentState)
workflow.add_node("scout", scout_scope_node)
workflow.add_node("scan", scan_directory_node)
workflow.add_node("triage", triage_hotspots_node)
workflow.add_node("save", save_to_db_node)

workflow.add_edge(START, "scout")
workflow.add_edge("scout", "scan")
workflow.add_edge("scan", "triage")
workflow.add_edge("triage", "save")
workflow.add_edge("save", END)

puedobot_app = workflow.compile()


# 7. Granular Event Streamer (for real-time CLI feedback)
def stream_scan_pipeline(
    target_path: str,
    repo_id: int,
    scan_history: bool = False,
    feature_only: bool = False,
    smart_scan: bool = True,
    max_files: int | None = None,
    repo_name: str | None = None,
) -> Generator[dict[str, Any], None, None]:
    """Yields step-by-step progress events for interactive CLI clients."""
    if not repo_name:
        try:
            from app.services.repository_service import RepositoryService
            r = RepositoryService.get_repository(repo_id)
            if r and r.get("repo_name"):
                repo_name = r["repo_name"]
        except Exception:
            pass
    if not repo_name:
        base = os.path.basename(os.path.normpath(target_path))
        repo_name = base if base else f"Repo #{repo_id}"

    yield {
        "type": "start",
        "target_path": target_path,
        "repo_id": repo_id,
        "repo_name": repo_name,
        "feature_only": feature_only,
        "smart_scan": smart_scan,
    }

    # Step 0: Agent Scout file selection (if smart_scan enabled and target is directory)
    selected_files: list[str] | None = None
    if smart_scan and os.path.isdir(target_path):
        yield {
            "type": "scout_started",
            "target_path": target_path,
            "repo_id": repo_id,
            "repo_name": repo_name,
        }
        scout_plan = scout_repository(target_path)
        selected_files = scout_plan.selected_files
        yield {
            "type": "scout_completed",
            "repo_id": repo_id,
            "repo_name": repo_name,
            "selected_count": len(scout_plan.selected_files),
            "rationale": scout_plan.rationale,
            "attack_surfaces": scout_plan.identified_attack_surfaces,
            "skipped_areas": scout_plan.skipped_areas,
            "selected_files": scout_plan.selected_files,
        }

    # Step 1: Discovery across every engine
    sink = Discovery()
    yield from run_discovery(
        target_path,
        sink,
        scan_history=scan_history,
        feature_only=feature_only,
        max_files=max_files,
        selected_files=selected_files,
    )
    all_hotspots = sink.hotspots


    # Step 2: Context index (built once) + AI triage + skeptical verification
    index = RepoIndex(target_path)
    confirmed = dismissed = low_confidence = 0

    for idx, hotspot in enumerate(all_hotspots, 1):
        rel_path = os.path.relpath(hotspot.file_path, target_path) if os.path.isdir(target_path) else hotspot.file_path
        yield {
            "type": "triage_progress",
            "index": idx,
            "total": len(all_hotspots),
            "function": hotspot.function_name,
            "file": rel_path,
            "line": hotspot.line_number,
        }

        budget = CURRENT_BUDGET.get()
        if budget:
            budget.consume("triage")
        try:
            outcome = analyze_hotspot(hotspot, index)
        except Exception as e:
            logger.error(f"Error triaging {hotspot.function_name}: {e}")
            yield {
                "type": "triage_error",
                "file": rel_path,
                "line": hotspot.line_number,
                "error": str(e),
            }
            continue

        if outcome.verdict == "unverified" and outcome.result is not None:
            save_finding(repo_id, hotspot, outcome)
            yield {
                "type": "triage_error",
                "file": rel_path,
                "line": hotspot.line_number,
                "error": "AI verification did not complete; finding retained in pending review.",
            }
        elif outcome.verdict == "confirmed" and outcome.result is not None:
            # Persist immediately for crash & interrupt durability
            finding_id = save_finding(repo_id, hotspot, outcome)
            confirmed += 1
            yield {
                "type": "hotspot_confirmed",
                "id": finding_id,
                "repo_id": repo_id,
                "repo_name": repo_name,
                "file": rel_path,
                "line": hotspot.line_number,
                "vulnerability_type": outcome.result.vulnerability_type,
                "severity": outcome.result.severity.value,
                "description": outcome.result.description,
                "confidence": outcome.confidence,
                "source": hotspot.source,
            }
        elif outcome.verdict == "low_confidence":
            low_confidence += 1
            yield {
                "type": "hotspot_low_confidence",
                "file": rel_path,
                "line": hotspot.line_number,
                "function": hotspot.function_name,
                "confidence": outcome.confidence,
                "note": outcome.note,
            }
        else:
            dismissed += 1
            yield {
                "type": "hotspot_rejected",
                "file": rel_path,
                "line": hotspot.line_number,
                "function": hotspot.function_name,
                "note": outcome.note,
            }

    yield {
        "type": "complete",
        "repo_id": repo_id,
        "repo_name": repo_name,
        "total_files": sink.total_files,
        "total_hotspots": len(all_hotspots),
        "confirmed_vulnerabilities": confirmed,
        "dismissed": dismissed,
        "low_confidence": low_confidence,
    }
