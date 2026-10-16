"""AI / LLM reasoning, Agent Scout, context building, and skeptical verification."""
from app.engine.triage.context_builder import CallSite, FunctionInfo, RepoIndex, build_extended_context
from app.engine.triage.llm_triage import challenge_finding, evaluate_hotspot
from app.engine.triage.scout import FileScoutPlan, scout_repository
from app.engine.triage.verification import Outcome, analyze_hotspot, save_finding

__all__ = [
    "RepoIndex",
    "FunctionInfo",
    "CallSite",
    "build_extended_context",
    "evaluate_hotspot",
    "challenge_finding",
    "scout_repository",
    "FileScoutPlan",
    "Outcome",
    "analyze_hotspot",
    "save_finding",
]
