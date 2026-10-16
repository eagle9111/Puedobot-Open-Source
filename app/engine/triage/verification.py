"""Trust layer: turns raw AI triage into verified, scored findings."""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.scan_budget import FINDING_SINK
from app.db.models import Vulnerability
from app.db.session import SessionLocal
from app.engine.scanners.secrets import detect_secret_in_line
from app.engine.triage.context_builder import RepoIndex, build_extended_context
from app.engine.triage.llm_triage import challenge_finding, evaluate_hotspot
from app.schemas.finding import (
    VERIFICATION_UNAVAILABLE_NOTE,
    FindingStatus,
    SecurityTriageResult,
)
from app.schemas.node import SuspiciousNode

logger = logging.getLogger(__name__)

Verdict = Literal["confirmed", "dismissed", "low_confidence", "unverified"]

DUMMY_MARKERS = re.compile(
    r"(?i)(example|dummy|sample|placeholder|changeme|change_me|your[_\-]|<[^>]+>|xxxx|fake|"
    r"test[_\-]?(key|token|secret|password)|lorem|redacted|\*{4,})"
)


@dataclass
class Outcome:
    verdict: Verdict
    result: SecurityTriageResult | None
    confidence: int
    note: str


class FindingPersistenceError(RuntimeError):
    """A finding could not be committed; the scan must not report saved success."""


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((c / len(value)) * math.log2(c / len(value)) for c in counts.values())


def _secret_is_dummy(node: SuspiciousNode) -> bool:
    """True if every secret-looking value in the snippet is an obvious placeholder."""
    found_any = False
    for line in node.code_context.splitlines():
        hit = detect_secret_in_line(line)
        if not hit:
            continue
        found_any = True
        _label, value = hit
        looks_dummy = bool(DUMMY_MARKERS.search(value)) or (len(value) >= 12 and _entropy(value) < 2.2)
        if not looks_dummy:
            return False
    return found_any


def _grounding_ratio(result: SecurityTriageResult, node: SuspiciousNode) -> tuple[float, int]:
    """Share of identifiers quoted in the AI's explanation that really appear in the code shown to it."""
    quoted = set(re.findall(r"[`'\"]([A-Za-z_][\w.]{2,40})[`'\"]", result.description))
    if not quoted:
        return 1.0, 0
    haystack = f"{node.code_context}\n{node.extended_context}"
    present = sum(1 for token in quoted if token in haystack)
    return present / len(quoted), len(quoted)


def analyze_hotspot(node: SuspiciousNode, index: RepoIndex | None = None) -> Outcome:
    """Run the full triage + verification pipeline for one hotspot."""
    if node.prebuilt_result is not None:
        res = node.prebuilt_result
        return Outcome("confirmed", res, res.confidence, "Deterministic: exact version matched a published advisory (OSV.dev).")

    node.extended_context = build_extended_context(node, index)

    result = evaluate_hotspot(node)
    result.confidence = max(0, min(100, int(result.confidence)))

    if not result.is_vulnerable:
        return Outcome("dismissed", result, result.confidence, "AI triage: not exploitable / false positive.")

    notes: list[str] = []
    confidence = result.confidence

    # --- deterministic sanity checks --------------------------------------
    if node.source in ("secret", "history") or "Secret" in node.function_name:
        if _secret_is_dummy(node):
            return Outcome("dismissed", result, 0, "Deterministic: value is a documented example / placeholder credential.")

    ratio, quoted_count = _grounding_ratio(result, node)
    if quoted_count >= 3 and ratio < 0.4:
        confidence -= 25
        notes.append(f"Only {int(ratio * 100)}% of the identifiers in the AI's explanation appear in the code (possible hallucination).")

    if confidence < settings.MIN_CONFIDENCE:
        return _gate(result, confidence, notes + ["Confidence too low before verification."])

    # --- skeptical verifier ------------------------------------------------
    if settings.ENABLE_VERIFIER:
        try:
            verdict = challenge_finding(node, result)
            ver_conf = max(0, min(100, int(verdict.confidence)))
            if verdict.refuted:
                return Outcome("dismissed", result, ver_conf, f"Verifier refuted: {verdict.reasoning}")
            confidence = min(confidence, ver_conf)
            notes.append(f"Verifier could not refute: {verdict.reasoning}")
        except Exception as exc:
            logger.warning(f"Verifier unavailable for {node.file_path}:{node.line_number}: {exc}")
            return Outcome("unverified", result, confidence, " ".join([VERIFICATION_UNAVAILABLE_NOTE, *notes]))
    else:
        notes.append("Verifier disabled.")

    return _gate(result, confidence, notes)


def _gate(result: SecurityTriageResult, confidence: int, notes: list[str]) -> Outcome:
    result.confidence = max(0, confidence)
    note = " ".join(notes) if notes else "Triage only."
    verdict: Verdict = "confirmed" if confidence >= settings.MIN_CONFIDENCE else "low_confidence"
    return Outcome(verdict, result, result.confidence, note)


def save_finding(repo_id: int, node: SuspiciousNode, outcome: Outcome) -> int:
    """Commit a reviewable finding or raise; never retry an ambiguous commit."""
    assert outcome.result is not None
    sink = FINDING_SINK.get()
    if sink is not None:
        return sink(repo_id, node, outcome)
    try:
        with SessionLocal() as db:
            row = Vulnerability(
                repository_id=repo_id,
                file_path=node.file_path,
                line_number=node.line_number,
                vulnerability_type=outcome.result.vulnerability_type,
                severity=outcome.result.severity,
                description=_compose_description(outcome.result),
                remediation=outcome.result.remediation,
                code_snippet=node.code_context,
                confidence=outcome.confidence,
                source=node.source,
                verification_note=outcome.note,
                status=FindingStatus.PENDING_REVIEW,
            )
            db.add(row)
            db.flush()
            finding_id = row.id
            db.commit()
            return finding_id
    except SQLAlchemyError:
        logger.error("Failed to persist finding for repository %s; audit incomplete.", repo_id)
        raise FindingPersistenceError("Could not save finding; audit incomplete. Previously committed findings remain available.") from None


def _compose_description(result: SecurityTriageResult) -> str:
    """Technical analysis plus the evidence a maintainer needs to reproduce it."""
    parts = [result.description.strip()]
    if result.input_source and result.input_source.strip().upper() != "N/A":
        parts.append(f"Untrusted input: {result.input_source.strip()}")
    if result.exploit_payload and result.exploit_payload.strip().upper() != "N/A":
        parts.append(f"Exploit example: {result.exploit_payload.strip()}")
    return "\n\n".join(parts)
