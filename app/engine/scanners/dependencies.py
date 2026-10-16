"""Dependency vulnerability scanner backed by OSV.dev."""
from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from app.core.scan_budget import HotspotList
from app.core.scan_http import fetch_json
from app.core.scan_budget import bounded_walk, CURRENT_BUDGET
from contextvars import copy_context
from app.core.constants import IGNORED_DIRS
from app.core.paths import is_safe_file, open_text_under
from app.schemas.finding import SecurityTriageResult, SeverityLevel
from app.schemas.node import SuspiciousNode
from app.engine.scanners.npm_manifest import parse_npm_manifest

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
MAX_ADVISORY_DETAILS = 60
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9_.\-+!]+)")


def _find_manifests(root: str):
    if os.path.isfile(root):
        if is_safe_file(Path(root).absolute().parent, Path(root).absolute()):
            yield root
        return
    for current, dirs, files in bounded_walk(root, topdown=True):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".") and not Path(current, d).is_symlink()]
        for name in files:
            if (name.startswith("requirements") and name.endswith(".txt")) or name == "package.json":
                path = os.path.join(current, name)
                if is_safe_file(Path(root).absolute(), Path(path).absolute()):
                    yield path


def _parse_requirements(path: str) -> tuple[list[tuple[str, str, int, str]], int]:
    """Return ([(name, version, line_no, raw_line)], unpinned_count)."""
    deps: list[tuple[str, str, int, str]] = []
    unpinned = 0
    try:
        with open_text_under(Path(path).absolute().parent, Path(path).absolute()) as handle:
            for idx, raw in enumerate(handle, 1):
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith(("-", "git+", "http")):
                    continue
                match = _REQ_LINE.match(line)
                if match:
                    deps.append((match.group(1), match.group(2), idx, raw.rstrip()))
                else:
                    unpinned += 1
    except (OSError, ValueError):
        pass
    return deps, unpinned


def _parse_package_json(path: str) -> list[tuple[str, str, int, str]]:
    """Compatibility view of exact manifest/lockfile evidence."""
    deps, _ = parse_npm_manifest(path, allow_lockfile=False)
    return [(dep.name, dep.version, dep.line, dep.evidence) for dep in deps]


def _query_osv(packages: list[tuple[str, str, str]]) -> list[list[str]]:
    """packages = [(ecosystem, name, version)] -> list of advisory id lists (same order)."""
    queries = [
        {"package": {"name": name, "ecosystem": eco}, "version": version}
        for eco, name, version in packages
    ]
    results: list[list[str]] = []
    if CURRENT_BUDGET.get():
        for start in range(0, len(queries), 500):
            data = fetch_json("POST", OSV_BATCH_URL, timeout=30, payload={"queries": queries[start:start+500]})
            results.extend([v["id"] for v in item.get("vulns", [])] for item in data.get("results", []))
        return results
    with httpx.Client(timeout=30.0) as client:
        for start in range(0, len(queries), 500):
            chunk = queries[start:start + 500]
            res = client.post(OSV_BATCH_URL, json={"queries": chunk})
            res.raise_for_status()
            for item in res.json().get("results", []):
                results.append([v["id"] for v in item.get("vulns", [])])
    return results


def _fetch_advisory(vuln_id: str) -> dict:
    try:
        if CURRENT_BUDGET.get():
            return fetch_json("GET", OSV_VULN_URL.format(id=vuln_id), timeout=20)
        res = httpx.get(OSV_VULN_URL.format(id=vuln_id), timeout=20.0)
        res.raise_for_status()
        return res.json()
    except Exception as exc:
        logger.warning(f"OSV advisory fetch failed for {vuln_id}: {exc}")
        return {"id": vuln_id}


def _severity_of(advisory: dict) -> str:
    raw = str((advisory.get("database_specific") or {}).get("severity", "")).upper()
    if raw == "MODERATE":
        return "MEDIUM"
    if raw in SEVERITY_ORDER:
        return raw
    return "MEDIUM"


def _fixed_versions(advisory: dict, package: str) -> list[str]:
    fixed: list[str] = []
    for affected in advisory.get("affected", []):
        if str((affected.get("package") or {}).get("name", "")).lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return fixed


def _highest(versions: list[str]) -> str | None:
    if not versions:
        return None
    try:
        from packaging.version import Version
        return str(max(versions, key=Version))
    except Exception:
        return sorted(versions)[-1]


def scan_dependencies(target_path: str) -> tuple[list[SuspiciousNode], list[str]]:
    """Return (findings, notices). Never raises: network trouble becomes a notice."""
    manifests = list(_find_manifests(target_path))
    if not manifests:
        return [], []

    entries: list[tuple[str, str, str, str, int, str]] = []  # eco, name, version, manifest, line, raw
    notices: list[str] = []
    for manifest in manifests:
        if os.path.basename(manifest) == "package.json":
            deps, npm_notices = parse_npm_manifest(manifest, allow_lockfile=os.path.isdir(target_path))
            notices.extend(npm_notices)
            for dep in deps:
                entries.append(("npm", dep.name, dep.version, dep.file_path, dep.line, dep.evidence))
        else:
            deps, unpinned = _parse_requirements(manifest)
            for name, version, line_no, raw in deps:
                entries.append(("PyPI", name, version, manifest, line_no, raw))
            if unpinned:
                notices.append(
                    f"{os.path.basename(manifest)}: {unpinned} unpinned requirement(s) skipped "
                    "(a CVE can only be matched to an exact version, so pin with '==')."
                )

    if not entries:
        return [], notices

    try:
        advisory_ids = _query_osv([(e[0], e[1], e[2]) for e in entries])
    except Exception as exc:
        logger.warning(f"⚠️ Dependency scanner: OSV.dev is unreachable or returned error ({exc}). Dependency CVE audit cannot proceed.")
        notices.append(f"⚠️ WARNING: OSV.dev is unreachable ({exc}). Dependency CVE scanning was skipped.")
        return [], notices

    unique_ids: list[str] = []
    for ids in advisory_ids:
        for vuln_id in ids:
            if vuln_id not in unique_ids:
                unique_ids.append(vuln_id)

    details: dict[str, dict] = {}
    if unique_ids:
        budget = CURRENT_BUDGET.get()
        with ThreadPoolExecutor(max_workers=budget.limits.osv_workers if budget else 8) as pool:
            futures = [pool.submit(copy_context().run, _fetch_advisory, identifier)
                       for identifier in unique_ids[:MAX_ADVISORY_DETAILS]]
            for future in futures:
                advisory = future.result()
                details[advisory.get("id", "")] = advisory

    findings: list[SuspiciousNode] = HotspotList()
    for entry, ids in zip(entries, advisory_ids):
        eco, name, version, manifest, line_no, raw = entry
        if not ids:
            continue

        advisories = [details.get(i, {"id": i}) for i in ids]
        severities = [_severity_of(a) for a in advisories]
        top = max(severities, key=SEVERITY_ORDER.index)
        if top == "LOW":
            continue

        fixed = _highest([f for a in advisories for f in _fixed_versions(a, name)])
        ranked = sorted(zip(advisories, severities), key=lambda p: SEVERITY_ORDER.index(p[1]), reverse=True)

        lines = [f"{raw.strip()}   <- version evidence in {os.path.basename(manifest)}", ""]
        for advisory, sev in ranked[:5]:
            cves = [a for a in advisory.get("aliases", []) if a.startswith("CVE-")]
            label = f"{advisory.get('id')}" + (f" ({', '.join(cves[:2])})" if cves else "")
            lines.append(f"- [{sev}] {label}: {advisory.get('summary', 'see advisory')}")
        if len(ranked) > 5:
            lines.append(f"- ... and {len(ranked) - 5} more advisories")
        lines.append("")
        lines.append(f"Fixed in: {fixed}" if fixed else "No fixed version published yet.")
        context = "\n".join(lines)

        result = SecurityTriageResult(
            is_vulnerable=True,
            severity=SeverityLevel(top),
            vulnerability_type="Vulnerable Dependency",
            description=(
                f"{name} {version} (recorded in {os.path.basename(manifest)}) has {len(ids)} known "
                f"published security advisor{'y' if len(ids) == 1 else 'ies'} on OSV.dev, the most severe being "
                f"{top}. Reachability of the vulnerable code paths in this project was not analyzed."
            ),
            remediation=f"Upgrade {name} to {fixed} or later." if fixed else f"Replace or remove {name}; no patched release exists.",
            confidence=90,
            input_source="N/A (known advisory matched to exact declared or lockfile-recorded version)",
            exploit_payload="See linked advisories: " + ", ".join(f"https://osv.dev/{a.get('id')}" for a, _ in ranked[:3]),
        )
        findings.append(SuspiciousNode(
            file_path=manifest,
            line_number=line_no,
            function_name=f"Vulnerable Dependency: {name}=={version}",
            code_context=context,
            source="dependency",
            prebuilt_result=result,
        ))

    return findings, notices
