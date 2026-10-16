"""PuedoBot detection benchmark.

Measures, against code where the right answer is known, how many real flaws the engine
finds (recall) and how many of its alarms are real (precision). Without this, "is the
scanner any good?" is a feeling; with it, it is a number you can watch change.

Annotations live next to the code in ``benchmarks/corpus``:

    # EXPECT: <class>   a real flaw that MUST be found and confirmed
    # SAFE              looks dangerous but is not; must NOT be confirmed
    # GAP: <class>      a real flaw we know the engine cannot see yet (tracked honestly)

Usage:
    python -m benchmarks.run_benchmark            # static engines only (free, fast)
    python -m benchmarks.run_benchmark --ai       # + AI triage and skeptical verifier
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table

from app.engine.analysis import analyze_hotspot
from app.engine.ast_parser import SuspiciousNode
from app.engine.context_builder import RepoIndex
from app.engine.discovery import Discovery, run_discovery

console = Console()
CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
ANNOTATION = re.compile(r"(?:#|//)\s*(EXPECT|SAFE|GAP)(?::\s*(\w+))?")
LINE_TOLERANCE = 1  # multi-line statements are reported on their first line by some engines


@dataclass
class Case:
    file: str
    line: int
    kind: str  # EXPECT | SAFE | GAP
    label: str


def load_cases(corpus: str) -> list[Case]:
    cases: list[Case] = []
    for current, _dirs, files in os.walk(corpus):
        for name in sorted(files):
            path = os.path.join(current, name)
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for number, text in enumerate(handle, 1):
                    match = ANNOTATION.search(text)
                    if match:
                        cases.append(Case(path, number, match.group(1), match.group(2) or ""))
    return cases


def find_hotspots(node_list: list[SuspiciousNode], case: Case, annotated: set[tuple[str, int]]) -> list[SuspiciousNode]:
    """Hotspots attributable to ``case``.

    Exact line matches always count. A hotspot one line away only counts when that neighbouring
    line is NOT an annotated case itself (otherwise adjacent cases would steal each other's hits).
    """
    case_file = os.path.abspath(case.file)
    hits = []
    for n in node_list:
        if os.path.abspath(n.file_path) != case_file:
            continue
        if n.line_number == case.line:
            hits.append(n)
        elif abs(n.line_number - case.line) <= LINE_TOLERANCE and (case_file, n.line_number) not in annotated:
            hits.append(n)
    return hits


def pct(num: int, den: int) -> str:
    return f"{(100 * num / den):.0f}%" if den else "n/a"


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark PuedoBot detection quality.")
    parser.add_argument("--ai", action="store_true", help="also run AI triage + verifier (uses your API key)")
    parser.add_argument("--corpus", default=CORPUS, help="directory with annotated code")
    parser.add_argument("--min-recall", type=float, default=0.0, help="exit 1 if recall falls below this (0-1)")
    parser.add_argument("--min-precision", type=float, default=0.0, help="exit 1 if precision falls below this (0-1)")
    args = parser.parse_args()

    logging.disable(logging.CRITICAL)  # keep the report readable
    corpus = os.path.abspath(args.corpus)
    cases = load_cases(corpus)
    expected = [c for c in cases if c.kind == "EXPECT"]
    safe = [c for c in cases if c.kind == "SAFE"]
    gaps = [c for c in cases if c.kind == "GAP"]
    annotated = {(os.path.abspath(c.file), c.line) for c in cases}

    console.print(f"[bold cyan]Corpus:[/bold cyan] {corpus}")
    console.print(f"{len(expected)} real flaws, {len(safe)} safe look-alikes, {len(gaps)} known gaps\n")

    sink = Discovery()
    with console.status("Running detection engines..."):
        for _event in run_discovery(corpus, sink):
            pass
    hotspots = sink.hotspots

    outcomes: dict[tuple[str, int], str] = {}
    if args.ai:
        index = RepoIndex(corpus)
        with console.status("AI triage + verification...") as status:
            for i, node in enumerate(hotspots, 1):
                status.update(f"AI triage {i}/{len(hotspots)}: {os.path.basename(node.file_path)}:{node.line_number}")
                try:
                    outcomes[(os.path.abspath(node.file_path), node.line_number)] = analyze_hotspot(node, index).verdict
                except Exception as exc:  # network / quota trouble must not hide the static numbers
                    outcomes[(os.path.abspath(node.file_path), node.line_number)] = f"error: {exc}"

    def verdict_for(case: Case) -> tuple[bool, bool]:
        """(flagged_by_engines, confirmed_final). Without --ai a flag counts as confirmed."""
        hits = find_hotspots(hotspots, case, annotated)
        if not hits:
            return False, False
        if not args.ai:
            return True, True
        confirmed = any(outcomes.get((os.path.abspath(h.file_path), h.line_number)) == "confirmed" for h in hits)
        return True, confirmed

    table = Table(title="Per-case results", title_style="bold")
    for column in ("Case", "Expected", "Flagged", "Confirmed", "Result"):
        table.add_column(column)

    tp = fn = fp = tn = gaps_closed = static_noise = 0
    for case in expected:
        flagged, confirmed = verdict_for(case)
        if confirmed:
            tp += 1
        else:
            fn += 1
        table.add_row(f"{os.path.basename(case.file)}:{case.line} {case.label}", "REAL", "yes" if flagged else "no",
                      "yes" if confirmed else "no", "[green]TP[/green]" if confirmed else "[red]MISSED[/red]")
    for case in safe:
        flagged, confirmed = verdict_for(case)
        if args.ai:
            if confirmed:
                fp += 1
            else:
                tn += 1
            label = "[red]FALSE ALARM[/red]" if confirmed else ("[green]OK (AI filtered)[/green]" if flagged else "[green]OK (never flagged)[/green]")
        else:
            static_noise += int(flagged)
            label = "[yellow]flagged -> AI must filter[/yellow]" if flagged else "[green]OK (never flagged)[/green]"
        table.add_row(f"{os.path.basename(case.file)}:{case.line}", "SAFE", "yes" if flagged else "no",
                      "yes" if (confirmed and args.ai) else "no", label)
    for case in gaps:
        flagged, confirmed = verdict_for(case)
        closed = flagged and confirmed
        gaps_closed += int(closed)
        table.add_row(f"{os.path.basename(case.file)}:{case.line} {case.label}", "KNOWN GAP", "yes" if flagged else "no",
                      "yes" if confirmed else "no", "[green]now detected![/green]" if closed else "[yellow]still a gap[/yellow]")
    console.print(table)

    recall = tp / len(expected) if expected else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    console.print()
    console.print(f"[bold]Mode:[/bold] {'static + AI + verifier' if args.ai else 'static engines only (run with --ai for the full pipeline)'}")
    console.print(f"[bold]Recall   :[/bold] {pct(tp, len(expected))}  ({tp}/{len(expected)} real flaws found)")
    if args.ai:
        console.print(f"[bold]Precision:[/bold] {pct(tp, tp + fp)}  ({fp} false alarm(s) among {tp + fp} confirmed)")
    else:
        console.print(f"[bold]Static noise:[/bold] {static_noise}/{len(safe)} safe look-alikes still flagged before AI triage (run --ai to measure precision)")
    console.print(f"[bold]Known gaps closed:[/bold] {gaps_closed}/{len(gaps)}")

    if recall < args.min_recall or precision < args.min_precision:
        console.print("[bold red]Benchmark below threshold.[/bold red]")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
