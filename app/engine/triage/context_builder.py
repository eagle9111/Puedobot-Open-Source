"""Context builder: give the AI the evidence a human auditor would look at."""
from __future__ import annotations

import ast
from bisect import bisect_right
import heapq
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.scan_budget import bounded_walk
from app.core.constants import IGNORED_DIRS
from app.core.paths import is_safe_file, open_text_under
from app.schemas.node import SuspiciousNode

logger = logging.getLogger(__name__)

MAX_INDEXED_FILES = 3000
MAX_FUNCTION_LINES = 70
MAX_CALLERS = 3
MAX_CONTEXT_CHARS = 6000

# Decorator names that expose a function to the outside world.
ENTRY_POINT_RE = re.compile(
    r"\b(route|get|post|put|delete|patch|api_view|endpoint|websocket|command|task|shared_task|"
    r"subscribe|receiver|rpc|expose)\b"
)

# Substrings that indicate a function reads attacker-influenced data.
UNTRUSTED_SOURCES = [
    "request.", "flask.request", "input(", "sys.argv", "os.environ", "getenv(",
    "form[", "args.get(", "json.loads(", "recv(", "stdin", ".read()", "params[", "GET[", "POST[",
]


@dataclass
class FunctionInfo:
    name: str
    file: str
    start: int
    end: int
    decorators: list[str] = field(default_factory=list)
    qualified_name: str = ""

    @property
    def identity(self) -> tuple[str, str, int]:
        return (self.file, self.qualified_name or self.name, self.start)

    @property
    def first_line(self) -> int:
        """First line including decorators."""
        return self.start

    def is_entry_point(self) -> bool:
        return any(ENTRY_POINT_RE.search(d) for d in self.decorators)


@dataclass
class CallSite:
    file: str
    line: int
    caller: FunctionInfo | None


class RepoIndex:
    """Parsed view of every Python file under ``root``: functions and who calls whom."""

    def __init__(self, root: str):
        self.target_file = os.path.abspath(root) if os.path.isfile(root) else None
        self.root = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))
        self.lines: dict[str, list[str]] = {}
        self.functions: dict[str, list[FunctionInfo]] = {}
        self._function_ranges: dict[str, tuple[list[int], list[FunctionInfo | None]]] = {}
        self.callers: dict[tuple[str, str, int], list[CallSite]] = {}
        self._build()

    def _python_files(self):
        if self.target_file is not None:
            if self.target_file.endswith(".py") and is_safe_file(self.root, self.target_file):
                yield self.target_file
            return
        count = 0
        for current, dirs, files in bounded_walk(self.root, topdown=True):
            dirs[:] = [
                d for d in dirs
                if d not in IGNORED_DIRS and not d.startswith(".") and not d.endswith(".egg-info")
                and not Path(current, d).is_symlink()
            ]
            for name in files:
                if name.endswith(".py"):
                    count += 1
                    if count > MAX_INDEXED_FILES:
                        logger.warning("RepoIndex: file cap reached, remaining files are not indexed.")
                        return
                    path = os.path.join(current, name)
                    if is_safe_file(Path(self.root).absolute(), Path(path).absolute()):
                        yield path

    def _build(self) -> None:
        parsed = []
        for path in self._python_files():
            try:
                with open_text_under(Path(self.root).absolute(), Path(path).absolute()) as handle:
                    source = handle.read()
                tree = ast.parse(source, filename=path)
            except (SyntaxError, OSError, ValueError):
                continue

            self.lines[path] = source.splitlines()
            funcs: list[FunctionInfo] = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    decorators = []
                    for dec in node.decorator_list:
                        try:
                            decorators.append(ast.unparse(dec))
                        except Exception:
                            continue
                    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                    funcs.append(FunctionInfo(
                        name=node.name, file=path, start=start,
                        end=node.end_lineno or node.lineno, decorators=decorators,
                    ))
            self.functions[path] = funcs
            self._function_ranges[path] = self._index_function_ranges(funcs)

            parsed.append((path, tree))
        from app.engine.triage.caller_index import build_callers
        build_callers(self, parsed)

    @staticmethod
    def _callee_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def enclosing_function(self, path: str, line: int) -> FunctionInfo | None:
        """Innermost function containing ``line``."""
        starts, owners = self._function_ranges.get(path, ([], []))
        index = bisect_right(starts, line) - 1
        return owners[index] if index >= 0 else None

    @staticmethod
    def _index_function_ranges(funcs: list[FunctionInfo]) -> tuple[list[int], list[FunctionInfo | None]]:
        """Sweep range boundaries once, preserving shortest-range and AST-order ties.

        Includes decorators and defaults just like the original line-range lookup.
        At most two boundaries per function; no per-source-line allocation.
        """
        starting: dict[int, list[tuple[int, FunctionInfo]]] = {}
        boundaries: set[int] = set()
        for order, fn in enumerate(funcs):
            starting.setdefault(fn.start, []).append((order, fn))
            boundaries.update((fn.start, fn.end + 1))
        heap: list[tuple[int, int, FunctionInfo]] = []
        starts: list[int] = []
        owners: list[FunctionInfo | None] = []
        for line in sorted(boundaries):
            for order, fn in starting.get(line, []):
                heapq.heappush(heap, (fn.end - fn.start, order, fn))
            while heap and heap[0][2].end < line:
                heapq.heappop(heap)
            starts.append(line)
            owners.append(heap[0][2] if heap else None)
        return starts, owners

    def source_of(self, fn: FunctionInfo, limit: int = MAX_FUNCTION_LINES) -> str:
        body = self.lines.get(fn.file, [])[fn.start - 1:fn.end]
        if len(body) > limit:
            body = body[:limit] + [f"    # ... ({fn.end - fn.start + 1 - limit} more lines truncated)"]
        return "\n".join(body)

    def imports_of(self, path: str, limit: int = 25) -> str:
        out = [ln for ln in self.lines.get(path, []) if ln.startswith(("import ", "from "))]
        return "\n".join(out[:limit])


def _numbered(text: str, start: int) -> str:
    return "\n".join(f"{start + i:>5} {ln}" for i, ln in enumerate(text.splitlines()))


def build_extended_context(node: SuspiciousNode, index: RepoIndex | None) -> str:
    """Return a compact evidence bundle for ``node`` (empty string if not applicable)."""
    if index is None or not node.file_path.endswith(".py") or node.file_path not in index.lines:
        return ""

    sections: list[str] = []
    fn = index.enclosing_function(node.file_path, node.line_number)

    if fn is not None:
        body = index.source_of(fn)
        sections.append(f"# ENCLOSING FUNCTION `{fn.name}` (lines {fn.start}-{fn.end})\n{_numbered(body, fn.start)}")

        if fn.is_entry_point():
            sections.append(
                f"# ENTRY POINT: `{fn.name}` is exposed through decorator(s) {fn.decorators}. "
                "This is an entry-point hint. Trace argument expressions before claiming attacker-controlled input reaches a sink."
            )

        full_body = "\n".join(index.lines[node.file_path][fn.start - 1:fn.end])
        touched = [src for src in UNTRUSTED_SOURCES if src in full_body]
        if touched:
            sections.append(f"# UNTRUSTED INPUT SOURCES referenced in this function: {touched}")

        if not fn.name.startswith("__"):
            sites = [s for s in index.callers.get(fn.identity, []) if s.caller is not fn][:MAX_CALLERS]
            if sites:
                rendered = []
                for site in sites:
                    where = f"{os.path.relpath(site.file, index.root)}:{site.line}"
                    who = f"in `{site.caller.name}`" if site.caller else "at module level"
                    entry = " [HTTP/CLI ENTRY POINT]" if site.caller and site.caller.is_entry_point() else ""
                    code = index.lines[site.file][site.line - 1].strip() if site.file in index.lines else ""
                    rendered.append(f"  - {where} {who}{entry}: {code}")
                sections.append(f"# CALLERS of `{fn.name}`\n" + "\n".join(rendered))
            else:
                sections.append(f"# CALLERS of `{fn.name}`: none found in this repository (may be dead code or an external entry point).")
    else:
        sections.append("# The flagged line is at module level (not inside a function).")

    imports = index.imports_of(node.file_path)
    if imports:
        sections.append(f"# MODULE IMPORTS\n{imports}")

    context = "\n\n".join(sections)
    return context[:MAX_CONTEXT_CHARS]
