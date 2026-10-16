"""AST visitor and sink analyzer for Python source files."""
from __future__ import annotations

import ast
import logging
from pathlib import Path

from app.core.scan_budget import HotspotList
from app.core.paths import open_text_under
from app.schemas.node import SuspiciousNode

logger = logging.getLogger(__name__)

# Dangerous sinks flagged for security triage
DANGEROUS_SINKS = {
    "eval", "exec", "os.system", "os.popen",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "execute", "executescript"  # Commonly used in SQL (cursor.execute)
}


class SecurityASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, file_content: str):
        self.file_path = file_path
        self.file_content = file_content.splitlines()
        self.findings: list[SuspiciousNode] = HotspotList()

    def _get_full_call_name(self, node: ast.Call) -> str:
        """Extracts the full qualified name of the function call (e.g., 'os.system' or 'subprocess.run')."""
        parts = []
        curr = node.func
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))

    def _get_code_context(self, start_line: int, end_line: int) -> str:
        """Grabs the surrounding lines of code so the LLM has enough taint context to analyze."""
        start = max(0, start_line - 8)
        end = min(len(self.file_content), end_line + 6)
        return "\n".join(self.file_content[start:end])

    def _is_safe_execute_call(self, node: ast.Call) -> bool:
        """Suppress literal SQL, including literal queries with bound parameters.

        Variables and calls (including text/select/where) are not evidence of
        safety: names may be shadowed, and wrappers can receive interpolated SQL.
        This visitor does not resolve symbols or prove their data flow. Keep
        those expressions as candidates for triage, not confirmed flaws.
        """
        if node.args:
            sql = node.args[0]
        else:
            # Drivers use different names; **kwargs cannot establish a literal.
            if any(keyword.arg is None for keyword in node.keywords):
                return False
            arguments = [keyword.value for keyword in node.keywords
                         if keyword.arg in {"statement", "query", "operation", "sql"}]
            if len(arguments) != 1:
                return False
            sql = arguments[0]
        return isinstance(sql, ast.Constant) and isinstance(sql.value, str)

    def visit_Call(self, node: ast.Call):
        """This built-in method triggers every time the parser sees a function call."""
        func_name = self._get_full_call_name(node)

        # Match exact sinks (e.g., 'os.system', 'eval') or method calls (e.g. 'cursor.execute')
        is_sink = (
            func_name in DANGEROUS_SINKS
            or any(func_name.endswith(f".{sink}") for sink in DANGEROUS_SINKS if "." not in sink)
        )

        # Suppress only SQL whose literal form is established in this call.
        if is_sink and func_name.endswith(".execute"):
            if self._is_safe_execute_call(node):
                is_sink = False

        if is_sink:
            end_line = node.end_lineno if node.end_lineno is not None else node.lineno
            context = self._get_code_context(node.lineno, end_line)

            finding = SuspiciousNode(
                file_path=self.file_path,
                line_number=node.lineno,
                function_name=func_name,
                code_context=context,
            )
            self.findings.append(finding)

        self.generic_visit(node)


def scan_file_for_hotspots(file_path: str) -> list[SuspiciousNode]:
    """Reads a Python file, parses the AST, and returns suspicious code blocks."""
    try:
        with open_text_under(Path(file_path).absolute().parent, Path(file_path).absolute(), errors="strict") as f:
            content = f.read()

        tree = ast.parse(content, filename=file_path)
        visitor = SecurityASTVisitor(file_path, content)
        visitor.visit(tree)

        return visitor.findings
    except SyntaxError:
        logger.error(f"Syntax error in {file_path}. Skipping AST parse.")
        return []
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        return []
