"""Check syntax and build a source copy; never import settings or read dotenv."""
from __future__ import annotations

import ast
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shutil
import tempfile


def main() -> int:
    from setuptools.build_meta import build_wheel

    project = Path(__file__).resolve().parents[1]
    artifacts = Path(tempfile.mkdtemp(prefix="puedobot-build-", dir="/tmp"))
    source = artifacts / "source"
    source.mkdir()
    count = 0
    for directory in ("app", "tests", "benchmarks", "dashboard"):
        for path in (project / directory).rglob("*"):
            if path.is_symlink() or path.suffix not in {".py", ".js", ".cjs", ".css", ".html", ".txt"}:
                continue
            target = source / path.relative_to(project)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            if path.suffix == ".py":
                ast.parse(path.read_text(), filename=str(path))
                count += 1
    for name in ("pyproject.toml", "README.md", "LICENSE", "requirements.txt"):
        shutil.copyfile(project / name, source / name)
    print(f"Python syntax: {count} files passed")
    os.chdir(source)
    output = io.StringIO()
    try:
        with redirect_stdout(output):
            wheel = build_wheel(str(artifacts / "wheels"))
    except (Exception, SystemExit) as exc:
        print(f"Full-source wheel build failed: {exc}")
        return 1
    print(f"Wheel build passed: {artifacts / 'wheels' / wheel}")
    print("Lint/type-check unavailable: ruff and mypy are not installed; no dependencies added.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
