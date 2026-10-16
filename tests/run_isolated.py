"""Run tests without real dotenv, credentials, databases, clone caches, Git or HTTP.

Usage: .venv/bin/python -B tests/run_isolated.py [pytest arguments]
Artifacts are retained under /tmp; this runner never removes files.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch


def main() -> int:
    project = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project))
    sys.dont_write_bytecode = True
    sandbox = Path(tempfile.mkdtemp(prefix="puedobot-tests-", dir="/tmp"))
    safe_env = {
        "PATH": os.defpath,
        "HOME": str(sandbox),
        "TMPDIR": str(sandbox),
        "DEBUG": "false",
        "PUEDOBOT_ISOLATED_TEST": "1",
        "POSTGRES_USER": "synthetic",
        "POSTGRES_PASSWORD": "synthetic",
        "POSTGRES_DB": "synthetic",
        "PUEDOBOT_API_KEY": "synthetic-test-server-key",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    os.environ.clear()
    os.environ.update(safe_env)
    os.chdir(sandbox)

    import httpx
    import pytest
    import sqlalchemy
    from pydantic_settings.sources import DotEnvSettingsSource
    from sqlalchemy.pool import StaticPool

    create_engine = sqlalchemy.create_engine

    def memory_engine(url, **kwargs):
        if str(url).startswith("postgresql:"):
            return create_engine("sqlite://", poolclass=StaticPool,
                                 connect_args={"check_same_thread": False})
        if str(url) not in {"sqlite://", "sqlite:///:memory:"}:
            raise AssertionError("Tests may only use in-memory databases")
        return create_engine(url, **kwargs)

    def guarded_popen(args, *positional, **kwargs):
        raise AssertionError("External processes, including Git, are forbidden in isolated tests")

    def no_http(*args, **kwargs):
        raise AssertionError("Live outbound HTTP is forbidden in isolated tests")

    async def no_async_http(*args, **kwargs):
        raise AssertionError("Live outbound HTTP is forbidden in isolated tests")

    with patch.object(DotEnvSettingsSource, "_read_env_files", return_value={}), \
         patch.object(sqlalchemy, "create_engine", side_effect=memory_engine), \
         patch.object(subprocess, "Popen", side_effect=guarded_popen), \
         patch.object(httpx.HTTPTransport, "handle_request", side_effect=no_http), \
         patch.object(httpx.AsyncHTTPTransport, "handle_async_request", side_effect=no_async_http):
        from app.db.models import Base
        from app.db.session import engine
        Base.metadata.create_all(engine)
        args = sys.argv[1:]
        if not any(arg.startswith("tests/") or arg.endswith(".py") for arg in args):
            args = [str(project / "tests"), *args]
        args = [str(project / arg) if arg.startswith("tests/") else arg for arg in args]
        print(f"Isolated fixtures and retained artifacts: {sandbox}")
        return pytest.main(["-q", "-p", "no:cacheprovider", "-m", "not network",
                            "--rootdir", str(project), "--basetemp", str(sandbox / "fixtures"), *args])


if __name__ == "__main__":
    raise SystemExit(main())
