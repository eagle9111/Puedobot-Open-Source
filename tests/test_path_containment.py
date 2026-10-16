"""Tests for filesystem containment and traversal protections."""
import os
import tempfile
from pathlib import Path
import pytest
from fastapi import HTTPException

from app.server.routes.scan import _resolve_server_target


def test_allowed_path_resolution():
    """Verify paths within current project directory are permitted."""
    valid_path = str(Path.cwd().resolve())
    resolved, repo_name = _resolve_server_target(valid_path)
    assert resolved == valid_path
    assert repo_name is None


def test_etc_directory_rejected():
    """Verify /etc cannot be audited and raises HTTP 403."""
    with pytest.raises(HTTPException) as exc_info:
        _resolve_server_target("/etc")
    assert exc_info.value.status_code == 403
    assert "outside permitted scanning boundaries" in exc_info.value.detail


def test_parent_directory_traversal_rejected():
    """Verify ../ paths escaping root are rejected."""
    # Build a path that resolves outside the project root
    traversal_path = str(Path.cwd().resolve() / ".." / ".." / ".." / ".." / "etc")
    with pytest.raises(HTTPException) as exc_info:
        _resolve_server_target(traversal_path)
    assert exc_info.value.status_code in (400, 403)


def test_symlink_escape_rejected():
    """Verify symlinks pointing outside permitted boundaries are resolved and rejected."""
    with tempfile.TemporaryDirectory(dir=str(Path.cwd())) as tmpdir:
        symlink_path = os.path.join(tmpdir, "evil_symlink")
        os.symlink("/etc", symlink_path)

        with pytest.raises(HTTPException) as exc_info:
            _resolve_server_target(symlink_path)

        assert exc_info.value.status_code == 403
        assert "outside permitted scanning boundaries" in exc_info.value.detail


def test_nonexistent_path_rejected():
    """Verify non-existent target path returns HTTP 400."""
    with pytest.raises(HTTPException) as exc_info:
        _resolve_server_target("/path/that/definitely/does/not/exist/987654")
    assert exc_info.value.status_code == 400
    assert "Target path does not exist" in exc_info.value.detail
