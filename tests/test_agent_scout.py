import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from app.engine.discovery import Discovery, run_discovery
from app.engine.orchestrator import scout_scope_node, scan_directory_node
from app.engine.scout import (
    build_repo_tree_context,
    scout_repository,
    FileScoutPlan,
)


@pytest.fixture
def mock_repo_tree(tmp_path):
    """Creates a mock repository structure with diverse custom naming patterns."""
    # Custom non-standard folder names (not in traditional keywords)
    (tmp_path / "transport" / "grpc").mkdir(parents=True)
    (tmp_path / "delivery" / "http").mkdir(parents=True)
    (tmp_path / "domain" / "billing").mkdir(parents=True)
    (tmp_path / "tests" / "unit").mkdir(parents=True)
    (tmp_path / "docs").mkdir(parents=True)
    (tmp_path / ".git").mkdir(parents=True)
    (tmp_path / ".venv").mkdir(parents=True)

    # Scannable files
    (tmp_path / "transport" / "grpc" / "server.py").write_text("import os\n")
    (tmp_path / "delivery" / "http" / "handlers.py").write_text("import sys\n")
    (tmp_path / "domain" / "billing" / "payment_gateway.py").write_text("def pay(): pass\n")
    (tmp_path / "config.toml").write_text("debug = false\n")

    # Noise files that should be ignored or skipped
    (tmp_path / "tests" / "unit" / "test_billing.py").write_text("def test_pay(): pass\n")
    (tmp_path / "docs" / "conf.py").write_text("project = 'mock'\n")
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / ".venv" / "lib.py").write_text("secret = 1\n")
    (tmp_path / "README.md").write_text("# Fast Delivery Microservice\nHandles payment webhooks and gRPC transports.\n")

    return tmp_path


def test_build_repo_tree_context(mock_repo_tree):
    """Verifies tree builder extracts scannable files, ignores venv/git, and extracts README."""
    tree_text, all_candidates, meta = build_repo_tree_context(str(mock_repo_tree))

    # Should ignore .git and .venv
    assert not any(".git" in p for p in all_candidates)
    assert not any(".venv" in p for p in all_candidates)

    # Should contain real scannable files
    assert "delivery/http/handlers.py" in all_candidates
    assert "transport/grpc/server.py" in all_candidates
    assert "domain/billing/payment_gateway.py" in all_candidates
    assert "config.toml" in all_candidates

    # Metadata should contain README info
    assert meta["total_files"] == len(all_candidates)
    assert "Fast Delivery Microservice" in meta["project_info"]


def test_scout_repository_single_file(tmp_path):
    """Verifies that scanning a direct file path bypasses scout LLM entirely."""
    single_file = tmp_path / "main.py"
    single_file.write_text("print('hello')\n")

    plan = scout_repository(str(single_file))
    assert plan.selected_files == ["main.py"]
    assert "Single target file" in plan.rationale


def test_scout_repository_small_repo_shortcut(mock_repo_tree):
    """Small repositories (<= 15 files) should audit all files without making an LLM call."""
    with patch("app.engine.scout.get_scout_chain") as mock_chain:
        plan = scout_repository(str(mock_repo_tree), force_agent=False)
        # LLM chain should NOT be invoked
        mock_chain.assert_not_called()
        assert len(plan.selected_files) > 0
        assert "Small codebase" in plan.rationale


def test_scout_repository_llm_selection_with_hallucination_filtering(mock_repo_tree):
    """Tests LLM file selection and ensures non-existent / hallucinated paths are discarded."""
    mock_llm_plan = FileScoutPlan(
        selected_files=[
            "delivery/http/handlers.py",
            "domain/billing/payment_gateway.py",
            "non_existent/hallucinated_file.py",  # Hallucinated path
        ],
        rationale="Selected HTTP delivery handlers and payment logic as core attack surfaces.",
        identified_attack_surfaces=["REST handlers", "Payment gateway"],
        skipped_areas=["Unit tests", "Docs"],
    )

    with patch("app.engine.scout.get_scout_chain") as mock_chain:
        mock_invoker = MagicMock()
        mock_invoker.invoke.return_value = mock_llm_plan
        mock_chain.return_value = mock_invoker

        # Force agent call
        plan = scout_repository(str(mock_repo_tree), force_agent=True)

        # Must discard non-existent hallucination
        assert "non_existent/hallucinated_file.py" not in plan.selected_files
        assert "delivery/http/handlers.py" in plan.selected_files
        assert "domain/billing/payment_gateway.py" in plan.selected_files
        assert plan.identified_attack_surfaces == ["REST handlers", "Payment gateway"]


def test_scout_repository_fallback_on_llm_error(mock_repo_tree):
    """Verifies that if the LLM call raises an error, it safely falls back to default scannable files."""
    with patch("app.engine.scout.get_scout_chain") as mock_chain:
        mock_invoker = MagicMock()
        mock_invoker.invoke.side_effect = RuntimeError("LLM connection timed out")
        mock_chain.return_value = mock_invoker

        plan = scout_repository(str(mock_repo_tree), force_agent=True)

        # Should fall back gracefully and not crash
        assert len(plan.selected_files) > 0
        assert "error" in plan.rationale.lower()


def test_run_discovery_with_selected_files(mock_repo_tree):
    """Verifies run_discovery only scans the files chosen by the Agent Scout."""
    sink = Discovery()
    chosen_files = ["delivery/http/handlers.py"]

    events = list(run_discovery(
        str(mock_repo_tree),
        sink,
        selected_files=chosen_files,
    ))

    scanned_file_events = [e for e in events if e.get("type") == "file_scanned"]
    # Only 1 file should have been audited
    assert len(scanned_file_events) == 1
    assert "delivery/http/handlers.py" in scanned_file_events[0]["file"]
    assert sink.total_files == 1


def test_orchestrator_scout_node(mock_repo_tree):
    """Verifies the LangGraph scout_scope_node initializes selected_files in agent state."""
    state = {
        "target_path": str(mock_repo_tree),
        "repo_id": 1,
        "scan_history": False,
        "smart_scan": True,
        "selected_files": None,
        "scout_plan": None,
        "hotspots": [],
        "reviewed_findings": [],
    }

    result = scout_scope_node(state)
    assert result["selected_files"] is not None
    assert len(result["selected_files"]) > 0
    assert result["scout_plan"] is not None


def test_hierarchical_tree_visual_representation(mock_repo_tree):
    """Verifies hierarchical tree formatting includes branch connectors and omits tests."""
    tree_text, all_candidates, meta = build_repo_tree_context(str(mock_repo_tree))

    # Should contain root and directory connectors
    assert "." in tree_text
    assert "delivery/" in tree_text
    assert "transport/" in tree_text
    assert "domain/" in tree_text
    assert "handlers.py" in tree_text
    assert "server.py" in tree_text
    assert "payment_gateway.py" in tree_text
    # Should summarize non-feature directories (like docs) rather than flooding
    assert "docs/ [" in tree_text
    assert "non-feature/test file(s) omitted" in tree_text


def test_scout_directory_module_and_glob_expansion(mock_repo_tree):
    """Verifies the LLM can pick whole directory modules or globs and they expand correctly."""
    mock_llm_plan = FileScoutPlan(
        selected_files=[
            "transport/grpc",         # Directory without trailing slash
            "delivery/http/",         # Directory with trailing slash
            "*.toml",                 # Glob pattern
            "nonexistent_ghost_dir/", # Hallucinated folder
        ],
        rationale="Chose transport and delivery modules and configuration.",
        identified_attack_surfaces=["Network RPC", "HTTP API", "App Config"],
        skipped_areas=["Tests", "Docs"],
    )

    with patch("app.engine.scout.get_scout_chain") as mock_chain:
        mock_invoker = MagicMock()
        mock_invoker.invoke.return_value = mock_llm_plan
        mock_chain.return_value = mock_invoker

        plan = scout_repository(str(mock_repo_tree), force_agent=True)

        # Directory modules should have expanded to their files
        assert "transport/grpc/server.py" in plan.selected_files
        assert "delivery/http/handlers.py" in plan.selected_files
        # Glob should have resolved
        assert "config.toml" in plan.selected_files
        # Hallucinated folder should be omitted
        assert not any("ghost" in f for f in plan.selected_files)
        # Should not expand tests
        assert not any("tests" in f for f in plan.selected_files)
