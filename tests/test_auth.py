"""Tests for API Key authentication and route protection."""
import os
import pytest
from starlette.testclient import TestClient
from unittest.mock import patch

TEST_API_KEY = "test-auth-secret-token-1234567890123456"
os.environ.setdefault("PUEDOBOT_API_KEY", TEST_API_KEY)

from app.core.config import settings
from app.server.main import app
from app.services.repository_service import RepositoryService


@pytest.fixture
def client():
    # Set a deterministic test key in settings for the test run (>= 32 chars)
    with patch.object(settings, "PUEDOBOT_API_KEY", TEST_API_KEY), \
         patch("app.server.main.ensure_schema"), \
         patch.object(RepositoryService, "list_repositories", return_value=[]), \
         patch.object(RepositoryService, "repository_page", return_value={"repositories": []}):
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


def test_missing_api_key_returns_401(client):
    """Requests without authentication headers should be rejected with 401."""
    res = client.get("/repositories")
    assert res.status_code == 401
    assert "PUEDOBOT_API_KEY" in res.json().get("detail", "")


def test_invalid_api_key_returns_401(client):
    """Requests with an incorrect API key should be rejected with 401."""
    res = client.get("/repositories", headers={"X-API-Key": "wrong-secret-token-123456789012345"})
    assert res.status_code == 401
    assert "Unauthorized" in res.json().get("detail", "")


def test_valid_x_api_key_header_succeeds(client):
    """Requests with valid X-API-Key header should succeed."""
    res = client.get("/repositories", headers={"X-API-Key": TEST_API_KEY})
    assert res.status_code == 200
    assert "repositories" in res.json()


def test_valid_bearer_token_succeeds(client):
    """Requests with Authorization: Bearer <token> should succeed."""
    headers = {"Authorization": f"Bearer {TEST_API_KEY}"}
    res = client.get("/repositories", headers=headers)
    assert res.status_code == 200
    assert "repositories" in res.json()


def test_docs_and_openapi_require_auth(client):
    """Documentation must not expose the API to unauthenticated visitors."""
    assert client.get("/openapi.json").status_code == 401
    assert client.get("/docs").status_code == 401
    assert client.get("/openapi.json", headers={"X-API-Key": TEST_API_KEY}).status_code == 200
