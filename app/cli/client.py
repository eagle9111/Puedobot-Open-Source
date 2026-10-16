import json
import warnings
import os
from typing import Any, Generator
import httpx

from app.core.config import settings


class PuedoBotClientError(Exception):
    """Custom exception for CLI API client errors."""
    pass


class PuedoBotClient:
    """HTTP Client communicating with the PuedoBot backend API."""

    def __init__(self, base_url: str | None = None, timeout: float = 120.0, api_key: str | None = None):
        self.base_url = (base_url or settings.SERVER_URL).rstrip("/")
        self.timeout = timeout
        self.api_key = api_key or settings.PUEDOBOT_API_KEY or ""

    def _get_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _client(self, timeout: float | httpx.Timeout | None = None) -> httpx.Client:
        return httpx.Client(
            follow_redirects=True,
            timeout=self.timeout if timeout is None else timeout,
            headers=self._get_headers(),
        )

    @staticmethod
    def _server_target(target_path: str) -> str:
        """Send remote references to the server so it can claim them before cloning."""
        from app.services.git_service import GitService

        return GitService.normalize_github_target(target_path) or os.path.abspath(target_path)

    def trigger_scan(self, target_path: str, scan_history: bool = False, smart_scan: bool = True, keep: bool = False) -> int:
        """Trigger an asynchronous background scan on the server and return the repo ID."""
        resolved_path = self._server_target(target_path)

        try:
            with self._client() as client:
                res = client.post(
                    f"{self.base_url}/scan",
                    json={"target_path": resolved_path, "scan_history": scan_history, "smart_scan": smart_scan, "keep": keep},
                )
                res.raise_for_status()
                data = res.json()
                return data["repo_id"]
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to connect to server: {e}") from e

    def stream_scan(self, target_path: str, scan_history: bool = False, smart_scan: bool = True, keep: bool = False) -> Generator[dict[str, Any], None, None]:
        """Stream real-time scan and LLM triage events from the server."""
        resolved_path = self._server_target(target_path)

        try:
            # Long read timeout: Semgrep and the two-pass AI verification can stay quiet for a while.
            with self._client(timeout=httpx.Timeout(self.timeout, read=600.0)) as client:
                with client.stream(
                    "POST",
                    f"{self.base_url}/scan/stream",
                    json={"target_path": resolved_path, "scan_history": scan_history, "smart_scan": smart_scan, "keep": keep},
                ) as response:
                    response.raise_for_status()
                    for line in response.iter_lines():
                        if line:
                            yield json.loads(line)
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Network error during scan stream: {e}") from e


    def get_errors(self, status: str = "pending") -> list[dict[str, Any]]:
        """Fetch findings filtered by status ('pending', 'approved', 'rejected', 'all')."""
        try:
            with self._client() as client:
                findings, seen = [], set()
                cursor = None
                for _ in range(100):
                    params = {"status": status, "limit": 100}
                    if cursor:
                        params["cursor"] = cursor
                    res = client.get(f"{self.base_url}/errors", params=params)
                    res.raise_for_status()
                    data = res.json()
                    findings.extend(data.get("findings", []))
                    cursor = data.get("pagination", {}).get("next_cursor")
                    if not cursor:
                        return findings
                    if cursor in seen:
                        raise PuedoBotClientError("Server repeated a pagination cursor; listing stopped")
                    seen.add(cursor)
                warnings.warn("Finding listing truncated after 100 pages (10,000 findings)", stacklevel=2)
                return findings
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to fetch errors: {e}") from e

    def get_pending_errors(self) -> list[dict[str, Any]]:
        """Fetch all findings currently pending review (alias for get_errors('pending'))."""
        return self.get_errors(status="pending")

    def get_error(self, finding_id: int) -> dict[str, Any]:
        """Fetch a single finding by ID directly from the server."""
        try:
            with self._client() as client:
                res = client.get(f"{self.base_url}/errors/{finding_id}")
                res.raise_for_status()
                return res.json().get("finding", {})
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", "")
            except Exception:
                detail = e.response.text
            raise PuedoBotClientError(detail or str(e)) from e
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to fetch finding #{finding_id}: {e}") from e


    def submit_review(
        self, finding_id: int, approved: bool, publish_to_github: bool = False
    ) -> dict[str, Any]:
        """Submit an approval or rejection review for a specific finding."""
        try:
            with self._client() as client:
                res = client.post(
                    f"{self.base_url}/errors/{finding_id}/push",
                    json={"approved": approved, "publish_to_github": publish_to_github},
                )
                res.raise_for_status()
                return res.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", "")
            except Exception:
                detail = e.response.text
            raise PuedoBotClientError(detail or str(e)) from e
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to submit review for #{finding_id}: {e}") from e

    def get_auto_candidates(
        self,
        limit: int = 5,
        cooldown_days: int = 180,
        min_size_kb: int = 10,
        max_size_kb: int = 5000,
        language: str = "python",
    ) -> list[dict[str, Any]]:
        """Fetch candidate GitHub repositories annotated with cooldown eligibility."""
        try:
            with self._client() as client:
                res = client.get(
                    f"{self.base_url}/scan/auto/candidates",
                    params={
                        "limit": limit,
                        "cooldown_days": cooldown_days,
                        "min_size_kb": min_size_kb,
                        "max_size_kb": max_size_kb,
                        "language": language,
                    },
                )
                res.raise_for_status()
                return res.json().get("candidates", [])
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to fetch auto candidates: {e}") from e

    def stream_auto_scan(
        self,
        limit: int = 3,
        cooldown_days: int = 180,
        min_size_kb: int = 10,
        max_size_kb: int = 5000,
        language: str = "python",
        feature_only: bool = True,
        smart_scan: bool = True,
        scan_history: bool = False,
        auto_publish: bool = False,
        keep: bool = False,
        continuous: bool = False,
        interval_minutes: int = 15,
    ) -> Generator[dict[str, Any], None, None]:
        """Stream real-time discovery and audit events across auto-selected repositories."""
        try:
            payload = {
                "limit": limit,
                "cooldown_days": cooldown_days,
                "min_size_kb": min_size_kb,
                "max_size_kb": max_size_kb,
                "language": language,
                "feature_only": feature_only,
                "smart_scan": smart_scan,
                "scan_history": scan_history,
                "auto_publish": auto_publish,
                "keep": keep,
                "continuous": continuous,
                "interval_minutes": interval_minutes,
            }

            with self._client(timeout=httpx.Timeout(self.timeout, read=600.0)) as client:
                with client.stream(
                    "POST",
                    f"{self.base_url}/scan/auto/stream",
                    json=payload,
                ) as response:
                    response.raise_for_status()
                    for line in response.iter_lines():
                        if line:
                            yield json.loads(line)
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Network error during auto scan stream: {e}") from e

    def stop_auto_scan(self) -> dict[str, Any]:
        """Stop any running continuous auto-scan daemon on the server."""
        try:
            with self._client() as client:
                res = client.post(f"{self.base_url}/scan/auto/stop")
                res.raise_for_status()
                return res.json()
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to stop auto scan daemon: {e}") from e

    def trigger_auto_scan(self, **payload: Any) -> dict[str, Any]:
        """Queue an autonomous batch on the server without keeping a stream open."""
        try:
            with self._client() as client:
                response = client.post(f"{self.base_url}/scan/auto", json=payload)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as exc:
            raise PuedoBotClientError(f"Failed to start background auto scan: {exc}") from exc

    def publish_repo_advisory(self, repo_id: int, min_confidence: int = 80) -> dict[str, Any]:
        """Bundle all verified findings for a repository into 1 consolidated issue on GitHub."""
        try:
            with self._client() as client:
                res = client.post(
                    f"{self.base_url}/repositories/{repo_id}/publish",
                    json={"min_confidence": min_confidence},
                )
                res.raise_for_status()
                return res.json()
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", "")
            except Exception:
                detail = e.response.text
            raise PuedoBotClientError(detail or str(e)) from e
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to publish advisory for repo #{repo_id}: {e}") from e

    def get_activity(self) -> dict[str, Any]:
        """Fetch running audits, recent runs, and sent GitHub advisory reports."""
        try:
            with self._client() as client:
                res = client.get(f"{self.base_url}/activity")
                res.raise_for_status()
                return res.json()
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to fetch activity: {e}") from e

    def get_repositories(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch all scanned repositories with finding counts."""
        try:
            with self._client() as client:
                res = client.get(f"{self.base_url}/repositories", params={"limit": limit})
                res.raise_for_status()
                data = res.json()
                return data.get("repositories", [])
        except httpx.HTTPError as e:
            raise PuedoBotClientError(f"Failed to fetch repositories: {e}") from e



