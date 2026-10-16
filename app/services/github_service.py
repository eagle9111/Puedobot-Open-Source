"""Open-source compatibility shim for GitHub service."""
from app.services.github_sanitizer import sanitize_issue_content


class GitHubServiceError(Exception):
    """Raised when private GitHub advisory actions are called in Core."""
    pass


class GitHubService:
    """Stub for GitHub advisory operations in open-source Core."""
    def __init__(self, *args, **kwargs):
        pass

    def publish_advisory(self, *args, **kwargs):
        raise GitHubServiceError("GitHub advisory publishing is not available in PuedoBot Core.")

    def search_candidate_repositories(self, *args, **kwargs):
        raise GitHubServiceError("Automated candidate search is not available in PuedoBot Core.")


__all__ = ["sanitize_issue_content", "GitHubService", "GitHubServiceError"]
