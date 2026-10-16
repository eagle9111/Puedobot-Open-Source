"""Lightweight compatibility shim: exports text sanitization utilities."""
from app.services.github_sanitizer import sanitize_issue_content

__all__ = ["sanitize_issue_content"]
