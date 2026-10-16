"""Tests for secret detection, placeholder exclusion, redaction, and issue sanitization."""
import pytest
from app.engine.secret_scanner import detect_secret_in_line, redact_secrets
from app.services.github_service import sanitize_issue_content


def test_detect_secrets_real_patterns():
    """Verify detection of various real credential patterns."""
    # AWS Key (20 chars: AKIA + 16 chars)
    aws_line = "AWS_KEY = 'AKIA1234567890ABCDEF'"
    hit = detect_secret_in_line(aws_line)
    assert hit is not None
    assert hit[0] == "AWS Access Key"

    # Database URI
    db_line = "URI = 'postgresql://admin:Sup3rS3cret@db.internal:5432/prod'"
    hit = detect_secret_in_line(db_line)
    assert hit is not None
    assert hit[0] == "Database Credentials URI"

    # GitHub Personal Token (ghp_ + 36 chars)
    gh_line = "TOKEN = 'ghp_" + "a" * 36 + "'"
    hit = detect_secret_in_line(gh_line)
    assert hit is not None
    assert hit[0] == "GitHub Personal Token"


def test_ignore_dummy_placeholders():
    """Verify documented example keys and generic placeholders are ignored."""
    # AWS documentation sample key
    assert detect_secret_in_line("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'") is None

    # Generic placeholders
    assert detect_secret_in_line("password = 'changeme'") is None
    assert detect_secret_in_line("secret = 'placeholder'") is None
    assert detect_secret_in_line("db_password = 'your_password'") is None


def test_redact_secrets_masks_credentials():
    """Verify sensitive values are masked before publishing."""
    text = "Found AWS key AKIA1234567890ABCDEF in config.py"
    redacted = redact_secrets(text)
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "AKIA********" in redacted


def test_sanitize_issue_content_comprehensive():
    """Verify that untrusted input is safely sanitized before issue creation."""
    raw = (
        "Ping @octocat and @security-team! "
        "![PoC Tracker](https://attacker.com/poc.png) "
        "Check [Exploit Details](https://attacker.com/exploit.html). "
        "<script>window.location='http://evil.com'</script>"
        "<iframe src='http://evil.com'></iframe>"
    )
    clean = sanitize_issue_content(raw, max_length=1000)

    # 1. Mentions neutralized with zero-width space
    assert "@octocat" not in clean
    assert "@\u200boctocat" in clean
    assert "@\u200bsecurity-team" in clean

    # 2. Markdown images neutralized
    assert "![" not in clean
    assert "[image removed: PoC Tracker]" in clean

    # 3. Markdown links neutralized to plain text
    assert "](https:" not in clean
    assert "Exploit Details (https://attacker.com/exploit.html)" in clean

    # 4. Dangerous HTML tags removed
    assert "<script>" not in clean
    assert "<iframe" not in clean
