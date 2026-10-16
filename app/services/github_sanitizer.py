"""Sanitization logic for untrusted codebase content before publishing to GitHub."""
from __future__ import annotations

import re
from app.engine.secret_scanner import redact_secrets


def sanitize_issue_content(text: str | None, max_length: int = 4000) -> str:
    """Sanitizes untrusted text originating from audited codebases before posting to GitHub:
    - Neutralizes @mentions by inserting a zero-width space (@user -> @\\u200buser).
    - Neutralizes markdown images (![alt](url) -> [image removed: alt]).
    - Neutralizes markdown links ([text](url) -> text (url)).
    - Neutralizes raw HTML tags (<script>, <iframe>, <img>, etc.).
    - Redacts sensitive credentials via redact_secrets.
    - Caps length at max_length characters with an explicit truncation indicator.
    """
    if not text:
        return ""

    cleaned = redact_secrets(str(text))

    # 1. Neutralize @mentions (@username, @org, @everyone, @here)
    cleaned = re.sub(r"@([a-zA-Z0-9_\-]+)", "@\u200b\\g<1>", cleaned)

    # 2. Neutralize markdown images: ![alt](url) -> [image removed: alt]
    cleaned = re.sub(r"!\[([^\[\]]*)\]\(([^()]*)\)", r"[image removed: \1]", cleaned)

    # 3. Neutralize markdown links: [label](url) -> label (url)
    cleaned = re.sub(r"\[([^\[\]]+)\]\(([^()]+)\)", r"\1 (\2)", cleaned)

    # 4. Neutralize potentially harmful HTML elements
    cleaned = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", "[script removed]", cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<\s*/?\s*(?:iframe|img|embed|object|link|meta|base)[^>]*>", "[html element removed]", cleaned, flags=re.IGNORECASE)

    # 5. Length cap
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + f"\n... [Truncated: exceeded {max_length} characters]"

    return cleaned
