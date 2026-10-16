import enum
from pydantic import BaseModel, Field


class SeverityLevel(str, enum.Enum):
    """Vulnerability risk severity level."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, enum.Enum):
    """Vulnerability review and triage lifecycle status."""
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PUBLISHED = "PUBLISHED"


VERIFICATION_UNAVAILABLE_NOTE = "[verification=unavailable] AI verification did not complete; manual review required."


def verification_unavailable(note: str | None) -> bool:
    """Recognize explicit failure state and notes written before this safeguard.

    Use the existing persisted note field so this correction needs no schema
    migration. Legacy failure text may follow other deterministic check notes.
    """
    return bool(note and (
        "[verification=unavailable]" in note
        or "Verifier unavailable; confidence is from triage only." in note
    ))


class SecurityTriageResult(BaseModel):
    """The strict JSON format the LLM must return after analyzing code."""

    is_vulnerable: bool = Field(
        description="True if the code actually contains an exploitable flaw. False if it is safe or a false positive."
    )
    severity: SeverityLevel = Field(
        description="The severity of the issue. Use INFO or LOW for false positives."
    )
    vulnerability_type: str = Field(
        description="Short category name, e.g., 'SQL Injection' or 'Command Injection'."
    )
    description: str = Field(
        description="Technical explanation of the vulnerability and how untrusted data reaches the sink."
    )
    remediation: str = Field(
        description="How the developer should fix it (e.g., 'Use parameterized queries')."
    )
    confidence: int = Field(
        description=(
            "0-100 certainty that this is a real, exploitable flaw. 90+ only when you can name the exact "
            "attacker-controlled input and show it reaches the sink unsanitized. Use <50 when unsure."
        )
    )
    input_source: str = Field(
        description=(
            "Where the untrusted data comes from (e.g. 'Flask request.args[\"q\"]', 'function parameter "
            "user_command reachable from POST /backup'). Write 'N/A' for hardcoded secrets or false positives."
        )
    )
    exploit_payload: str = Field(
        description=(
            "A concrete example input an attacker would send and the effect it has. "
            "Write 'N/A' if the finding is a false positive."
        )
    )


class VerificationResult(BaseModel):
    """Output of the skeptical second pass that tries to REFUTE a finding."""

    refuted: bool = Field(
        description="True if the finding is a false positive or not realistically exploitable."
    )
    confidence: int = Field(
        ge=0,
        le=100,
        description="0-100 certainty that the finding is REAL after trying hard to disprove it."
    )
    reasoning: str = Field(
        min_length=1,
        description="One or two sentences: the strongest argument for or against the finding."
    )
