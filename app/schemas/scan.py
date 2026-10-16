import enum
from pydantic import BaseModel, Field


class ScanMode(str, enum.Enum):
    """Scan execution mode."""
    MANUAL = "MANUAL"
    AUTO = "AUTO"


class ScanRequest(BaseModel):
    """Payload to trigger a repository scan."""
    target_path: str = Field(..., description="Target filesystem path or repository path to scan")
    scan_history: bool = Field(False, description="Also search past git commits for secrets that were later deleted")
    smart_scan: bool = Field(True, description="Enable AI Agent Scout to dynamically choose high-risk attack surface files")
    keep: bool = Field(False, description="Preserve cloned remote repositories in cache after audit")


class ScanResponse(BaseModel):
    """Response returned upon triggering a scan."""
    status: str
    repo_id: int
    message: str


class AutoCandidate(BaseModel):
    """Candidate repository discovered from GitHub."""
    full_name: str
    clone_url: str
    html_url: str
    size_kb: int = 0
    stars: int = 0
    pushed_at: str | None = None
    created_at: str | None = None
    description: str = ""
    is_eligible: bool = True
    cooldown_reason: str | None = None


class AutoScanRequest(BaseModel):
    """Request payload to discover and audit candidate repositories automatically."""
    limit: int = Field(3, ge=1, le=30, description="Number of candidate repositories to audit")
    cooldown_days: int = Field(180, ge=180, description="Minimum days between audits of the same repo")
    min_size_kb: int = Field(10, description="Minimum repository size in KB")
    max_size_kb: int = Field(5000, description="Maximum repository size in KB (small repos first)")
    language: str = Field("python", description="Target repository primary language")
    feature_only: bool = Field(True, description="Focus on core feature files (routes, API, controllers)")
    smart_scan: bool = Field(True, description="Enable AI Agent Scout to dynamically choose high-risk attack surface files")
    scan_history: bool = Field(False, description="Scan commit history for deleted secrets")
    auto_publish: bool = Field(False, description="Automatically submit verified findings in 1 consolidated issue on GitHub")
    keep: bool = Field(False, description="Preserve cloned remote repositories in cache after audit")
    continuous: bool = Field(False, description="Run indefinitely in daemon mode, sleeping between discovery batches")
    interval_minutes: int = Field(15, ge=1, le=1440, description="Sleep interval in minutes between discovery cycles when running in continuous daemon mode")

