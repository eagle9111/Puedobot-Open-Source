from pydantic import BaseModel, Field


class FileScoutPlan(BaseModel):
    """Structured plan produced by the AI Agent Scout after analyzing repository tree."""

    selected_files: list[str] = Field(
        ...,
        description="List of relative file paths that should be prioritized for security auditing.",
    )
    rationale: str = Field(
        ...,
        description="Architectural rationale explaining why these files and modules were selected based on the repository structure.",
    )
    identified_attack_surfaces: list[str] = Field(
        default_factory=list,
        description="Key attack surfaces discovered in the repository (e.g., 'FastAPI route endpoints', 'Payment processing handlers', 'Auth middleware', 'SQL query builder').",
    )
    skipped_areas: list[str] = Field(
        default_factory=list,
        description="Low-risk areas skipped to conserve audit bandwidth (e.g., 'Unit test suite in tests/', 'Documentation generators in docs/').",
    )
