"""Findings inspection, review, status mutation, and GitHub publication routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.services.vulnerability_service import VulnerabilityService
from app.core.pagination import InvalidCursor

router = APIRouter(prefix="/errors", tags=["Findings Review"])


class PushRequest(BaseModel):
    approved: bool
    publish_to_github: bool = False


class StatusUpdateRequest(BaseModel):
    status: str


@router.get("")
@router.get("/")
def get_errors(
    status: str = "pending",
    repository_id: int | None = Query(None, description="Optional repo ID filter"),
    limit: int = Query(100, ge=1, le=200),
    cursor: str | None = None,
):
    """Fetch findings filtered by status and optional repository ID."""
    try:
        return VulnerabilityService.finding_page(status, repository_id, limit, cursor)
    except InvalidCursor as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.get("/{finding_id}")
def get_single_error(finding_id: int):
    """Fetch single finding details."""
    finding = VulnerabilityService.get_vulnerability(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding #{finding_id} not found.")
    return {"finding": finding}


@router.patch("/{finding_id}")
def update_error_status(finding_id: int, request: StatusUpdateRequest):
    """Update finding status directly (e.g. APPROVED, REJECTED, PENDING_REVIEW)."""
    updated = VulnerabilityService.update_status(finding_id, request.status)
    if not updated:
        raise HTTPException(status_code=400, detail="Invalid status or finding not found.")
    return {"success": True, "message": f"Finding #{finding_id} status updated to {request.status}."}


@router.delete("/{finding_id}")
def delete_error(finding_id: int):
    """Delete a finding from the database."""
    deleted = VulnerabilityService.delete_vulnerability(finding_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Finding #{finding_id} not found.")
    return {"success": True, "message": f"Finding #{finding_id} deleted."}


@router.post("/{finding_id}/push")
def review_or_publish_error(finding_id: int, request: PushRequest):
    """Review and confirm/reject a finding, optionally publishing it to GitHub."""
    try:
        result = VulnerabilityService.submit_review(
            vuln_id=finding_id,
            approved=request.approved,
            publish_to_github=request.publish_to_github,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
