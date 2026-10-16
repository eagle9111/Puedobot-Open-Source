"""Repository routes: CRUD endpoints for tracked codebases."""
from fastapi import APIRouter, HTTPException, Query

from app.services.repository_service import RepositoryService
from app.core.pagination import InvalidCursor

router = APIRouter(prefix="/repositories", tags=["Repositories"])


@router.get("")
@router.get("/")
def list_repositories(limit: int = Query(100, ge=1, le=200), cursor: str | None = None):
    """List all scanned repositories with vulnerability counts."""
    try:
        return RepositoryService.repository_page(limit, cursor)
    except InvalidCursor as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@router.get("/{repo_id}")
def get_repository(repo_id: int, findings_limit: int = Query(100, ge=1, le=200), findings_cursor: str | None = None):
    """Get single repository details and all its findings."""
    try:
        repo = RepositoryService.get_repository(repo_id, findings_limit, findings_cursor)
    except InvalidCursor as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if not repo:
        raise HTTPException(status_code=404, detail=f"Repository #{repo_id} not found.")
    return {"repository": repo}


@router.delete("/{repo_id}")
def delete_repository(repo_id: int):
    """Delete a repository and its findings from the database."""
    deleted = RepositoryService.delete_repository(repo_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Repository #{repo_id} not found.")
    return {"success": True, "message": f"Repository #{repo_id} deleted."}


from pydantic import BaseModel, Field


class PublishAdvisoryRequest(BaseModel):
    min_confidence: int = Field(80, ge=0, le=100)


@router.post("/{repo_id}/publish")
def publish_repository_advisory(repo_id: int, request: PublishAdvisoryRequest = PublishAdvisoryRequest()):
    """Bundle all verified findings for a repository into ONE consolidated security issue on GitHub."""
    from app.services.vulnerability_service import VulnerabilityService
    try:
        result = VulnerabilityService.publish_repository_advisory(
            repo_id=repo_id,
            min_confidence=request.min_confidence,
        )
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("message"))
        return result
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

