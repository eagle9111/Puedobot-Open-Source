"""Authenticated, bounded execution status and sent report history."""
from fastapi import APIRouter, HTTPException, Query
from app.services.activity_service import ActivityService
from app.core.pagination import InvalidCursor

router = APIRouter(prefix="/activity", tags=["Activity"])


@router.get("")
def get_activity(running_limit: int = Query(100, ge=1, le=200),
                 recent_limit: int = Query(20, ge=1, le=200),
                 reports_limit: int = Query(50, ge=1, le=200),
                 running_cursor: str | None = None, recent_cursor: str | None = None,
                 reports_cursor: str | None = None):
    try:
        return ActivityService.snapshot(running_limit, recent_limit, reports_limit,
                                        running_cursor, recent_cursor, reports_cursor)
    except InvalidCursor as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
