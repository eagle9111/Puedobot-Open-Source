"""Repository Service: Manages repository records, CRUD, and spam cooldown tracking."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import func
from app.core.pagination import paginate
from calendar import monthrange
from app.db.session import SessionLocal
from app.db.models import Repository, Vulnerability
from app.schemas.scan import ScanMode

logger = logging.getLogger(__name__)


class RepositoryService:
    """Encapsulates all database operations and business logic for repositories."""

    @staticmethod
    def list_repositories() -> list[dict[str, Any]]:
        return RepositoryService.repository_page()["repositories"]

    @staticmethod
    def repository_page(limit: int = 100, cursor: str | None = None) -> dict[str, Any]:
        """Bounded repositories and SQL counts, including empty repositories."""
        with SessionLocal() as db:
            counts = db.query(Vulnerability.repository_id.label("repository_id"),
                              func.count(Vulnerability.id).label("count")).group_by(Vulnerability.repository_id).subquery()
            repos = (db.query(Repository, func.coalesce(counts.c.count, 0))
                     .outerjoin(counts, counts.c.repository_id == Repository.id)
                     )
            repos, pagination = paginate(repos, (Repository.scanned_at, Repository.id),
                                         limit=limit, cursor=cursor, scope="repositories",
                                         key=lambda row: (row[0].scanned_at, row[0].id))
            results = []
            for r, findings_count in repos:

                results.append({
                    "id": r.id,
                    "target_path": r.target_path,
                    "repo_name": r.repo_name or r.target_path.split("/")[-1],
                    "size_kb": r.size_kb,
                    "stars": r.stars,
                    "status": r.status,
                    "scan_mode": r.scan_mode.value if hasattr(r.scan_mode, "value") else str(r.scan_mode),
                    "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
                    "findings_count": findings_count,
                })
            return {"repositories": results, "pagination": pagination}

    @staticmethod
    def get_repository(repo_id: int, findings_limit: int = 100, findings_cursor: str | None = None) -> dict[str, Any] | None:
        """Fetch a single repository by ID with its list of findings."""
        with SessionLocal() as db:
            repo = db.query(Repository).filter(Repository.id == repo_id).first()
            if not repo:
                return None

            rows, pagination = paginate(db.query(Vulnerability).filter(Vulnerability.repository_id == repo_id),
                                        (Vulnerability.id,), limit=findings_limit, cursor=findings_cursor,
                                        scope=f"repository-findings:{repo_id}", descending=False)
            findings = [
                {k: v for k, v in f.__dict__.items() if not k.startswith("_")}
                for f in rows
            ]

            return {
                "id": repo.id,
                "target_path": repo.target_path,
                "repo_name": repo.repo_name,
                "size_kb": repo.size_kb,
                "stars": repo.stars,
                "status": repo.status,
                "scan_mode": repo.scan_mode.value if hasattr(repo.scan_mode, "value") else str(repo.scan_mode),
                "scanned_at": repo.scanned_at.isoformat() if repo.scanned_at else None,
                "findings": findings,
                "findings_pagination": pagination,
            }

    @staticmethod
    def delete_repository(repo_id: int) -> bool:
        """Delete repository and cascade-delete all associated findings."""
        with SessionLocal() as db:
            repo = db.query(Repository).filter(Repository.id == repo_id).first()
            if not repo:
                return False
            db.delete(repo)
            db.commit()
            return True

    @staticmethod
    def check_cooldown(repo_name: str, cooldown_days: int, pushed_at: str | None = None) -> tuple[bool, str | None]:
        """Check if a repository was audited within the cooldown window.
        
        Returns:
            (is_eligible, cooldown_reason)
        """
        now = datetime.now(timezone.utc)
        month_index = now.year * 12 + now.month - 1 - 6
        year, month_zero = divmod(month_index, 12)
        month = month_zero + 1
        six_months_ago = now.replace(
            year=year, month=month, day=min(now.day, monthrange(year, month)[1])
        )
        cutoff = min(now - timedelta(days=max(180, cooldown_days)), six_months_ago)
        with SessionLocal() as db:
            existing = (
                db.query(Repository)
                .filter(func.lower(Repository.repo_name) == repo_name.casefold())
                .order_by(Repository.scanned_at.desc())
                .first()
            )
            if existing:
                scanned_at = existing.scanned_at
                if scanned_at.tzinfo is None:
                    scanned_at = scanned_at.replace(tzinfo=timezone.utc)
                if scanned_at >= cutoff:
                    return False, "Audited recently (minimum cooldown: six months)"
                if not pushed_at:
                    return False, "Cannot confirm new pushes since the previous audit"
                if pushed_at:
                    pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    if pushed <= scanned_at:
                        return False, "No new pushes since the previous audit"
            return True, None

    @staticmethod
    def create_repository(
        target_path: str,
        repo_name: str | None = None,
        size_kb: int | None = None,
        stars: int | None = None,
        scan_mode: ScanMode = ScanMode.MANUAL,
    ) -> int:
        """Create a new repository record and return its ID."""
        with SessionLocal() as db:
            repo = Repository(
                target_path=target_path,
                repo_name=repo_name,
                size_kb=size_kb,
                stars=stars,
                scan_mode=scan_mode,
            )
            db.add(repo)
            db.commit()
            db.refresh(repo)
            return repo.id
