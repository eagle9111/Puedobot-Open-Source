"""Persist scan progress and read confirmed publication history for the dashboard."""
from __future__ import annotations

import json
import logging
import os
import socket
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

from app.db.models import Repository, ScanRun, Vulnerability
from app.core.pagination import paginate
from app.core.scan_budget import ScanLimitExceeded
from sqlalchemy import func
from app.db.session import SessionLocal

logger = logging.getLogger(__name__)


class ActivityService:
    @staticmethod
    def start(mode: str, target: str) -> int:
        with SessionLocal() as db:
            run = ScanRun(mode=mode, target=target, current_repo=target if mode == "MANUAL" else None,
                          worker_pid=os.getpid(), worker_host=socket.gethostname())
            db.add(run)
            db.commit()
            return run.id

    @staticmethod
    def update(run_id: int, **values: Any) -> None:
        with SessionLocal() as db:
            run = db.get(ScanRun, run_id)
            if run:
                for key, value in values.items():
                    setattr(run, key, value)
                run.updated_at = datetime.now(timezone.utc)
                db.commit()

    @staticmethod
    def repository_status(repo_id: int | None, status: str) -> None:
        if repo_id is None:
            return
        with SessionLocal() as db:
            repo = db.get(Repository, repo_id)
            if repo and repo.status != "published":
                repo.status = status
                db.commit()

    @classmethod
    def finish(cls, run_id: int, status: str, message: str | None = None) -> None:
        cls.update(run_id, status=status, stage=status.replace("_", " ").capitalize(),
                   message=message, finished_at=datetime.now(timezone.utc))

    @classmethod
    def track(cls, run_id: int, events: Iterator[str]) -> Iterator[str]:
        """Observe the worker's events, so progress survives a disconnected viewer."""
        repo_id = None
        last_write = 0.0
        warnings = False
        repo_warnings = False
        partial = False
        partial_message = None
        repo_partial = False
        try:
            for line in events:
                event = json.loads(line)
                kind = event.get("type")
                if event.get("partial"):
                    partial = repo_partial = True
                    partial_message = json.dumps({"reason": event.get("reason"), "counts": event.get("counts", {})})
                    cls.repository_status(repo_id, "partial")
                changes: dict[str, Any] = {}
                if kind == "auto_discovery_start":
                    changes = {"stage": "Discovering repositories"}
                elif kind == "daemon_cycle_start":
                    changes = {"stage": f"Daemon cycle #{event.get('cycle', 1)}", "message": None}
                elif kind == "daemon_sleeping":
                    changes = {
                        "stage": f"Sleeping until {event.get('next_cycle_at')}",
                        "current_repo": None,
                        "current_file": None,
                        "progress": None,
                        "total": None,
                        "message": f"Cycle #{event.get('cycle', 1)} complete; idle for {event.get('interval_minutes')}m",
                    }
                elif kind == "daemon_stopped":
                    changes = {"stage": "Daemon stopped", "message": event.get("message")}
                elif kind == "repo_started":
                    repo_id = None
                    changes = {"stage": "Cloning", "current_repo": event["repo_name"],
                               "repository_id": None, "current_file": None, "progress": None, "total": None}
                elif kind == "start":
                    repo_warnings = False
                    repo_partial = bool(event.get("partial"))
                    repo_id = event.get("repo_id")
                    cls.repository_status(repo_id, "running")
                    changes = {"stage": "Scanning", "repository_id": repo_id}
                elif kind == "scout_started":
                    changes = {"stage": "AI planning"}
                elif kind == "scout_completed":
                    changes = {"stage": "Static analysis"}
                elif kind == "file_scanned" and time.monotonic() - last_write > 2:
                    changes = {"stage": "Static analysis", "current_file": event.get("file")}
                elif kind == "triage_progress":
                    changes = {"stage": "AI verification", "current_file": event.get("file"),
                               "progress": event.get("index"), "total": event.get("total")}
                elif kind == "complete":
                    cls.repository_status(repo_id, "partial" if repo_partial else "completed_with_warnings" if repo_warnings else "completed")
                    changes = {"stage": "Partial" if repo_partial else "Finishing", "current_file": None}
                    if repo_partial:
                        changes["message"] = json.dumps({"reason": event.get("reason"), "counts": event.get("counts", {})})
                elif kind == "repo_completed":
                    changes = {"stage": "Between repositories", "current_repo": None,
                               "repository_id": None, "current_file": None, "progress": None, "total": None}
                    repo_id = None
                elif kind == "repo_advisory_reported":
                    changes = {"stage": "Report sent", "message": event.get("issue_url")}
                elif kind in {"repo_clone_error", "triage_error"}:
                    warnings = True
                    repo_warnings = True
                    changes = {"message": event.get("error")}
                elif kind == "engine_notice":
                    message = event.get("message", "")
                    if any(part in message for part in ("failed", "skipped for", "Discovery failed")):
                        warnings = True
                        changes = {"message": message}
                        cls.repository_status(repo_id, "failed")
                if changes:
                    cls.update(run_id, **changes)
                    last_write = time.monotonic()
                yield line
            cls.finish(run_id, "partial" if partial else "completed_with_warnings" if warnings else "completed", partial_message)
        except ScanLimitExceeded as exc:
            cls.repository_status(repo_id, "partial")
            cls.finish(run_id, "partial", json.dumps({"reason": exc.reason}))
            yield json.dumps({"type": "engine_notice", "partial": True, "reason": exc.reason,
                              "message": f"Partial audit: {exc.reason}"}) + "\n"
            yield json.dumps({"type": "complete", "partial": True, "reason": exc.reason,
                              "repo_id": repo_id, "total_files": 0, "confirmed_vulnerabilities": 0}) + "\n"
        except Exception as exc:
            cls.repository_status(repo_id, "failed")
            cls.finish(run_id, "failed", str(exc))
            raise
        finally:
            close = getattr(events, "close", None)
            if close:
                close()

    @staticmethod
    def snapshot(running_limit: int = 100, recent_limit: int = 20, reports_limit: int = 50,
                 running_cursor: str | None = None, recent_cursor: str | None = None,
                 reports_cursor: str | None = None) -> dict[str, Any]:
        with SessionLocal() as db:
            running_query = db.query(ScanRun).filter(ScanRun.status == "running")
            running, running_page = paginate(running_query, (ScanRun.started_at, ScanRun.id),
                                            limit=running_limit, cursor=running_cursor, scope="activity:running")
            for run in running:
                if run.worker_host == socket.gethostname():
                    try:
                        os.kill(run.worker_pid, 0)
                    except ProcessLookupError:
                        run.status = "interrupted"
                        run.stage = "Interrupted by server shutdown"
                        run.finished_at = datetime.now(timezone.utc)
                        repo = db.get(Repository, run.repository_id) if run.repository_id else None
                        if repo and repo.status == "running":
                            repo.status = "interrupted"
                    except PermissionError:
                        pass
            db.commit()
            # Re-page after interrupted-state transitions so counts/rows agree.
            if any(run.status != "running" for run in running):
                running, running_page = paginate(running_query, (ScanRun.started_at, ScanRun.id),
                                                limit=running_limit, cursor=running_cursor, scope="activity:running")
            recent, recent_page = paginate(db.query(ScanRun).filter(ScanRun.status != "running"),
                                          (ScanRun.started_at, ScanRun.id), limit=recent_limit,
                                          cursor=recent_cursor, scope="activity:recent")
            def serialize(run: ScanRun) -> dict[str, Any]:
                return {key: (value.isoformat() if isinstance(value, datetime) else value)
                        for key, value in run.__dict__.items()
                        if not key.startswith("_") and key not in {"worker_pid", "worker_host"}}
            groups = (db.query(Vulnerability.github_issue_url.label("url"),
                               func.count(Vulnerability.id).label("findings_count"),
                               func.max(Vulnerability.id).label("newest_id"))
                      .filter(Vulnerability.github_issue_url.isnot(None), Vulnerability.github_issue_url != "")
                      .group_by(Vulnerability.github_issue_url).subquery())
            query = (db.query(groups.c.url, groups.c.findings_count, groups.c.newest_id,
                              Repository.repo_name, Repository.target_path,
                              Repository.id.label("repository_id"), Repository.scan_mode)
                     .join(Vulnerability, Vulnerability.id == groups.c.newest_id)
                     .join(Repository, Repository.id == Vulnerability.repository_id))
            reports, reports_page = paginate(query, (groups.c.newest_id,), limit=reports_limit,
                                            cursor=reports_cursor, scope="activity:reports")
            return {"running": [serialize(run) for run in running],
                    "recent_runs": [serialize(run) for run in recent],
                    "reports": [{"url": row.url, "repo_name": row.repo_name or row.target_path,
                                 "repository_id": row.repository_id, "scan_mode": row.scan_mode.value,
                                 "findings_count": row.findings_count} for row in reports],
                    "reports_count": reports_page["total"], "running_pagination": running_page,
                    "recent_pagination": recent_page, "reports_pagination": reports_page}
