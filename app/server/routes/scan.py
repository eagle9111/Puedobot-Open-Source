"""Scan routes: Endpoints for manual repository scanning."""
import json
import logging
import os
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import StreamingResponse
from starlette.concurrency import iterate_in_threadpool

from app.schemas.scan import ScanMode, ScanRequest, ScanResponse
from app.services.git_service import GitService
from app.services.repository_service import RepositoryService
from app.services.scan_worker import scan_events as stream_scan_pipeline, supervised_call
from app.services.scan_admission import admit_scan, own_events, schedule_job, CURRENT_JOB
from app.core.scan_budget import ScanLimitExceeded
from app.core.config import settings

from app.services.scan_lock import RepositoryLease, RepositoryBusyError
from app.services.scan_stream import server_owned_scan_stream, ScanStreamHub
from app.services.activity_service import ActivityService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scan", tags=["Scanning"])


def _resolve_server_target(target_path: str, scan_history: bool = False) -> tuple[str, str | None]:
    """Resolves target: clones GitHub repository if remote reference, else validates local path against allowed boundaries."""
    from pathlib import Path
    from app.core.config import settings

    gh_target = GitService.normalize_github_target(target_path)
    if gh_target:
        try:
            job = CURRENT_JOB.get()
            cloned = supervised_call(GitService.clone_github_repo, gh_target, full_history=scan_history,
                                     seconds=job.remaining() if job else settings.SCAN_SECONDS)
            return cloned, gh_target
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"GitHub Error: {e}")

    # Resolve canonical target path (resolving any .. and symlinks)
    target = Path(target_path).resolve()
    if not target.exists():
        raise HTTPException(status_code=400, detail="Target path does not exist.")

    # Determine allowed boundary roots
    raw_roots = settings.PUEDOBOT_ALLOWED_ROOTS.strip()
    if raw_roots:
        allowed_roots = [Path(r.strip()).resolve() for r in raw_roots.split(",") if r.strip()]
    else:
        # Default boundary: project directory and cached repos directory
        allowed_roots = [
            Path.cwd().resolve(),
            Path.home().resolve() / ".cache" / "puedobot",
        ]

    is_allowed = any(target == root or target.is_relative_to(root) for root in allowed_roots)
    if not is_allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Path '{target_path}' is outside permitted scanning boundaries."
        )

    return str(target), None


def _claim_target(request: ScanRequest) -> tuple[str, str | None, RepositoryLease]:
    from pathlib import Path

    key = GitService.normalize_github_target(request.target_path)
    if key is None:
        target = Path(request.target_path).resolve()
        cache = GitService.get_cache_base_dir().resolve()
        relative = target.relative_to(cache) if target.is_relative_to(cache) else None
        key = relative.as_posix() if relative and len(relative.parts) == 2 else str(target)
    try:
        lease = RepositoryLease(key)
    except RepositoryBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        path, name = _resolve_server_target(request.target_path, request.scan_history)
        return path, name, lease
    except BaseException:
        lease.release()
        raise


def run_scan_pipeline(
    target_path: str,
    repo_id: int,
    scan_history: bool = False,
    keep: bool = False,
    is_remote: bool = False,
    smart_scan: bool = True,
    lease: RepositoryLease | None = None,
    run_id: int | None = None,
    job=None,
    repo_name: str | None = None,
):
    """Background task to run the LangGraph orchestrator."""
    logger.info(f"Starting background scan for repo {repo_id}")
    try:
        if run_id is not None:
            ActivityService.update(run_id, stage="Scanning", repository_id=repo_id)
        ActivityService.repository_status(repo_id, "running")
        token = CURRENT_JOB.set(job)
        try:
            events = (json.dumps(event) + "\n" for event in stream_scan_pipeline(
                target_path, repo_id, scan_history=scan_history, smart_scan=smart_scan,
                repo_name=repo_name,
                seconds=job.remaining() if job else settings.SCAN_SECONDS))
            if run_id is not None:
                for _ in ActivityService.track(run_id, events):
                    pass
            else:
                for _ in events:
                    pass
        finally:
            CURRENT_JOB.reset(token)
    except ScanLimitExceeded as exc:
        ActivityService.repository_status(repo_id, "partial")
        if run_id is not None:
            ActivityService.finish(run_id, "partial", exc.reason)
    except Exception as e:
        logger.error(f"Error in scan pipeline: {e}")
        ActivityService.repository_status(repo_id, "failed")
        if run_id is not None:
            ActivityService.finish(run_id, "failed", str(e))
    finally:
        try:
            if not keep and is_remote:
                GitService.cleanup_clone(target_path)
        finally:
            if lease:
                lease.release()
            if job:
                job.release()


@router.post("/stream")
@admit_scan
def trigger_scan_stream(request: ScanRequest):
    """Start a server-owned audit and stream progress without tying work to the client."""
    run_id = ActivityService.start("MANUAL", request.target_path)
    try:
        ActivityService.update(run_id, stage="Preparing checkout")
        target_path, repo_name, lease = _claim_target(request)
    except ScanLimitExceeded as exc:
        ActivityService.finish(run_id, "partial", exc.reason)
        raise HTTPException(408, f"Partial preparation: {exc.reason}") from None
    except Exception as exc:
        ActivityService.finish(run_id, "failed", str(exc))
        raise

    try:
        repo_id = RepositoryService.create_repository(
            target_path=target_path,
            repo_name=repo_name,
            scan_mode=ScanMode.MANUAL,
        )
    except BaseException:
        ActivityService.finish(run_id, "failed", "Could not create repository record")
        lease.release()
        raise

    def event_generator():
        try:
            for event in stream_scan_pipeline(
                target_path,
                repo_id,
                scan_history=request.scan_history,
                smart_scan=request.smart_scan,
                repo_name=repo_name,
                seconds=CURRENT_JOB.get().remaining() if CURRENT_JOB.get() else settings.SCAN_SECONDS,
            ):
                if repo_name and not event.get("repo_name"):
                    event["repo_name"] = repo_name
                yield json.dumps(event) + "\n"
        finally:
            try:
                if not request.keep and repo_name:
                    GitService.cleanup_clone(target_path)
            finally:
                lease.release()

    progress = server_owned_scan_stream(own_events(ActivityService.track(run_id, event_generator())), name=f"scan-{repo_id}", run_id=run_id)
    return StreamingResponse(iterate_in_threadpool(progress), media_type="application/x-ndjson")


@router.get("/stream/status")
def get_stream_status():
    """Check if an audit stream is active or recently buffered."""
    active = ScanStreamHub.get_active()
    if not active:
        return {"active": False, "finished": True, "message": "No active scan stream."}
    return {
        "active": not active.finished,
        "finished": active.finished,
        "name": active.name,
        "run_id": active.run_id,
        "events_buffered": len(active.history),
    }


@router.get("/stream/active")
def reattach_active_stream():
    """Reattach to the currently active or recent audit stream with history replay."""
    active = ScanStreamHub.get_active()
    if not active:
        raise HTTPException(status_code=404, detail="No active scan stream available.")
    return StreamingResponse(
        iterate_in_threadpool(active.subscribe(replay_history=True)),
        media_type="application/x-ndjson",
    )


@router.get("/stream/{run_id}")
def reattach_run_stream(run_id: int):
    """Reattach to a specific scan stream by run ID with history replay."""
    stream = ScanStreamHub.get_by_run_id(run_id)
    if not stream:
        raise HTTPException(status_code=404, detail=f"No scan stream found for run #{run_id}.")
    return StreamingResponse(
        iterate_in_threadpool(stream.subscribe(replay_history=True)),
        media_type="application/x-ndjson",
    )



@router.post("")
@router.post("/")
@admit_scan
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Trigger an asynchronous scan executed in the background."""
    run_id = ActivityService.start("MANUAL", request.target_path)
    try:
        ActivityService.update(run_id, stage="Preparing checkout")
        target_path, repo_name, lease = _claim_target(request)
    except ScanLimitExceeded as exc:
        ActivityService.finish(run_id, "partial", exc.reason)
        raise HTTPException(408, f"Partial preparation: {exc.reason}") from None
    except Exception as exc:
        ActivityService.finish(run_id, "failed", str(exc))
        raise

    try:
        repo_id = RepositoryService.create_repository(
            target_path=target_path,
            repo_name=repo_name,
            scan_mode=ScanMode.MANUAL,
        )
    except BaseException:
        lease.release()
        raise

    schedule_job(background_tasks,
        run_scan_pipeline,
        target_path,
        repo_id,
        request.scan_history,
        keep=request.keep,
        is_remote=bool(repo_name),
        smart_scan=request.smart_scan,
        lease=lease,
        run_id=run_id,
        repo_name=repo_name,
    )
    return ScanResponse(
        repo_id=repo_id,
        status="Scanning initiated",
        message="Scan running in background on server.",
    )
