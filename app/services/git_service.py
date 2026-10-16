import os
import shutil
import subprocess
import logging
import time
from enum import Enum
from pathlib import Path
from app.core.scan_process import run_process
from app.core.paths import checked_path, repository_parts
from app.services.scan_lock import RepositoryLease, RepositoryBusyError

logger = logging.getLogger(__name__)


class GitFileStatus(str, Enum):
    TRACKED = "TRACKED"          # Actively committed/staged in git
    GITIGNORED = "GITIGNORED"    # Properly excluded by .gitignore
    UNTRACKED_UNPROTECTED = "UNTRACKED_UNPROTECTED"  # In git repo, but missing from .gitignore
    NOT_A_GIT_REPO = "NOT_A_GIT_REPO"  # Not inside a git repository


class GitService:
    """Helper service to inspect git repository status, manage clones, and enforce cache policies."""

    @staticmethod
    def get_git_status(file_path: str) -> GitFileStatus:
        """Determines the Git tracking and .gitignore status for a given file."""
        file_dir = os.path.dirname(os.path.abspath(file_path))
        if not os.path.exists(file_dir):
            return GitFileStatus.NOT_A_GIT_REPO

        # 1. Check if inside a git work tree
        try:
            res = run_process(
                ["git", "-C", file_dir, "rev-parse", "--is-inside-work-tree"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                return GitFileStatus.NOT_A_GIT_REPO
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Failed to determine git work tree status for '%s': %s", file_dir, exc)
            return GitFileStatus.NOT_A_GIT_REPO

        # 2. Check if the file is tracked in git
        try:
            res_tracked = run_process(
                ["git", "-C", file_dir, "ls-files", "--error-unmatch", file_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res_tracked.returncode == 0:
                return GitFileStatus.TRACKED
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Failed to check if file is tracked '%s': %s", file_path, exc)

        # 3. Check if the file is ignored by .gitignore
        try:
            res_ignored = run_process(
                ["git", "-C", file_dir, "check-ignore", file_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res_ignored.returncode == 0:
                return GitFileStatus.GITIGNORED
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Failed to check git ignore status for '%s': %s", file_path, exc)

        return GitFileStatus.UNTRACKED_UNPROTECTED

    @staticmethod
    def get_repo_root(path: str) -> str | None:
        """Finds the root directory of the git repository containing path."""
        target_dir = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
        if not os.path.exists(target_dir):
            return None
        try:
            res = run_process(
                ["git", "-C", target_dir, "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                return res.stdout.strip()
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Failed to resolve git repo root for '%s': %s", target_dir, exc)
        return None

    @staticmethod
    def get_github_remote(path: str) -> str | None:
        """Extracts 'owner/repo' if the path belongs to a git repository pointing to GitHub."""
        target_dir = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
        if not os.path.exists(target_dir):
            return None

        try:
            res = run_process(
                ["git", "-C", target_dir, "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                return None

            remote_url = res.stdout.strip()
            import re
            match = re.fullmatch(r"git@github\.com:([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?", remote_url)
            if match:
                reference = f"{match.group(1)}/{match.group(2)}"
                try:
                    repository_parts(reference)
                except ValueError:
                    return None
                return reference
            return GitService.normalize_github_target(remote_url)
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Failed to get git remote for '%s': %s", target_dir, exc)
            return None

    @staticmethod
    def normalize_github_target(target: str) -> str | None:
        """Determines if the target string is a GitHub repository reference.
        
        Matches:
        - https://github.com/owner/repo
        - github.com/owner/repo
        - owner/repo (only if it does not exist as a local path)
        
        Returns 'owner/repo' or None.
        """
        import re
        target = target.strip()

        # Check full URL format: https://github.com/owner/repo
        url_match = re.fullmatch(r"(?:https?://)?(?:www\.)?github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git|/)?$", target)
        if url_match:
            reference = f"{url_match.group(1)}/{url_match.group(2)}"
            try:
                repository_parts(reference)
            except ValueError:
                return None
            return reference

        # Check shorthand format: owner/repo
        shorthand_match = re.match(r"^([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+)$", target)
        if shorthand_match and not os.path.exists(target):
            reference = f"{shorthand_match.group(1)}/{shorthand_match.group(2).removesuffix('.git')}"
            try:
                repository_parts(reference)
            except ValueError:
                return None
            return reference

        return None

    @staticmethod
    def get_cache_base_dir() -> Path:
        """Returns the canonical cache directory path for cloned repositories."""
        return Path.home() / ".cache" / "puedobot" / "repos"

    @classmethod
    def clone_github_repo(cls, owner_repo: str, full_history: bool = False) -> str:
        """Shallow clones (depth 1) a GitHub repository into a local cache directory.

        With ``full_history=True`` the clone is deepened to ``HISTORY_MAX_COMMITS`` commits so the
        history scanner can find secrets that were committed and later deleted.

        Returns the absolute local directory path.
        """
        from app.core.config import settings

        repository_parts(owner_repo)
        owner_repo = owner_repo.casefold()
        depth = str(settings.HISTORY_MAX_COMMITS) if full_history else "1"
        cache_base = cls.get_cache_base_dir().resolve()
        target_dir = checked_path(cache_base, Path(owner_repo))
        
        repo_url = f"https://github.com/{owner_repo}.git"

        # Check and enforce cache limits prior to cloning
        cls.enforce_cache_limits()

        if target_dir.exists():
            # Already cached, update shallow branch
            try:
                run_process(
                    ["git", "-C", str(target_dir), "fetch", "--depth", depth, "origin"],
                    capture_output=True,
                    text=True,
                    timeout=180 if full_history else 30,
                    check=True,
                )
                run_process(
                    ["git", "-C", str(target_dir), "reset", "--hard", "FETCH_HEAD"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=True,
                )
                return str(target_dir.resolve())
            except (subprocess.SubprocessError, OSError) as exc:
                logger.warning("Cache update failed for '%s' (%s). Purging and re-cloning.", target_dir, exc)
                cls.cleanup_clone(str(target_dir))

        checked_path(cache_base, target_dir)
        target_dir.parent.mkdir(parents=True, exist_ok=True)
        checked_path(cache_base, target_dir)
        try:
            res = run_process(
                ["git", "clone", "--depth", depth, repo_url, str(target_dir)],
                capture_output=True,
                text=True,
                timeout=300 if full_history else 60,
            )
            if res.returncode != 0:
                error_msg = res.stderr.strip() or "Repository not found or clone failed."
                raise ValueError(f"Failed to clone https://github.com/{owner_repo}: {error_msg}")
        except subprocess.TimeoutExpired as exc:
            cls.cleanup_clone(str(target_dir))
            raise TimeoutError(f"Cloning timed out for {owner_repo}") from exc
        except (subprocess.SubprocessError, OSError) as exc:
            cls.cleanup_clone(str(target_dir))
            raise ValueError(f"Git execution error cloning {owner_repo}: {exc}") from exc

        return str(target_dir.resolve())

    @classmethod
    def cleanup_clone(cls, target_path: str):
        """Safely removes a cloned repository directory after audit if within the cache directory."""
        try:
            target = cls._cache_target(Path(target_path))
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
                logger.info("Cleaned up cloned repository: %s", target)
        except (OSError, ValueError) as exc:
            logger.warning("Failed to cleanup cloned directory '%s': %s", target_path, exc)

    @classmethod
    def _cache_target(cls, target: Path) -> Path:
        base = cls.get_cache_base_dir().resolve()
        relative = target.absolute().relative_to(base)
        repository_parts(relative.as_posix())
        return checked_path(base, target.absolute())

    @classmethod
    def _evict_if_idle(cls, target: Path) -> bool:
        try:
            target = cls._cache_target(target)
            key = target.relative_to(cls.get_cache_base_dir().resolve()).as_posix()
            with RepositoryLease(key):
                # Validate again after acquiring the lease, immediately before removal.
                shutil.rmtree(cls._cache_target(target), ignore_errors=True)
            return True
        except (RepositoryBusyError, OSError, ValueError):
            return False

    @classmethod
    def enforce_cache_limits(cls, max_size_mb: int = 500, max_age_days: int = 7):
        """Evicts oldest cached repositories if cache size exceeds max_size_mb or age exceeds max_age_days."""
        cache_base = cls.get_cache_base_dir().resolve()
        if not cache_base.exists():
            return

        now = time.time()
        max_age_seconds = max_age_days * 86400
        max_bytes = max_size_mb * 1024 * 1024

        # Discover top-level repo folders (owner/repo structure)
        repo_dirs: list[Path] = []
        try:
            for owner in cache_base.iterdir():
                if owner.is_dir() and not owner.is_symlink():
                    for repo in owner.iterdir():
                        if repo.is_dir() and not repo.is_symlink():
                            try:
                                repo_dirs.append(cls._cache_target(repo))
                            except ValueError:
                                continue
        except OSError as exc:
            logger.warning("Error inspecting cache directory '%s': %s", cache_base, exc)
            return

        # 1. Evict based on age
        remaining_repos: list[tuple[Path, float, int]] = []
        for r in repo_dirs:
            try:
                mtime = r.stat().st_mtime
                if now - mtime > max_age_seconds:
                    if cls._evict_if_idle(r):
                        logger.info("Evicted aged cached repo (>%d days): %s", max_age_days, r)
                        continue

                # Calculate directory size
                total_size = sum(f.stat().st_size for f in r.rglob("*") if f.is_file() and not f.is_symlink())
                remaining_repos.append((r, mtime, total_size))
            except OSError:
                continue

        # 2. Evict oldest if total size exceeds limit
        current_total = sum(size for _, _, size in remaining_repos)
        if current_total > max_bytes:
            # Sort by mtime ascending (oldest first)
            remaining_repos.sort(key=lambda item: item[1])
            for r, _, size in remaining_repos:
                if current_total <= max_bytes:
                    break
                if cls._evict_if_idle(r):
                    current_total -= size
                    logger.info("Evicted cached repo to free space: %s (%d bytes)", r, size)
