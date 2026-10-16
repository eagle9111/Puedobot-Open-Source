"""Global project constants, file extensions, and path exclusion boundaries."""

# Directories ignored to prevent false positives, test code contamination, and bloated scans
IGNORED_DIRS = {
    ".venv", "venv", "env",
    ".git", ".github",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", "dist", "build",
    "tests", "test",
    "alembic", "migrations",
}

# Supported configuration and secret targets
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json", ".sql", ".toml", ".ini", ".conf"}
CONFIG_EXACT_NAMES = {"Dockerfile"}

# Lockfiles and template files ignored to avoid false alerts
IGNORED_FILES = {
    ".env.example", ".env.sample", ".env.template",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"
}

# Directories deliberately skipped during Agent Scout discovery
NON_FEATURE_DIRS = {
    "docs", "doc", "documentation",
    "examples", "example", "samples", "sample",
    "scripts", "tools", "util", "utils",
    "tests", "test", "testing",
    "benchmarks", "fixtures",
    ".github", ".vscode", ".idea",
}

FEATURE_DIR_KEYWORDS = {
    "api", "routes", "routers", "controllers", "views", "handlers",
    "services", "endpoints", "auth", "billing", "models", "app", "src", "core"
}


def is_scannable_file(filename: str) -> bool:
    """Determine if a file is relevant for security/secret auditing."""
    if filename in IGNORED_FILES or filename.endswith(".lock"):
        return False

    # Python source files
    if filename.endswith(".py"):
        return True

    # Environment variable files (.env, .env.local, .env.production, etc.)
    if filename.startswith(".env") and not (filename.endswith(".example") or filename.endswith(".sample")):
        return True

    # Configuration files
    if any(filename.endswith(ext) for ext in CONFIG_EXTENSIONS):
        return True

    # Docker / container specifications
    if filename in CONFIG_EXACT_NAMES or filename.startswith("docker-compose"):
        return True

    return False
