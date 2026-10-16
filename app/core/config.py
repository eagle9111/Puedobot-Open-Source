from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "puedobot"
    DEBUG: bool = False

    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "puedobot"


    # Universal AI Configuration (Cloud / Remote)
    AI_API_KEY: str | None = None
    AI_API_URL: str | None = None
    MODEL_NAME: str = "gemini-2.5-flash"

    # Local AI Configuration (Ollama / vLLM)
    LOCAL_AI_URL: str = "http://127.0.0.1:11434/v1"
    LOCAL_AI_MODEL: str = "qwen2.5-coder:7b"
    LOCAL_AI_API_KEY: str = "ollama"

    # Priority Routing: "cloud" (Cloud first, Local fallback) or "local" (Local first, Cloud fallback)
    AI_PRIORITY: str = "cloud"

    # Legacy variables for backwards compatibility
    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str | None = None
    OLLAMA_BASE_URL: str | None = None
    OLLAMA_MODEL: str | None = None
    OLLAMA_API_KEY: str | None = None

    SERVER_HOST: str = "127.0.0.1"
    SERVER_PORT: int = 8000
    SERVER_URL: str = "http://127.0.0.1:8000"
    ALLOW_REMOTE: bool = False
    PUEDOBOT_ALLOW_REMOTE: bool = False

    # Security & API Protection
    PUEDOBOT_API_KEY: str | None = None
    PUEDOBOT_ALLOWED_ROOTS: str = ""


    # Per-process admission and per-repository hard resource budgets.
    SCAN_ACTIVE_JOBS: int = Field(1, ge=1, le=4)
    SCAN_SECONDS: float = Field(900, ge=30, le=3600)
    SCAN_ENTRIES: int = Field(30000, ge=100, le=100000)
    SCAN_FILES: int = Field(3000, ge=1, le=10000)
    SCAN_FILE_BYTES: int = Field(1048576, ge=1024, le=10485760)
    SCAN_READ_BYTES: int = Field(67108864, ge=1048576, le=536870912)
    SCAN_HOTSPOTS: int = Field(1000, ge=1, le=5000)
    SCAN_TRIAGE: int = Field(100, ge=1, le=500)
    SCAN_REQUESTS: int = Field(250, ge=1, le=1000)
    SCAN_MODEL_BYTES: int = Field(2097152, ge=16384, le=16777216)
    SCAN_OUTPUT_TOKENS: int = Field(2048, ge=256, le=8192)
    SCAN_OSV_WORKERS: int = Field(4, ge=1, le=8)
    SCAN_SUBSCRIBERS: int = Field(16, ge=1, le=64)

    # Detection engines (each can be switched off without touching code)
    ENABLE_SEMGREP: bool = True
    SEMGREP_CONFIGS: str = "p/security-audit,p/owasp-top-ten"
    SEMGREP_BIN: str | None = None  # optional explicit path to the semgrep executable
    ENABLE_DEPENDENCY_SCAN: bool = True
    HISTORY_MAX_COMMITS: int = 500

    ENABLE_AGENT_SCOUT: bool = True   # AI agent analyzes repo tree to select high-risk files
    ENABLE_VERIFIER: bool = True      # second, skeptical LLM pass that tries to refute each finding

    MIN_CONFIDENCE: int = 60          # below this a finding is discarded as too uncertain

    @computed_field
    @property
    def effective_ai_api_key(self) -> str:
        return self.AI_API_KEY or self.GEMINI_API_KEY or ""

    @computed_field
    @property
    def effective_model_name(self) -> str:
        if "MODEL_NAME" in self.model_fields_set and self.MODEL_NAME:
            return self.MODEL_NAME
        return self.GEMINI_MODEL or self.MODEL_NAME or "gemini-2.5-flash"

    @computed_field
    @property
    def effective_local_ai_url(self) -> str:
        if "LOCAL_AI_URL" in self.model_fields_set and self.LOCAL_AI_URL:
            return self.LOCAL_AI_URL
        return self.OLLAMA_BASE_URL or self.LOCAL_AI_URL or "http://127.0.0.1:11434/v1"

    @computed_field
    @property
    def effective_local_ai_model(self) -> str:
        if "LOCAL_AI_MODEL" in self.model_fields_set and self.LOCAL_AI_MODEL:
            return self.LOCAL_AI_MODEL
        return self.OLLAMA_MODEL or self.LOCAL_AI_MODEL or "qwen2.5-coder:7b"

    @computed_field
    @property
    def is_remote_allowed(self) -> bool:
        return bool(self.PUEDOBOT_ALLOW_REMOTE or self.ALLOW_REMOTE)

    @computed_field
    @property
    def effective_local_ai_api_key(self) -> str:
        if "LOCAL_AI_API_KEY" in self.model_fields_set and self.LOCAL_AI_API_KEY:
            return self.LOCAL_AI_API_KEY
        return self.OLLAMA_API_KEY or self.LOCAL_AI_API_KEY or "ollama"


    @computed_field
    @property
    def database_url(self) -> str:
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

settings = Settings()
