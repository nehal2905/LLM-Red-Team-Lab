"""Central configuration for the LLM Red-Team Lab.

A single :class:`Settings` object (see :data:`settings`) is imported everywhere.
Values come from environment variables / a local ``.env`` file, with safe
defaults so the lab is runnable out of the box.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root = parent of the ``config`` directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Strongly-typed, env-overridable settings for the whole lab."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- LLM runtime ---
    llm_ollama_host: str = Field(default="http://localhost:11434")
    llm_model: str = Field(default="llama3.1")
    llm_temperature: float = Field(default=0.1)
    llm_request_timeout: int = Field(default=120)

    # --- Embeddings ---
    embedding_backend: str = Field(default="ollama")  # "ollama" | "sentence_transformers"
    embedding_model: str = Field(default="nomic-embed-text")
    embedding_fallback_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2"
    )

    # --- Vector store ---
    chroma_dir: Path = Field(default=PROJECT_ROOT / ".chroma")
    chroma_collection: str = Field(default="company_corpus")

    # --- Retrieval / chunking ---
    retriever_top_k: int = Field(default=4)
    chunk_size: int = Field(default=800)
    chunk_overlap: int = Field(default=120)

    # --- Risk thresholds (0-100) ---
    threshold_flag: int = Field(default=25)
    threshold_block: int = Field(default=50)
    threshold_critical: int = Field(default=75)

    # --- Detection toggles ---
    enable_semantic_detection: bool = Field(default=False)
    semantic_similarity_threshold: float = Field(default=0.75)

    # --- Authorization (L3 context guard) ---
    authorized_roles: str = Field(default="admin,security")

    # --- Paths ---
    corpus_dir: Path = Field(default=PROJECT_ROOT / "data" / "corpus")
    payload_dir: Path = Field(default=PROJECT_ROOT / "data" / "attack_payloads")
    results_dir: Path = Field(default=PROJECT_ROOT / "results")
    audit_log_path: Path = Field(default=PROJECT_ROOT / "results" / "runs" / "audit.jsonl")

    # --- Derived helpers ---
    @property
    def authorized_role_set(self) -> set[str]:
        return {r.strip().lower() for r in self.authorized_roles.split(",") if r.strip()}

    @property
    def runs_dir(self) -> Path:
        return self.results_dir / "runs"

    @property
    def charts_dir(self) -> Path:
        return self.results_dir / "charts"

    @property
    def report_csv(self) -> Path:
        return self.results_dir / "report.csv"

    def ensure_dirs(self) -> None:
        """Create all writable directories the lab needs."""
        for p in (
            self.chroma_dir,
            self.results_dir,
            self.runs_dir,
            self.charts_dir,
            self.audit_log_path.parent,
        ):
            Path(p).mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()


# Module-level singleton for convenient imports: ``from config.settings import settings``
settings = get_settings()
