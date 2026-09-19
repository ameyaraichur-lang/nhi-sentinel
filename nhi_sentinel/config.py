"""Runtime configuration with validated bounds (BG02: defaults in code, customer decisions in setup).

Environment overrides use the NHI_ prefix (e.g. NHI_DATA_DIR for test isolation)."""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Bounds(BaseModel):
    """Hard operational bounds (OP02/OP03/OP04 defaults, enforced server-side)."""

    max_task_attempts: int = Field(default=3, ge=1, le=5)
    task_deadline_s: int = Field(default=900, ge=5)
    engine_tick_ms: int = Field(default=250, ge=50, le=5000)
    fanout_per_run: int = Field(default=4, ge=1, le=32)
    fanout_per_tenant: int = Field(default=10, ge=1, le=64)
    model_calls_per_run: int = Field(default=40, ge=0)
    model_token_budget: int = Field(default=100_000, ge=0)
    max_page_size: int = Field(default=100, ge=1, le=500)
    max_hops: int = Field(default=6, ge=1, le=6)
    max_paths: int = Field(default=20, ge=1, le=50)
    session_ttl_min: int = Field(default=240, ge=5)
    active_proof_enabled: bool = False  # D06: disabled in pilot; no env/code path enables it


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NHI_", extra="ignore")

    app_name: str = "NHI Sentinel"
    env: str = "dev"
    data_dir: Path = Path(__file__).resolve().parent.parent / "data"
    fixture_dir: Path = Path(__file__).resolve().parent.parent / "fixtures"
    web_dir: Path = Path(__file__).resolve().parent.parent / "web"
    db_url: str = ""  # computed from data_dir unless NHI_DB_URL set
    signing_secret: str = "dev-only-signing-secret-not-for-production"
    demo_password: str = "demo-synthetic-only"
    synthetic_label: str = "Synthetic demo data - not customer facts"
    engine_tick_ms: int = Field(default=250, ge=50, le=10000)  # slower in tests via NHI_ENGINE_TICK_MS
    rate_limit_per_min: int = Field(default=600, ge=0)  # SC22/AT25 per-client-IP sliding window; 0 disables

    def model_post_init(self, _):
        if not self.db_url:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.db_url = f"sqlite:///{(self.data_dir / 'sentinel.db').as_posix()}"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def bounds(self) -> Bounds:
        return Bounds(engine_tick_ms=self.engine_tick_ms)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    global _settings
    _settings = None
