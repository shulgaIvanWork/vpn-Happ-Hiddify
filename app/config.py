from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- secrets / branding ---
    sub_token: str = "change-me-sub-token"
    admin_token: str = "change-me-admin-token"
    profile_title: str = "Moscow Auto-VPN"
    support_url: str = "https://t.me/your_channel"
    web_page_url: str | None = None
    total_bytes: int = 322_122_547_200
    expire_unix: int = 1_893_456_000

    # --- subscription ---
    nodes_in_sub: int = 35
    max_nodes_per_subnet: int = Field(default=8, ge=0)

    # --- checker ---
    batch_size: int = Field(default=70, ge=1, le=200)
    check_timeout: float = Field(default=4.0, gt=0, le=30)
    probe_concurrency: int = Field(default=20, ge=1, le=200)
    max_nodes_per_scan: int = Field(default=2500, ge=1)
    max_latency_ms: int = Field(default=8000, ge=100)

    # --- schedule ---
    full_scan_interval: int = 3600
    live_recheck_interval: int = 600
    scheduler_enabled: bool = True
    min_live_for_ready: int = 5

    # --- infra ---
    data_dir: Path = Path("data")
    singbox_path: str = "sing-box"
    sources_file: Path = Path("sources.yaml")
    log_level: str = "INFO"
    trust_forwarded_for: bool = True
    rate_limit_per_min: int = 120

    # --- limits ---
    max_live_store: int = 200

    @property
    def placeholder_secrets(self) -> list[str]:
        bad = []
        if "change-me" in self.sub_token:
            bad.append("SUB_TOKEN")
        if "change-me" in self.admin_token:
            bad.append("ADMIN_TOKEN")
        return bad


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
