from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class Settings:
    app_name = "CBAC Shield"
    session_cookie = "cbac_session"
    session_secret = os.getenv("CBAC_SESSION_SECRET", "change-me-in-production")
    host = os.getenv("CBAC_HOST", "127.0.0.1")
    port = int(os.getenv("CBAC_PORT", "8000"))

    config_dir = Path(os.getenv("CBAC_CONFIG_DIR", PROJECT_ROOT / "config"))
    log_dir = Path(os.getenv("CBAC_LOG_DIR", PROJECT_ROOT / "logs"))
    dry_run = os.getenv("CBAC_DRY_RUN", "").lower() in {"1", "true", "yes", "on"}

    rules_file = config_dir / "rules.json"
    blocked_ips_file = config_dir / "blocked_ips.json"
    blocked_sites_file = config_dir / "blocked_sites.json"
    admin_file = config_dir / "admin.json"
    conf_file = config_dir / "cbac.conf"
    backups_dir = config_dir / "backups"

    events_log = log_dir / "events.log"
    alerts_log = log_dir / "alerts.log"


settings = Settings()


def ensure_directories() -> None:
    settings.config_dir.mkdir(parents=True, exist_ok=True)
    settings.backups_dir.mkdir(parents=True, exist_ok=True)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
