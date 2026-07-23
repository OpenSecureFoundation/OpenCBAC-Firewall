from __future__ import annotations

import json
from pathlib import Path

from app.config import ensure_directories, settings
from app.models import utc_now


def append_json_line(path: Path, payload: dict) -> None:
    ensure_directories()
    record = {"time": utc_now(), **payload}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_event(**payload) -> None:
    append_json_line(settings.events_log, payload)


def log_alert(level: str, message: str, **payload) -> None:
    append_json_line(
        settings.alerts_log,
        {"level": level.upper(), "message": message, **payload},
    )


def read_json_lines(path: Path, limit: int = 100) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    records: list[dict] = []
    for line in lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            records.append({"time": "", "message": line})
    return list(reversed(records))


def recent_events(limit: int = 50) -> list[dict]:
    return read_json_lines(settings.events_log, limit)


def recent_alerts(limit: int = 50) -> list[dict]:
    return read_json_lines(settings.alerts_log, limit)
