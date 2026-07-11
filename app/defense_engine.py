from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ipaddress

from app.config import ensure_directories, settings
from app.firewall_engine import FirewallEngine
from app.log_manager import log_alert


def _read_json(path: Path, default):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, data) -> None:
    ensure_directories()
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


class DefenseEngine:
    def list_blocked_ips(self) -> list[dict]:
        records = _read_json(settings.blocked_ips_file, [])
        now = datetime.now(timezone.utc)
        changed = False
        for item in records:
            if item.get("status") != "active":
                continue
            until = datetime.fromisoformat(item["blocked_until"])
            if until <= now:
                item["status"] = "expired"
                changed = True
        if changed:
            _write_json(settings.blocked_ips_file, records)
        return records

    def block_ip(self, ip: str, reason: str, duration_minutes: int = 60) -> dict:
        ipaddress.ip_address(ip)
        engine = FirewallEngine()
        engine.require_ready()

        now = datetime.now(timezone.utc).replace(microsecond=0)
        record = {
            "ip": ip,
            "reason": reason,
            "blocked_at": now.isoformat(),
            "duration_minutes": duration_minutes,
            "blocked_until": (now + timedelta(minutes=duration_minutes)).isoformat(),
            "status": "active",
        }
        records = [item for item in self.list_blocked_ips() if item.get("ip") != ip]
        records.append(record)
        _write_json(settings.blocked_ips_file, records)

        engine.block_source_ip(ip)
        level = "WARNING" if engine.dry_run else "CRITICAL"
        message = "IP bloquee en simulation" if engine.dry_run else "IP bloquee automatiquement"
        log_alert(level, message, source_ip=ip, reason=reason)
        return record

    def unblock_ip(self, ip: str) -> None:
        records = self.list_blocked_ips()
        for item in records:
            if item.get("ip") == ip and item.get("status") == "active":
                item["status"] = "expired"
        _write_json(settings.blocked_ips_file, records)
        log_alert("INFO", "IP marquee comme expiree", source_ip=ip)
