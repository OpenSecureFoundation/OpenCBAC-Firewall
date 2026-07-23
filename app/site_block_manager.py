from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from uuid import uuid4

from app.config import ensure_directories, settings
from app.models import utc_now


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


def resolve_ipv4(target: str) -> list[str]:
    target = target.strip().lower()
    if not target:
        raise ValueError("Le domaine ou l'adresse IP est obligatoire.")
    try:
        ip = ipaddress.ip_address(target)
        if ip.version != 4:
            raise ValueError("Seules les adresses IPv4 sont supportees par iptables.")
        return [str(ip)]
    except ValueError:
        pass

    try:
        records = socket.getaddrinfo(
            target, None, family=socket.AF_INET, type=socket.SOCK_STREAM
        )
    except OSError as exc:
        raise ValueError(f"Impossible de resoudre {target}.") from exc
    ips = sorted({record[4][0] for record in records})
    if not ips:
        raise ValueError(f"Aucune IPv4 trouvee pour {target}.")
    return ips


class SiteBlockManager:
    def list_blocks(self) -> list[dict]:
        return _read_json(settings.blocked_sites_file, [])

    def add_block(self, target: str, reason: str = "Blocage site") -> dict:
        target = target.strip().lower()
        ips = resolve_ipv4(target)
        records = [item for item in self.list_blocks() if item.get("target") != target]
        record = {
            "id": str(uuid4()),
            "target": target,
            "ips": ips,
            "reason": reason,
            "created_at": utc_now(),
            "enabled": True,
        }
        records.append(record)
        _write_json(settings.blocked_sites_file, records)
        return record

    def delete_block(self, block_id: str) -> None:
        records = self.list_blocks()
        kept = [item for item in records if item.get("id") != block_id]
        if len(kept) == len(records):
            raise KeyError("Blocage site introuvable.")
        _write_json(settings.blocked_sites_file, kept)

    def delete_target(self, target: str) -> dict:
        target = target.strip().lower()
        records = self.list_blocks()
        deleted = next((item for item in records if item.get("target") == target), None)
        if deleted is None:
            raise KeyError("Blocage site introuvable.")
        _write_json(
            settings.blocked_sites_file,
            [item for item in records if item.get("target") != target],
        )
        return deleted
