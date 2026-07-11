from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Any
from uuid import uuid4


PROTOCOLS = {"TCP", "UDP", "ICMP", "ALL"}
ACTIONS = {"ALLOW", "DENY"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_any(value: str | None) -> str:
    value = (value or "any").strip()
    return "any" if value.lower() in {"", "any", "*"} else value


def validate_ip_or_any(value: str | None, field: str) -> str:
    value = _normalize_any(value)
    if value == "any":
        return value
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"{field} doit etre une adresse IP, un CIDR ou 'any'.") from exc
    return value


def validate_port_or_any(value: str | int | None, field: str) -> str:
    value = _normalize_any(str(value) if value is not None else None)
    if value == "any":
        return value
    if not value.isdigit():
        raise ValueError(f"{field} doit etre un port numerique ou 'any'.")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"{field} doit etre entre 1 et 65535.")
    return str(port)


@dataclass
class FirewallRule:
    id: str
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: str
    destination_port: str
    action: str
    priority: int
    enabled: bool
    created_at: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FirewallRule":
        protocol = str(data.get("protocol", "ALL")).upper()
        action = str(data.get("action", "ALLOW")).upper()
        if protocol not in PROTOCOLS:
            raise ValueError("Le protocole doit etre TCP, UDP, ICMP ou ALL.")
        if action not in ACTIONS:
            raise ValueError("L'action doit etre ALLOW ou DENY.")
        return cls(
            id=str(data.get("id") or uuid4()),
            source_ip=validate_ip_or_any(data.get("source_ip"), "IP source"),
            destination_ip=validate_ip_or_any(
                data.get("destination_ip"), "IP destination"
            ),
            protocol=protocol,
            source_port=validate_port_or_any(data.get("source_port"), "Port source"),
            destination_port=validate_port_or_any(
                data.get("destination_port"), "Port destination"
            ),
            action=action,
            priority=int(data.get("priority", 100)),
            enabled=bool(data.get("enabled", True)),
            created_at=str(data.get("created_at") or utc_now()),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "action": self.action,
            "priority": self.priority,
            "enabled": self.enabled,
            "created_at": self.created_at,
        }
