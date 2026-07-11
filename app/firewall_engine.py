from __future__ import annotations

import os
import platform
import shutil
import subprocess

from app.config import settings
from app.log_manager import log_event
from app.models import FirewallRule
from app.rule_manager import RuleManager
from app.site_block_manager import SiteBlockManager


class FirewallUnavailableError(RuntimeError):
    """Raised when real iptables execution is requested but unavailable."""


class FirewallEngine:
    def __init__(self) -> None:
        self.iptables = shutil.which("iptables")

    @property
    def dry_run(self) -> bool:
        return settings.dry_run

    def readiness_error(self) -> str | None:
        if self.dry_run:
            return None
        if platform.system().lower() != "linux":
            return "CBAC Shield doit etre lance sur Linux pour appliquer iptables."
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return "CBAC Shield doit etre lance avec les privileges root (sudo)."
        if self.iptables is None:
            return "La commande iptables est introuvable. Installe iptables avant de continuer."
        return None

    def require_ready(self) -> None:
        error = self.readiness_error()
        if error:
            raise FirewallUnavailableError(error)

    def _run(self, args: list[str]) -> None:
        command = [self.iptables or "iptables", *args]
        if self.dry_run:
            log_event(action="DRY_RUN", message=" ".join(command))
            return
        self.require_ready()
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as exc:
            raise FirewallUnavailableError(
                f"Commande iptables echouee ({exc.returncode}): {' '.join(command)}"
            ) from exc
        log_event(action="APPLY", message=" ".join(command))

    def status(self) -> dict:
        error = self.readiness_error()
        return {
            "active": not self.dry_run and error is None,
            "mode": "simulation" if self.dry_run else "iptables",
            "iptables": self.iptables or "introuvable",
            "default_policy": "DROP",
            "error": error,
            "config_dir": str(settings.config_dir),
            "log_dir": str(settings.log_dir),
        }

    def reset(self) -> None:
        self._run(["-F", "INPUT"])
        self._run(["-F", "FORWARD"])
        self._run(["-F", "OUTPUT"])

    def disable(self) -> None:
        self.reset()
        self._run(["-P", "INPUT", "ACCEPT"])
        self._run(["-P", "FORWARD", "ACCEPT"])
        self._run(["-P", "OUTPUT", "ACCEPT"])

    def apply_base_rules(self) -> None:
        self._run(["-P", "INPUT", "DROP"])
        self._run(["-P", "FORWARD", "DROP"])
        self._run(["-P", "OUTPUT", "ACCEPT"])
        self._run(["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        self._run(
            [
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ]
        )
        self._run(
            ["-A", "INPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP"]
        )

    def _rule_to_iptables(self, rule: FirewallRule) -> list[str]:
        args = ["-A", "INPUT"]
        if rule.source_ip != "any":
            args += ["-s", rule.source_ip]
        if rule.destination_ip != "any":
            args += ["-d", rule.destination_ip]
        if rule.protocol != "ALL":
            args += ["-p", rule.protocol.lower()]
        if rule.source_port != "any" and rule.protocol in {"TCP", "UDP"}:
            args += ["--sport", rule.source_port]
        if rule.destination_port != "any" and rule.protocol in {"TCP", "UDP"}:
            args += ["--dport", rule.destination_port]
        args += ["-m", "conntrack", "--ctstate", "NEW"]
        args += ["-j", "ACCEPT" if rule.action == "ALLOW" else "DROP"]
        return args

    def apply_rule(self, rule: FirewallRule) -> None:
        if rule.enabled:
            self._run(self._rule_to_iptables(rule))

    def block_source_ip(self, ip: str) -> None:
        self._run(["-I", "INPUT", "1", "-s", ip, "-j", "DROP"])

    def apply_site_blocks(self) -> None:
        for item in SiteBlockManager().list_blocks():
            if not item.get("enabled", True):
                continue
            for ip in item.get("ips", []):
                self._run(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])

    def apply_all(self) -> None:
        self.reset()
        self.apply_base_rules()
        for rule in RuleManager().list_rules():
            self.apply_rule(rule)
        self.apply_site_blocks()
