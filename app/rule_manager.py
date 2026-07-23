from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

from app.config import ensure_directories, settings
from app.models import FirewallRule


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


class RuleManager:
    def list_rules(self) -> list[FirewallRule]:
        data = _read_json(settings.rules_file, [])
        rules = [FirewallRule.from_dict(item) for item in data]
        return sorted(rules, key=lambda rule: rule.priority)

    def save_rules(self, rules: list[FirewallRule], backup: bool = True) -> None:
        if backup and settings.rules_file.exists():
            self.backup_rules()
        _write_json(settings.rules_file, [rule.to_dict() for rule in rules])

    def backup_rules(self) -> Path | None:
        ensure_directories()
        if not settings.rules_file.exists():
            return None
        stamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        target = settings.backups_dir / f"rules-{stamp}.json"
        shutil.copy2(settings.rules_file, target)
        return target

    def list_backups(self) -> list[Path]:
        ensure_directories()
        return sorted(settings.backups_dir.glob("rules-*.json"), reverse=True)

    def restore_backup(self, filename: str) -> None:
        source = settings.backups_dir / Path(filename).name
        if not source.exists():
            raise FileNotFoundError("Sauvegarde introuvable.")
        self.backup_rules()
        shutil.copy2(source, settings.rules_file)

    def add_rule(self, data: dict) -> FirewallRule:
        rules = self.list_rules()
        rule = FirewallRule.from_dict(data)
        rules.append(rule)
        self.save_rules(rules)
        return rule

    def update_rule(self, rule_id: str, data: dict) -> FirewallRule:
        rules = self.list_rules()
        updated: FirewallRule | None = None
        for index, rule in enumerate(rules):
            if rule.id == rule_id:
                payload = rule.to_dict()
                payload.update(data)
                updated = FirewallRule.from_dict(payload)
                rules[index] = updated
                break
        if updated is None:
            raise KeyError("Regle introuvable.")
        self.save_rules(rules)
        return updated

    def delete_rule(self, rule_id: str) -> None:
        rules = self.list_rules()
        kept = [rule for rule in rules if rule.id != rule_id]
        if len(kept) == len(rules):
            raise KeyError("Regle introuvable.")
        self.save_rules(kept)

    def toggle_rule(self, rule_id: str) -> FirewallRule:
        rules = self.list_rules()
        for index, rule in enumerate(rules):
            if rule.id == rule_id:
                payload = rule.to_dict()
                payload["enabled"] = not rule.enabled
                rules[index] = FirewallRule.from_dict(payload)
                self.save_rules(rules)
                return rules[index]
        raise KeyError("Regle introuvable.")
