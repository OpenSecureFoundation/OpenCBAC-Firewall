from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.config import ensure_directories, settings
from app.defense_engine import DefenseEngine
from app.firewall_engine import FirewallEngine, FirewallUnavailableError
from app.log_manager import recent_alerts, recent_events
from app.models import FirewallRule
from app.rule_manager import RuleManager
from app.site_block_manager import SiteBlockManager


def parse_port_proto(value: str | None) -> tuple[str, str]:
    if not value:
        return "any", "ALL"
    text = value.strip()
    if "/" in text:
        port, proto = text.split("/", 1)
        return port or "any", proto.upper()
    if text.upper() in {"TCP", "UDP", "ICMP", "ALL"}:
        return "any", text.upper()
    return text, "TCP"


def parse_rule_tokens(tokens: list[str], action: str, priority: int, enabled: bool) -> dict:
    if tokens and tokens[0].lower() in {"in", "incoming"}:
        tokens = tokens[1:]
    payload = {
        "source_ip": "any",
        "destination_ip": "any",
        "protocol": "ALL",
        "source_port": "any",
        "destination_port": "any",
        "action": action,
        "priority": priority,
        "enabled": enabled,
    }
    if len(tokens) == 1 and tokens[0] not in {"from", "to", "port", "proto"}:
        port, proto = parse_port_proto(tokens[0])
        payload["destination_port"] = port
        payload["protocol"] = proto
        return payload

    index = 0
    while index < len(tokens):
        token = tokens[index].lower()
        if token == "from" and index + 1 < len(tokens):
            payload["source_ip"] = tokens[index + 1]
            index += 2
        elif token == "to" and index + 1 < len(tokens):
            payload["destination_ip"] = tokens[index + 1]
            index += 2
        elif token == "port" and index + 1 < len(tokens):
            port, proto = parse_port_proto(tokens[index + 1])
            payload["destination_port"] = port
            if proto != "ALL":
                payload["protocol"] = proto
            index += 2
        elif token == "sport" and index + 1 < len(tokens):
            payload["source_port"] = tokens[index + 1]
            index += 2
        elif token == "proto" and index + 1 < len(tokens):
            payload["protocol"] = tokens[index + 1].upper()
            index += 2
        else:
            raise ValueError(f"Syntaxe inconnue pres de: {' '.join(tokens[index:])}")
    return payload


def parse_out_target(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    lowered = [token.lower() for token in tokens]
    if lowered[:2] == ["out", "to"] and len(tokens) >= 3:
        return tokens[2]
    if lowered[0] == "out" and len(tokens) >= 2:
        return tokens[1]
    if lowered[:2] == ["outgoing", "to"] and len(tokens) >= 3:
        return tokens[2]
    return None


def format_rule(number: int, rule: FirewallRule) -> str:
    state = "active" if rule.enabled else "inactive"
    return (
        f"[{number}] {rule.id[:8]} priority={rule.priority} {rule.action:<5} "
        f"{rule.protocol:<4} from {rule.source_ip:<18} to {rule.destination_ip:<18} "
        f"sport {rule.source_port:<5} dport {rule.destination_port:<5} {state}"
    )


def resolve_rule_identifier(identifier: str, rules: list[FirewallRule]) -> str:
    if identifier.isdigit():
        number = int(identifier)
        if 1 <= number <= len(rules):
            return rules[number - 1].id
        raise KeyError("Numero de regle introuvable.")
    matches = [rule.id for rule in rules if rule.id.startswith(identifier)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise KeyError("Regle introuvable.")
    raise KeyError("Identifiant ambigu, utilise plus de caracteres.")


def print_rules(manager: RuleManager) -> None:
    rules = manager.list_rules()
    if not rules:
        print("Aucune regle personnalisee.")
        return
    for number, rule in enumerate(rules, start=1):
        print(format_rule(number, rule))


def cmd_status(args: argparse.Namespace) -> int:
    manager = RuleManager()
    engine = FirewallEngine()
    status = engine.status()
    if status["active"]:
        state = "active"
    elif status["mode"] == "simulation":
        state = "simulation"
    else:
        state = "unavailable"
    print(f"Status: {state}")
    print(f"Backend: {status['mode']}")
    print(f"iptables: {status['iptables']}")
    print(f"Config: {status['config_dir']}")
    print(f"Logs: {status['log_dir']}")
    print(f"Default INPUT policy: {status['default_policy']}")
    if status["error"]:
        print(f"Error: {status['error']}")
    print()
    print_rules(manager)
    return 0


def cmd_add_rule(args: argparse.Namespace) -> int:
    manager = RuleManager()
    engine = FirewallEngine()
    engine.require_ready()
    out_target = parse_out_target(args.rule)
    if out_target and args.action == "DENY":
        record = SiteBlockManager().add_block(out_target, args.reason)
        engine.apply_all()
        print(f"Sortie bloquee: {record['target']}")
        print("IP bloquees: " + ", ".join(record["ips"]))
        return 0
    if out_target and args.action == "ALLOW":
        record = SiteBlockManager().delete_target(out_target)
        engine.apply_all()
        print(f"Sortie autorisee: {record['target']}")
        return 0
    payload = parse_rule_tokens(args.rule, args.action, args.priority, not args.disabled)
    rule = manager.add_rule(payload)
    engine.apply_all()
    print(f"Regle ajoutee: {rule.id}")
    print(format_rule(1, rule))
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    manager = RuleManager()
    FirewallEngine().require_ready()
    rules = manager.list_rules()
    rule_id = resolve_rule_identifier(args.rule, rules)
    manager.delete_rule(rule_id)
    FirewallEngine().apply_all()
    print(f"Regle supprimee: {rule_id}")
    return 0


def cmd_set_enabled(args: argparse.Namespace) -> int:
    manager = RuleManager()
    FirewallEngine().require_ready()
    rules = manager.list_rules()
    rule_id = resolve_rule_identifier(args.rule, rules)
    manager.update_rule(rule_id, {"enabled": args.enabled})
    FirewallEngine().apply_all()
    print(f"Regle {'activee' if args.enabled else 'desactivee'}: {rule_id}")
    return 0


def cmd_reload(args: argparse.Namespace) -> int:
    FirewallEngine().apply_all()
    print("Regles CBAC rechargees.")
    return 0


def cmd_disable(args: argparse.Namespace) -> int:
    if not args.yes:
        print("Refus: ajoute --yes pour desactiver le pare-feu et repasser en ACCEPT.")
        return 2
    FirewallEngine().disable()
    print("Pare-feu desactive: politiques INPUT/FORWARD/OUTPUT en ACCEPT.")
    return 0


def cmd_block(args: argparse.Namespace) -> int:
    record = DefenseEngine().block_ip(args.ip, args.reason, args.duration)
    print(f"IP bloquee: {record['ip']} jusqu'a {record['blocked_until']}")
    return 0


def cmd_unblock(args: argparse.Namespace) -> int:
    DefenseEngine().unblock_ip(args.ip)
    print(f"IP expiree: {args.ip}")
    return 0


def cmd_blocked(args: argparse.Namespace) -> int:
    records = DefenseEngine().list_blocked_ips()
    if not records:
        print("Aucune IP bloquee.")
        return 0
    for item in records:
        print(
            f"{item['ip']:<18} {item['status']:<8} "
            f"until={item['blocked_until']} reason={item['reason']}"
        )
    return 0


def cmd_block_site(args: argparse.Namespace) -> int:
    engine = FirewallEngine()
    engine.require_ready()
    record = SiteBlockManager().add_block(args.target, args.reason)
    engine.apply_all()
    print(f"Site bloque: {record['target']}")
    print("IP bloquees: " + ", ".join(record["ips"]))
    return 0


def cmd_unblock_site(args: argparse.Namespace) -> int:
    engine = FirewallEngine()
    engine.require_ready()
    SiteBlockManager().delete_block(args.block_id)
    engine.apply_all()
    print(f"Blocage site supprime: {args.block_id}")
    return 0


def cmd_blocked_sites(args: argparse.Namespace) -> int:
    records = SiteBlockManager().list_blocks()
    if not records:
        print("Aucun site bloque.")
        return 0
    for item in records:
        print(
            f"{item['id'][:8]} {item['target']:<32} "
            f"ips={','.join(item.get('ips', []))} reason={item.get('reason', '')}"
        )
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    reader = recent_alerts if args.kind == "alerts" else recent_events
    for item in reader(args.limit):
        print(item)
    return 0


def cmd_backups(args: argparse.Namespace) -> int:
    backups = RuleManager().list_backups()
    if not backups:
        print("Aucune sauvegarde.")
        return 0
    for path in backups:
        print(path.name)
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    FirewallEngine().require_ready()
    RuleManager().restore_backup(Path(args.filename).name)
    FirewallEngine().apply_all()
    print(f"Sauvegarde restauree: {args.filename}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cbacctl",
        description="CLI locale pour configurer CBAC Shield comme ufw.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Afficher l'etat et les regles")
    status.set_defaults(func=cmd_status)
    rules = sub.add_parser("rules", help="Lister les regles numerotees")
    rules.set_defaults(func=lambda args: (print_rules(RuleManager()) or 0))

    for command, action in (("allow", "ALLOW"), ("deny", "DENY")):
        add = sub.add_parser(command, help=f"Ajouter une regle {action}")
        add.add_argument(
            "rule",
            nargs="*",
            help="Ex: 22/tcp, from 1.2.3.4 to any port 22 proto tcp, out to aerocash.app",
        )
        add.add_argument("--priority", type=int, default=100)
        add.add_argument("--disabled", action="store_true")
        add.add_argument("--reason", default="Regle CLI")
        add.set_defaults(func=cmd_add_rule, action=action)

    delete = sub.add_parser("delete", help="Supprimer une regle par numero ou id")
    delete.add_argument("rule")
    delete.set_defaults(func=cmd_delete)

    enable_rule = sub.add_parser("enable-rule", help="Activer une regle")
    enable_rule.add_argument("rule")
    enable_rule.set_defaults(func=cmd_set_enabled, enabled=True)

    disable_rule = sub.add_parser("disable-rule", help="Desactiver une regle")
    disable_rule.add_argument("rule")
    disable_rule.set_defaults(func=cmd_set_enabled, enabled=False)

    reload_cmd = sub.add_parser("reload", help="Recharger les regles dans iptables")
    reload_cmd.set_defaults(func=cmd_reload)

    enable = sub.add_parser("enable", help="Alias de reload")
    enable.set_defaults(func=cmd_reload)

    disable = sub.add_parser("disable", help="Desactiver iptables CBAC et repasser en ACCEPT")
    disable.add_argument("--yes", action="store_true")
    disable.set_defaults(func=cmd_disable)

    block = sub.add_parser("block", help="Bloquer une IP")
    block.add_argument("ip")
    block.add_argument("--reason", default="Blocage manuel CLI")
    block.add_argument("--duration", type=int, default=60, help="Duree en minutes")
    block.set_defaults(func=cmd_block)

    unblock = sub.add_parser("unblock", help="Expirer le blocage d'une IP")
    unblock.add_argument("ip")
    unblock.set_defaults(func=cmd_unblock)

    blocked = sub.add_parser("blocked", help="Lister les IP bloquees")
    blocked.set_defaults(func=cmd_blocked)

    block_site = sub.add_parser("block-site", help="Bloquer un domaine ou une IP en sortie")
    block_site.add_argument("target", help="Ex: aerocash.app ou 93.127.203.72")
    block_site.add_argument("--reason", default="Blocage site CLI")
    block_site.set_defaults(func=cmd_block_site)

    unblock_site = sub.add_parser("unblock-site", help="Supprimer un blocage site par id")
    unblock_site.add_argument("block_id")
    unblock_site.set_defaults(func=cmd_unblock_site)

    blocked_sites = sub.add_parser("blocked-sites", help="Lister les sites bloques")
    blocked_sites.set_defaults(func=cmd_blocked_sites)

    logs = sub.add_parser("logs", help="Afficher les logs ou alertes")
    logs.add_argument("--kind", choices=["events", "alerts"], default="events")
    logs.add_argument("--limit", type=int, default=20)
    logs.set_defaults(func=cmd_logs)

    backups = sub.add_parser("backups", help="Lister les sauvegardes")
    backups.set_defaults(func=cmd_backups)

    restore = sub.add_parser("restore", help="Restaurer une sauvegarde")
    restore.add_argument("filename")
    restore.set_defaults(func=cmd_restore)

    return parser


def main(argv: list[str] | None = None) -> int:
    ensure_directories()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, KeyError, FileNotFoundError, FirewallUnavailableError) as exc:
        print(f"Erreur: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
