from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.auth import authenticate
from app.config import PROJECT_ROOT, ensure_directories, settings
from app.defense_engine import DefenseEngine
from app.firewall_engine import FirewallEngine, FirewallUnavailableError
from app.log_manager import recent_alerts, recent_events
from app.rule_manager import RuleManager
from app.site_block_manager import SiteBlockManager


ensure_directories()

app = FastAPI(title=settings.app_name)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie=settings.session_cookie,
    https_only=False,
    same_site="lax",
)
app.mount("/static", StaticFiles(directory=PROJECT_ROOT / "app" / "static"), name="static")
templates = Jinja2Templates(directory=PROJECT_ROOT / "app" / "templates")

rules = RuleManager()
firewall = FirewallEngine()
defense = DefenseEngine()
site_blocks = SiteBlockManager()


def require_login(request: Request) -> None:
    if not request.session.get("admin"):
        raise HTTPException(status_code=303, headers={"Location": "/login"})


def render(request: Request, template: str, context: dict | None = None):
    payload = {"request": request, "app_name": settings.app_name}
    payload.update(context or {})
    return templates.TemplateResponse(request, template, payload)


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def apply_firewall() -> str | None:
    try:
        firewall.apply_all()
    except FirewallUnavailableError as exc:
        return str(exc)
    return None


def rule_payload(
    source_ip: str,
    destination_ip: str,
    protocol: str,
    source_port: str,
    destination_port: str,
    action: str,
    priority: int,
    enabled: bool,
) -> dict:
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "action": action,
        "priority": priority,
        "enabled": enabled,
    }


def find_rule(rule_id: str):
    for rule in rules.list_rules():
        if rule.id == rule_id:
            return rule
    raise KeyError("Regle introuvable.")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html")


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if authenticate(settings.admin_file, username, password):
        request.session["admin"] = username
        return redirect("/")
    return render(request, "login.html", {"error": "Identifiants invalides."})


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    require_login(request)
    rule_list = rules.list_rules()
    blocked = defense.list_blocked_ips()
    return render(
        request,
        "dashboard.html",
        {
            "status": firewall.status(),
            "rule_count": len([rule for rule in rule_list if rule.enabled]),
            "blocked_count": len([item for item in blocked if item["status"] == "active"]),
            "events": recent_events(6),
            "alerts": recent_alerts(6),
        },
    )


@app.get("/rules", response_class=HTMLResponse)
def rules_page(request: Request):
    require_login(request)
    return render(request, "rules.html", {"rules": rules.list_rules()})


@app.post("/rules")
def create_rule(
    request: Request,
    source_ip: str = Form("any"),
    destination_ip: str = Form("any"),
    protocol: str = Form("ALL"),
    source_port: str = Form("any"),
    destination_port: str = Form("any"),
    action: str = Form("ALLOW"),
    priority: int = Form(100),
    enabled: bool = Form(False),
):
    require_login(request)
    try:
        firewall.require_ready()
        rules.add_rule(
            rule_payload(
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                action,
                priority,
                enabled,
            )
        )
        error = apply_firewall()
        if error:
            return render(request, "rules.html", {"rules": rules.list_rules(), "error": error})
    except (ValueError, FirewallUnavailableError) as exc:
        return render(request, "rules.html", {"rules": rules.list_rules(), "error": str(exc)})
    return redirect("/rules")


@app.get("/rules/{rule_id}/edit", response_class=HTMLResponse)
def edit_rule_page(request: Request, rule_id: str):
    require_login(request)
    try:
        rule = find_rule(rule_id)
    except KeyError as exc:
        return render(request, "rules.html", {"rules": rules.list_rules(), "error": str(exc)})
    return render(request, "edit_rule.html", {"rule": rule})


@app.post("/rules/{rule_id}/update")
def update_rule(
    request: Request,
    rule_id: str,
    source_ip: str = Form("any"),
    destination_ip: str = Form("any"),
    protocol: str = Form("ALL"),
    source_port: str = Form("any"),
    destination_port: str = Form("any"),
    action: str = Form("ALLOW"),
    priority: int = Form(100),
    enabled: bool = Form(False),
):
    require_login(request)
    try:
        firewall.require_ready()
        rules.update_rule(
            rule_id,
            rule_payload(
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                action,
                priority,
                enabled,
            ),
        )
        error = apply_firewall()
        if error:
            return render(request, "rules.html", {"rules": rules.list_rules(), "error": error})
    except (ValueError, KeyError, FirewallUnavailableError) as exc:
        try:
            rule = find_rule(rule_id)
            return render(request, "edit_rule.html", {"rule": rule, "error": str(exc)})
        except KeyError:
            return render(request, "rules.html", {"rules": rules.list_rules(), "error": str(exc)})
    return redirect("/rules")


@app.post("/rules/{rule_id}/toggle")
def toggle_rule(request: Request, rule_id: str):
    require_login(request)
    try:
        firewall.require_ready()
    except FirewallUnavailableError as exc:
        return render(request, "rules.html", {"rules": rules.list_rules(), "error": str(exc)})
    rules.toggle_rule(rule_id)
    error = apply_firewall()
    if error:
        return render(request, "rules.html", {"rules": rules.list_rules(), "error": error})
    return redirect("/rules")


@app.post("/rules/{rule_id}/delete")
def delete_rule(request: Request, rule_id: str):
    require_login(request)
    try:
        firewall.require_ready()
    except FirewallUnavailableError as exc:
        return render(request, "rules.html", {"rules": rules.list_rules(), "error": str(exc)})
    rules.delete_rule(rule_id)
    error = apply_firewall()
    if error:
        return render(request, "rules.html", {"rules": rules.list_rules(), "error": error})
    return redirect("/rules")


@app.post("/reload")
def reload_firewall(request: Request):
    require_login(request)
    error = apply_firewall()
    if error:
        rule_list = rules.list_rules()
        blocked = defense.list_blocked_ips()
        return render(
            request,
            "dashboard.html",
            {
                "status": firewall.status(),
                "rule_count": len([rule for rule in rule_list if rule.enabled]),
                "blocked_count": len([item for item in blocked if item["status"] == "active"]),
                "events": recent_events(6),
                "alerts": recent_alerts(6),
                "error": error,
            },
        )
    return redirect("/")


@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request):
    require_login(request)
    return render(request, "logs.html", {"events": recent_events(100)})


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    require_login(request)
    return render(
        request,
        "alerts.html",
        {
            "alerts": recent_alerts(100),
            "blocked_ips": defense.list_blocked_ips(),
            "site_blocks": site_blocks.list_blocks(),
        },
    )


@app.post("/blocked-ips")
def block_ip(
    request: Request,
    ip: str = Form(...),
    reason: str = Form("Blocage manuel"),
    duration_minutes: int = Form(60),
):
    require_login(request)
    try:
        defense.block_ip(ip, reason, duration_minutes)
    except (ValueError, FirewallUnavailableError) as exc:
        return render(
            request,
            "alerts.html",
            {
                "alerts": recent_alerts(100),
                "blocked_ips": defense.list_blocked_ips(),
                "site_blocks": site_blocks.list_blocks(),
                "error": str(exc),
            },
        )
    return redirect("/alerts")


@app.post("/blocked-sites")
def block_site(
    request: Request,
    target: str = Form(...),
    reason: str = Form("Blocage site"),
):
    require_login(request)
    try:
        firewall.require_ready()
        site_blocks.add_block(target, reason)
        error = apply_firewall()
        if error:
            return render(
                request,
                "alerts.html",
                {
                    "alerts": recent_alerts(100),
                    "blocked_ips": defense.list_blocked_ips(),
                    "site_blocks": site_blocks.list_blocks(),
                    "error": error,
                },
            )
    except (ValueError, FirewallUnavailableError) as exc:
        return render(
            request,
            "alerts.html",
            {
                "alerts": recent_alerts(100),
                "blocked_ips": defense.list_blocked_ips(),
                "site_blocks": site_blocks.list_blocks(),
                "error": str(exc),
            },
        )
    return redirect("/alerts")


@app.post("/blocked-sites/{block_id}/delete")
def delete_site_block(request: Request, block_id: str):
    require_login(request)
    try:
        firewall.require_ready()
        site_blocks.delete_block(block_id)
        error = apply_firewall()
        if error:
            return render(
                request,
                "alerts.html",
                {
                    "alerts": recent_alerts(100),
                    "blocked_ips": defense.list_blocked_ips(),
                    "site_blocks": site_blocks.list_blocks(),
                    "error": error,
                },
            )
    except (KeyError, FirewallUnavailableError) as exc:
        return render(
            request,
            "alerts.html",
            {
                "alerts": recent_alerts(100),
                "blocked_ips": defense.list_blocked_ips(),
                "site_blocks": site_blocks.list_blocks(),
                "error": str(exc),
            },
        )
    return redirect("/alerts")


@app.post("/blocked-ips/{ip}/unblock")
def unblock_ip(request: Request, ip: str):
    require_login(request)
    defense.unblock_ip(ip)
    return redirect("/alerts")


@app.get("/backups", response_class=HTMLResponse)
def backups_page(request: Request):
    require_login(request)
    return render(
        request,
        "backups.html",
        {"backups": [path.name for path in rules.list_backups()]},
    )


@app.post("/backups/{filename}/restore")
def restore_backup(request: Request, filename: str):
    require_login(request)
    try:
        firewall.require_ready()
    except FirewallUnavailableError as exc:
        return render(
            request,
            "backups.html",
            {"backups": [path.name for path in rules.list_backups()], "error": str(exc)},
        )
    rules.restore_backup(Path(filename).name)
    error = apply_firewall()
    if error:
        return render(
            request,
            "backups.html",
            {"backups": [path.name for path in rules.list_backups()], "error": error},
        )
    return redirect("/backups")
