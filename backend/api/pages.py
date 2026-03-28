"""Server-rendered dashboard pages with Jinja templates."""

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from starlette.templating import Jinja2Templates

from ..auth.dependencies import get_current_user_from_cookie
from ..services.dns import dns
from ..services.wireguard import wireguard
from ..services.zapret import zapret

router = APIRouter(tags=["pages"])
_templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_templates_dir))

# WireGuard params labels (Russian)
WG_PARAMS_LABELS = {
    "SERVER_PUB_IP": "Публичный IP или DNS (Endpoint)",
    "SERVER_PUB_NIC": "Публичный NIC",
    "SERVER_WG_NIC": "Интерфейс WG",
    "SERVER_WG_IPV4": "IPv4 сети туннеля",
    "SERVER_WG_IPV6": "IPv6 сети туннеля",
    "SERVER_PORT": "Порт UDP",
    "SERVER_PRIV_KEY": "Приватный ключ сервера",
    "SERVER_PUB_KEY": "Публичный ключ сервера (Peer)",
    "CLIENT_DNS_1": "DNS для клиентов (1)",
    "CLIENT_DNS_2": "DNS для клиентов (2)",
    "ALLOWED_IPS": "AllowedIPs (клиенты)",
}

WG_PARAMS_KEYS = list(WG_PARAMS_LABELS.keys())


def _ru_relative_time(sec_ago: int) -> str:
    """Format relative time in Russian (simplified)."""
    if sec_ago < 60:
        return "только что"
    if sec_ago < 3600:
        m = sec_ago // 60
        return f"{m} мин. назад"
    if sec_ago < 86400:
        h = sec_ago // 3600
        return f"{h} ч. назад"
    if sec_ago < 2592000:
        d = sec_ago // 86400
        return f"{d} дн. назад"
    return "давно"


def _format_created_at(ts: int | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _format_last_visit(client: dict) -> dict:
    now = int(datetime.now(timezone.utc).timestamp())
    hs = client.get("last_handshake")
    created = client.get("created_at") or 0
    if hs is None or hs is False:
        return {"main": "нет данных", "sub": "", "title": ""}
    if hs == 0:
        return {"main": "ещё не подключался", "sub": "", "title": ""}
    sec_ago = now - int(hs)
    hs_abs = datetime.fromtimestamp(int(hs), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return {"main": _ru_relative_time(sec_ago), "sub": "", "title": hs_abs}


@router.get("/dashboard", include_in_schema=False)
async def dashboard_redirect():
    return RedirectResponse(url="/dashboard/wireguard", status_code=302)


def _messages_from_query(request: Request) -> dict | None:
    msg = request.query_params.get("msg")
    if not msg:
        return None
    from urllib.parse import unquote_plus
    err = request.query_params.get("err") == "1"
    return {"text": unquote_plus(msg), "type": "danger" if err else "success"}


@router.get("/dashboard/wireguard")
async def page_wireguard(
    request: Request,
    user: str = Depends(get_current_user_from_cookie),
):
    clients = wireguard.list_clients_with_activity()
    params_doc = wireguard.get_params_document()
    params = params_doc.get("params") or {}
    path = params_doc.get("path", "")
    exists = params_doc.get("exists", False)

    clients_sorted = sorted(
        clients,
        key=lambda c: (
            (c.get("last_handshake") or 0) if isinstance(c.get("last_handshake"), (int, float)) else 0,
            c.get("name", ""),
        ),
        reverse=True,
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_feature": "wireguard",
            "messages": _messages_from_query(request),
            "wireguard": {
                "clients": clients_sorted,
                "params": params,
                "params_path": path,
                "params_exists": exists,
                "params_keys": WG_PARAMS_KEYS,
                "params_labels": WG_PARAMS_LABELS,
            },
            "format_visit": _format_last_visit,
        },
    )


@router.get("/dashboard/wireguard/clients/{client_name}")
async def page_wireguard_client(
    request: Request,
    client_name: str,
    user: str = Depends(get_current_user_from_cookie),
):
    clients = wireguard.list_clients_with_activity()
    client = next((c for c in clients if c.get("name") == client_name), None)
    if client is None:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_feature": "wireguard_client",
            "messages": _messages_from_query(request),
            "wireguard_client": {"client": client},
            "format_visit": _format_last_visit,
            "format_created_at": _format_created_at,
        },
    )


@router.get("/dashboard/dns")
async def page_dns(
    request: Request,
    user: str = Depends(get_current_user_from_cookie),
):
    keywords = dns.list_keywords()
    queries = dns.find_queries_by_keywords(limit=200)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_feature": "dns",
            "messages": _messages_from_query(request),
            "dns": {"keywords": keywords, "queries": queries},
        },
    )


@router.get("/dashboard/zapret")
async def page_zapret(
    request: Request,
    user: str = Depends(get_current_user_from_cookie),
):
    lists_ = zapret.list_txt_lists()
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_feature": "zapret",
            "messages": _messages_from_query(request),
            "zapret": {"lists": lists_},
        },
    )


# --- Form POST handlers ---


@router.post("/dashboard/wireguard/clients/add")
async def form_wg_add_client(
    user: str = Depends(get_current_user_from_cookie),
    client_name: str = Form(...),
):
    try:
        wireguard.add_client(client_name.strip(), user)
        return RedirectResponse(url="/dashboard/wireguard?msg=Клиент+добавлен", status_code=302)
    except ValueError as e:
        return RedirectResponse(url=f"/dashboard/wireguard?msg={str(e)}&err=1", status_code=302)


@router.post("/dashboard/wireguard/clients/{client_name}/delete")
async def form_wg_delete_client(
    client_name: str,
    user: str = Depends(get_current_user_from_cookie),
):
    wireguard.remove_client(client_name)
    return RedirectResponse(url="/dashboard/wireguard?msg=Клиент+удалён", status_code=302)


@router.get("/dashboard/wireguard/clients/{client_name}/config")
async def download_wg_config(
    client_name: str,
    user: str = Depends(get_current_user_from_cookie),
):
    cfg = wireguard.get_config(client_name)
    if cfg is None:
        raise HTTPException(status_code=404, detail="Client config not found")
    return Response(
        content=cfg,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="wg-{client_name}.conf"'},
    )


@router.post("/dashboard/wireguard/params")
async def form_wg_params(
    request: Request,
    user: str = Depends(get_current_user_from_cookie),
):
    form = await request.form()
    params = {}
    for key in WG_PARAMS_KEYS:
        val = form.get(f"params_{key}")
        if val is not None:
            params[key] = str(val).strip()
    apply_to_clients = "apply_to_clients" in form
    try:
        result = wireguard.save_params(params, apply_to_clients=apply_to_clients)
        msg = "Сохранено."
        if result.get("clients_updated") is not None:
            msg += f" Обновлено конфигов: {result['clients_updated']}."
        return RedirectResponse(url=f"/dashboard/wireguard?msg={msg}", status_code=302)
    except Exception as e:
        return RedirectResponse(url=f"/dashboard/wireguard?msg={str(e)}&err=1", status_code=302)


@router.post("/dashboard/dns/keywords/bulk")
async def form_dns_add_bulk(
    user: str = Depends(get_current_user_from_cookie),
    text: str = Form(...),
):
    try:
        dns.add_keywords_bulk(text.strip())
        return RedirectResponse(url="/dashboard/dns?msg=Слова+добавлены", status_code=302)
    except Exception as e:
        return RedirectResponse(url=f"/dashboard/dns?msg={str(e)}&err=1", status_code=302)


@router.post("/dashboard/dns/keywords/delete")
async def form_dns_delete_keyword(
    user: str = Depends(get_current_user_from_cookie),
    keyword: str = Form(...),
):
    dns.delete_keyword(keyword.strip())
    return RedirectResponse(url="/dashboard/dns?msg=Слово+удалено", status_code=302)


def _parse_sites(raw: str) -> list[str]:
    return [s.strip() for s in (raw or "").split() if s.strip()]


@router.post("/dashboard/zapret/sites/add")
async def form_zapret_add(
    user: str = Depends(get_current_user_from_cookie),
    list_name: str = Form(...),
    scope: str = Form("domains"),
    sites: str = Form(...),
):
    sites_list = _parse_sites(sites)
    if not sites_list:
        return RedirectResponse(url="/dashboard/zapret?msg=Укажите+сайты&err=1", status_code=302)
    try:
        zapret.add_sites(list_name, sites_list, scope if scope in ("domains", "ipset") else None)
        return RedirectResponse(url="/dashboard/zapret?msg=Сайты+добавлены", status_code=302)
    except Exception as e:
        return RedirectResponse(url=f"/dashboard/zapret?msg={str(e)}&err=1", status_code=302)


@router.post("/dashboard/zapret/sites/remove")
async def form_zapret_remove(
    user: str = Depends(get_current_user_from_cookie),
    list_name: str = Form(...),
    scope: str = Form("domains"),
    sites: str = Form(...),
):
    sites_list = _parse_sites(sites)
    if not sites_list:
        return RedirectResponse(url="/dashboard/zapret?msg=Укажите+адреса&err=1", status_code=302)
    try:
        zapret.remove_sites(list_name, sites_list, scope if scope in ("domains", "ipset") else None)
        return RedirectResponse(url="/dashboard/zapret?msg=Адреса+удалены", status_code=302)
    except Exception as e:
        return RedirectResponse(url=f"/dashboard/zapret?msg={str(e)}&err=1", status_code=302)


@router.post("/dashboard/zapret/check")
async def form_zapret_check(
    request: Request,
    user: str = Depends(get_current_user_from_cookie),
    site: str = Form(...),
):
    site = (site or "").strip()
    if not site:
        return RedirectResponse(url="/dashboard/zapret?msg=Введите+сайт&err=1", status_code=302)
    domain, matches = zapret.find_site_all(site)
    lines = [f"Домен: {domain}"]
    if matches:
        lines.append(f"Найдено в {len(matches)} файле(ах):")
        for m in matches:
            lines.append(f"  • {m['filename']} ({m['scope']}) — {m['path']}")
    else:
        lines.append("Ни в одном списке не найдено.")
    result_text = "\n".join(lines)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "active_feature": "zapret",
            "zapret": {"lists": zapret.list_txt_lists()},
            "zapret_check_result": result_text,
        },
    )
