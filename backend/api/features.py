from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth.dependencies import get_current_user
from ..models.features import (
    DnsBulkKeywordsRequest,
    DnsKeywordRequest,
    WgAddRequest,
    WgParamsPutRequest,
    WgRenameRequest,
    ZapretAddRequest,
    ZapretCheckRequest,
)
from ..services.dns import dns
from ..services.wireguard import wireguard
from ..services.zapret import zapret

router = APIRouter(prefix="/api", tags=["features"], dependencies=[Depends(get_current_user)])


@router.get("/wireguard/stats")
def wg_stats(include_ip: bool = False) -> dict:
    return {"stats": wireguard.get_stats(include_ip)}


@router.post("/wireguard/clients")
def wg_add(payload: WgAddRequest, user: str = Depends(get_current_user)) -> dict:
    return wireguard.add_client(payload.client_name, user)


@router.delete("/wireguard/clients/{client_name}")
def wg_remove(client_name: str) -> dict:
    removed = wireguard.remove_client(client_name)
    return {"removed": removed}


@router.patch("/wireguard/clients/rename")
def wg_rename(payload: WgRenameRequest) -> dict:
    return wireguard.rename_client(payload.old_name, payload.new_name)


@router.get("/wireguard/clients")
def wg_list() -> dict:
    return {"clients": wireguard.list_clients_with_activity()}


@router.get("/wireguard/params")
def wg_params_get() -> dict:
    return wireguard.get_params_document()


@router.put("/wireguard/params")
def wg_params_put(payload: WgParamsPutRequest) -> dict:
    return wireguard.save_params(
        payload.params, apply_to_clients=payload.apply_to_clients
    )


@router.get("/wireguard/clients/{client_name}/config")
def wg_config(client_name: str) -> dict:
    cfg = wireguard.get_config(client_name)
    if cfg is None:
        raise HTTPException(status_code=404, detail="Client config not found")
    return {"client_name": client_name, "config": cfg}


@router.post("/zapret/sites")
def zapret_add(payload: ZapretAddRequest) -> dict:
    return zapret.add_sites(
        payload.list_name, payload.sites, payload.scope
    )


@router.get("/zapret/lists")
def zapret_lists() -> dict:
    return {"lists": zapret.list_txt_lists()}


@router.post("/zapret/check")
def zapret_check(payload: ZapretCheckRequest) -> dict:
    domain, matches = zapret.find_site_all(payload.site)
    return {"found": bool(matches), "domain": domain, "matches": matches}


@router.post("/zapret/sites/remove")
def zapret_remove(payload: ZapretAddRequest) -> dict:
    return zapret.remove_sites(
        payload.list_name, payload.sites, payload.scope
    )


@router.get("/dns/keywords")
def dns_keywords() -> dict:
    return {"keywords": dns.list_keywords()}


@router.post("/dns/keywords")
def dns_add_keyword(payload: DnsKeywordRequest) -> dict:
    dns.add_keyword(payload.keyword)
    return {"added": payload.keyword.lower()}


@router.delete("/dns/keywords")
def dns_delete_keyword(payload: DnsKeywordRequest) -> dict:
    return {"removed": dns.delete_keyword(payload.keyword)}


@router.get("/dns/queries")
def dns_queries(limit: int = Query(200, ge=1, le=5000)) -> dict:
    return {"entries": dns.find_queries_by_keywords(limit=limit)}


@router.post("/dns/keywords/bulk")
def dns_add_keywords_bulk(payload: DnsBulkKeywordsRequest) -> dict:
    return dns.add_keywords_bulk(payload.text)
