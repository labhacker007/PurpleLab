"""Palo Alto Networks Panorama API emulation.

Mimics the Panorama XML/REST API so Joti's PAN-OS/Panorama connector
can execute network SOAR actions (block IP, block domain, block URL)
against the simulation.

Key endpoints:
  POST /api/?type=keygen             API key generation
  GET  /api/?type=op                 operational commands (commit, etc.)
  GET  /restapi/v10.2/Objects/Addresses   list address objects
  POST /restapi/v10.2/Objects/Addresses   create address object (block IP)
  GET  /restapi/v10.2/Objects/CustomURLCategories  list URL categories
  POST /restapi/v10.2/Objects/CustomURLCategories  add URL/domain
  GET  /restapi/v10.2/Policies/SecurityPreRules    list security rules
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Body, Query
from fastapi.responses import Response

from backend.engine.action_executor import execute_action

router = APIRouter(prefix="/api/vendor/panorama", tags=["vendor:panorama"])

_FAKE_KEY = "LUFRPT14MW5xOEo1R09BVIBHeUhBelFpZCtVMnFaQXc9SnM4Y3FueU9HN0FnVzVxZW5sd25CckFmWA=="

_address_objects: dict[str, dict] = {}
_url_categories: dict[str, list[str]] = {"PurpleLab-Blocklist": []}
_blocked_ips: list[str] = []


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _xml_ok(content: str = "") -> Response:
    body = f"<response status='success'>{content}</response>"
    return Response(content=body, media_type="application/xml")


def _xml_err(msg: str) -> Response:
    body = f"<response status='error'><msg>{msg}</msg></response>"
    return Response(content=body, media_type="application/xml", status_code=400)


# ── XML API (legacy key-gen + operations) ─────────────────────────────────────

@router.post("/api/")
@router.get("/api/")
async def xml_api(
    type: Optional[str] = Query(None),
    cmd: Optional[str] = Query(None),
    key: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    password: Optional[str] = Query(None),
    xpath: Optional[str] = Query(None),
    element: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None),
):
    if type == "keygen":
        return _xml_ok(f"<key>{_FAKE_KEY}</key>")
    if type == "op":
        return _xml_ok("<result><success>Commit succeeded</success></result>")
    if type == "config" and xpath and "address" in (xpath or "").lower():
        # Create address object (block IP via XPATH)
        ip = ""
        if element:
            import re
            m = re.search(r"<ip-netmask>([\d./]+)</ip-netmask>", element)
            if m:
                ip = m.group(1).split("/")[0]
        if ip and session_id:
            await execute_action(session_id, "block_ioc",
                                 {"ioc_type": "ip", "ioc_value": ip, "actor": "panorama_api"})
            _blocked_ips.append(ip)
        return _xml_ok()
    return _xml_ok()


# ── REST API v10.2 ────────────────────────────────────────────────────────────

@router.get("/restapi/v10.2/Objects/Addresses")
async def list_addresses(location: str = "vsys", vsys: str = "vsys1"):
    objs = list(_address_objects.values())
    return {"@status": "success", "@code": "19",
            "result": {"@total-count": len(objs), "@count": len(objs), "entry": objs}}


@router.post("/restapi/v10.2/Objects/Addresses")
async def create_address(
    body: dict = Body(default={}),
    location: str = Query("vsys"),
    vsys: str = Query("vsys1"),
    session_id: Optional[str] = Query(None),
):
    name = body.get("@name", f"PurpleLab-{uuid.uuid4().hex[:8]}")
    ip = body.get("ip-netmask", "").split("/")[0]
    _address_objects[name] = {"@name": name, "ip-netmask": body.get("ip-netmask", ""),
                               "description": body.get("description", "PurpleLab block")}
    if ip and session_id:
        await execute_action(session_id, "block_ioc",
                             {"ioc_type": "ip", "ioc_value": ip, "actor": "panorama_api"})
        _blocked_ips.append(ip)
    return {"@status": "success", "@code": "20", "msg": "command succeeded"}


@router.delete("/restapi/v10.2/Objects/Addresses")
async def delete_address(name: str = Query(...), location: str = Query("vsys"),
                          session_id: Optional[str] = Query(None)):
    _address_objects.pop(name, None)
    return {"@status": "success", "@code": "20", "msg": "command succeeded"}


@router.get("/restapi/v10.2/Objects/CustomURLCategories")
async def list_url_categories(location: str = "vsys", vsys: str = "vsys1"):
    cats = [{"@name": k, "list": {"member": v}, "type": "URL List"}
            for k, v in _url_categories.items()]
    return {"@status": "success", "@code": "19",
            "result": {"@total-count": len(cats), "entry": cats}}


@router.post("/restapi/v10.2/Objects/CustomURLCategories")
async def create_url_category(
    body: dict = Body(default={}),
    session_id: Optional[str] = Query(None),
):
    name = body.get("@name", "PurpleLab-Blocklist")
    members = body.get("list", {}).get("member", [])
    if isinstance(members, str):
        members = [members]
    _url_categories.setdefault(name, []).extend(members)
    if session_id:
        for m in members:
            ioc_type = "domain" if "." in m and "/" not in m else "url"
            await execute_action(session_id, "block_ioc",
                                 {"ioc_type": ioc_type, "ioc_value": m,
                                  "actor": "panorama_api"})
    return {"@status": "success", "@code": "20", "msg": "command succeeded"}


@router.get("/restapi/v10.2/Policies/SecurityPreRules")
async def list_security_rules(location: str = "vsys", vsys: str = "vsys1"):
    rules = [
        {"@name": "Allow-Corp-Outbound", "action": "allow", "from": ["trust"], "to": ["untrust"]},
        {"@name": "Block-C2-Domains", "action": "deny", "from": ["any"], "to": ["any"],
         "destination": {"member": list(_url_categories.get("PurpleLab-Blocklist", []))}},
        {"@name": "Deny-All", "action": "deny", "from": ["any"], "to": ["any"]},
    ]
    return {"@status": "success", "@code": "19",
            "result": {"@total-count": len(rules), "entry": rules}}


# ── Commit (triggers async commit job) ───────────────────────────────────────

@router.post("/api/commit")
async def commit():
    return {"jobid": uuid.uuid4().hex[:8], "status": "success"}
