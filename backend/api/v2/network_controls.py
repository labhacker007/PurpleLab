"""Network Security Simulation API — v2.

Emulates Palo Alto NGFW / Cisco ASA / Zscaler / Cloudflare DNS filtering APIs.
Supports IP blocking, domain blocking, URL blocking, and file hash blocking
at the network layer. All actions are logged to containment_actions.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func, or_

from backend.db.session import async_session
from backend.db.models import BlockListEntry, ContainmentAction

router = APIRouter(prefix="/network", tags=["network"])


# ── Request schemas ───────────────────────────────────────────────────────────

class BlockIPRequest(BaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to block")
    direction: str = Field("both", description="inbound | outbound | both")
    reason: str = ""
    requester: str = "api"
    vendor: str = "palo_alto"
    duration_hours: Optional[int] = Field(None, description="Auto-expire after N hours. None = permanent.")


class BlockDomainRequest(BaseModel):
    domain: str = Field(..., description="Domain to block (e.g. malicious.example.com)")
    reason: str = ""
    requester: str = "api"
    vendor: str = "zscaler"
    category: str = Field("malicious", description="malicious | phishing | c2 | spam | cryptomining")
    block_subdomains: bool = True


class BlockURLRequest(BaseModel):
    url: str
    reason: str = ""
    requester: str = "api"
    vendor: str = "zscaler"


class BlockHashNetworkRequest(BaseModel):
    sha256: str
    filename: Optional[str] = None
    reason: str = ""
    requester: str = "api"
    vendor: str = "palo_alto"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _entry_to_dict(e: BlockListEntry) -> dict[str, Any]:
    return {
        "id": str(e.id),
        "block_type": e.block_type,
        "value": e.value,
        "direction": e.direction,
        "vendor": e.vendor,
        "reason": e.reason,
        "comment": e.comment,
        "added_by": e.added_by,
        "is_active": e.is_active,
        "expires_at": e.expires_at.isoformat() if e.expires_at else None,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


def _action_to_dict(a: ContainmentAction) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "action_type": a.action_type,
        "target_type": a.target_type,
        "target_value": a.target_value,
        "requester": a.requester,
        "reason": a.reason,
        "status": a.status,
        "executed_at": a.executed_at.isoformat() if a.executed_at else None,
    }


async def _check_duplicate(session, block_type: str, value: str, direction: Optional[str] = None):
    q = select(BlockListEntry).where(
        BlockListEntry.block_type == block_type,
        BlockListEntry.value == value.lower(),
        BlockListEntry.is_active == True,
    )
    if direction:
        q = q.where(or_(BlockListEntry.direction == direction, BlockListEntry.direction == "both"))
    existing = (await session.execute(q)).scalar_one_or_none()
    if existing:
        raise HTTPException(409, f"{block_type.upper()} '{value}' is already blocked (id: {existing.id})")


# ── IP blocking ───────────────────────────────────────────────────────────────

@router.post("/block/ip")
async def block_ip(req: BlockIPRequest):
    """Block an IP address on the simulated firewall/NGW.

    Simulates Palo Alto NGFW dynamic address group update or
    Cloudflare Gateway IP firewall rule creation.
    """
    async with async_session() as session:
        await _check_duplicate(session, "ip", req.ip, req.direction)

        expires_at = None
        if req.duration_hours:
            expires_at = datetime.utcnow().replace(microsecond=0)
            from datetime import timedelta
            expires_at = datetime.utcnow() + timedelta(hours=req.duration_hours)

        entry = BlockListEntry(
            id=uuid.uuid4(),
            block_type="ip",
            value=req.ip.lower(),
            direction=req.direction,
            vendor=req.vendor,
            reason=req.reason,
            added_by=req.requester,
            is_active=True,
            expires_at=expires_at,
        )
        action = ContainmentAction(
            id=uuid.uuid4(),
            action_type="block_ip",
            target_type="ip",
            target_value=req.ip,
            requester=req.requester,
            reason=req.reason,
            status="success",
            result_detail={"ip": req.ip, "direction": req.direction, "vendor": req.vendor, "duration_hours": req.duration_hours},
        )
        session.add(entry)
        session.add(action)
        await session.commit()

    return {
        "success": True,
        "block_id": str(entry.id),
        "action_id": str(action.id),
        "ip": req.ip,
        "direction": req.direction,
        "vendor": req.vendor,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "message": f"IP {req.ip} blocked ({req.direction}) on {req.vendor}",
        "timestamp": entry.created_at.isoformat(),
    }


@router.delete("/block/ip/{ip}")
async def unblock_ip(ip: str, requester: str = "api", reason: str = ""):
    """Remove an IP from the block list."""
    async with async_session() as session:
        entry = (await session.execute(
            select(BlockListEntry).where(
                BlockListEntry.block_type == "ip",
                BlockListEntry.value == ip.lower(),
                BlockListEntry.is_active == True,
            )
        )).scalar_one_or_none()
        if not entry:
            raise HTTPException(404, f"IP {ip} is not in the active block list")

        entry.is_active = False
        action = ContainmentAction(
            id=uuid.uuid4(),
            action_type="unblock_ip",
            target_type="ip",
            target_value=ip,
            requester=requester,
            reason=reason or "IP unblocked",
            status="success",
            result_detail={"ip": ip, "block_id": str(entry.id)},
        )
        session.add(action)
        await session.commit()

    return {"success": True, "action_id": str(action.id), "ip": ip, "message": f"IP {ip} removed from block list"}


# ── Domain blocking ───────────────────────────────────────────────────────────

@router.post("/block/domain")
async def block_domain(req: BlockDomainRequest):
    """Block a domain on the simulated DNS filter / web proxy.

    Simulates Zscaler ZIA URL filtering or Cisco Umbrella DNS policy update.
    """
    async with async_session() as session:
        await _check_duplicate(session, "domain", req.domain)

        entry = BlockListEntry(
            id=uuid.uuid4(),
            block_type="domain",
            value=req.domain.lower(),
            vendor=req.vendor,
            reason=req.reason,
            comment=req.category,
            added_by=req.requester,
            is_active=True,
        )
        action = ContainmentAction(
            id=uuid.uuid4(),
            action_type="block_domain",
            target_type="domain",
            target_value=req.domain,
            requester=req.requester,
            reason=req.reason,
            status="success",
            result_detail={
                "domain": req.domain,
                "vendor": req.vendor,
                "category": req.category,
                "block_subdomains": req.block_subdomains,
            },
        )
        session.add(entry)
        session.add(action)
        await session.commit()

    wildcard = f"*.{req.domain}" if req.block_subdomains else req.domain
    return {
        "success": True,
        "block_id": str(entry.id),
        "action_id": str(action.id),
        "domain": req.domain,
        "wildcard_applied": wildcard,
        "category": req.category,
        "vendor": req.vendor,
        "message": f"Domain {req.domain} blocked on {req.vendor} (category: {req.category})",
    }


@router.delete("/block/domain/{domain}")
async def unblock_domain(domain: str, requester: str = "api"):
    """Remove a domain from the block list."""
    async with async_session() as session:
        entry = (await session.execute(
            select(BlockListEntry).where(
                BlockListEntry.block_type == "domain",
                BlockListEntry.value == domain.lower(),
                BlockListEntry.is_active == True,
            )
        )).scalar_one_or_none()
        if not entry:
            raise HTTPException(404, f"Domain '{domain}' is not in the active block list")
        entry.is_active = False
        action = ContainmentAction(
            id=uuid.uuid4(),
            action_type="unblock_domain",
            target_type="domain",
            target_value=domain,
            requester=requester,
            reason="Domain unblocked",
            status="success",
        )
        session.add(action)
        await session.commit()
    return {"success": True, "action_id": str(action.id), "domain": domain, "message": f"Domain {domain} unblocked"}


# ── URL blocking ──────────────────────────────────────────────────────────────

@router.post("/block/url")
async def block_url(req: BlockURLRequest):
    """Block a specific URL pattern on the web proxy."""
    async with async_session() as session:
        await _check_duplicate(session, "url", req.url)
        entry = BlockListEntry(
            id=uuid.uuid4(), block_type="url", value=req.url, vendor=req.vendor,
            reason=req.reason, added_by=req.requester, is_active=True,
        )
        action = ContainmentAction(
            id=uuid.uuid4(), action_type="block_url", target_type="url",
            target_value=req.url, requester=req.requester, reason=req.reason,
            status="success", result_detail={"url": req.url, "vendor": req.vendor},
        )
        session.add(entry)
        session.add(action)
        await session.commit()
    return {"success": True, "block_id": str(entry.id), "action_id": str(action.id), "url": req.url}


# ── Hash blocking (network layer) ─────────────────────────────────────────────

@router.post("/block/hash")
async def block_hash_network(req: BlockHashNetworkRequest):
    """Block a file hash at the network/gateway layer (e.g. Palo Alto WildFire custom block)."""
    async with async_session() as session:
        await _check_duplicate(session, "hash_net", req.sha256)
        entry = BlockListEntry(
            id=uuid.uuid4(),
            block_type="hash_net",
            value=req.sha256.lower(),
            hash_type="sha256",
            vendor=req.vendor,
            reason=req.reason,
            comment=req.filename or "",
            added_by=req.requester,
            is_active=True,
        )
        action = ContainmentAction(
            id=uuid.uuid4(), action_type="block_hash_network", target_type="hash",
            target_value=req.sha256, requester=req.requester, reason=req.reason,
            status="success", result_detail={"sha256": req.sha256, "filename": req.filename, "vendor": req.vendor},
        )
        session.add(entry)
        session.add(action)
        await session.commit()
    return {"success": True, "block_id": str(entry.id), "action_id": str(action.id), "sha256": req.sha256}


# ── Block list query ──────────────────────────────────────────────────────────

@router.get("/blocks")
async def list_all_blocks(
    block_type: Optional[str] = None,
    active_only: bool = True,
    vendor: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = 0,
):
    """List all active network-layer blocks (IPs, domains, URLs, hashes).

    This is the unified view across all simulated network controls.
    """
    async with async_session() as session:
        q = select(BlockListEntry).order_by(BlockListEntry.created_at.desc())
        if active_only:
            q = q.where(BlockListEntry.is_active == True)
        if block_type:
            q = q.where(BlockListEntry.block_type == block_type)
        if vendor:
            q = q.where(BlockListEntry.vendor == vendor)
        if search:
            q = q.where(BlockListEntry.value.ilike(f"%{search}%"))
        total = (await session.execute(
            select(func.count()).select_from(q.subquery())
        )).scalar() or 0
        entries = (await session.execute(q.offset(offset).limit(limit))).scalars().all()

    return {
        "blocks": [_entry_to_dict(e) for e in entries],
        "total": total,
        "offset": offset,
        "limit": limit,
        "summary": {
            "ip": sum(1 for e in entries if e.block_type == "ip"),
            "domain": sum(1 for e in entries if e.block_type == "domain"),
            "url": sum(1 for e in entries if e.block_type == "url"),
            "hash": sum(1 for e in entries if e.block_type in ("hash", "hash_net")),
        },
    }


@router.get("/blocks/stats")
async def block_stats():
    """Summary statistics for all active blocks."""
    async with async_session() as session:
        q = select(BlockListEntry).where(BlockListEntry.is_active == True)
        entries = (await session.execute(q)).scalars().all()

    stats: dict[str, int] = {}
    for e in entries:
        stats[e.block_type] = stats.get(e.block_type, 0) + 1

    return {
        "total_active_blocks": len(entries),
        "by_type": stats,
        "vendors": list({e.vendor for e in entries}),
    }
