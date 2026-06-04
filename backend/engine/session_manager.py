"""Session manager — DB-backed persistence with in-memory write-through cache.

Handles CRUD operations for simulation sessions and coordinates
with the scheduler and dispatcher for event generation.

The in-memory `_sessions` dict acts as a write-through cache for running
sessions. On `get_session`, memory is checked first; DB is the source of
truth for stopped/persisted sessions.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from sqlalchemy import select

from backend.db.models import GeneratedEvent, SimulationSession
from backend.db.session import async_session
from backend.engine.generators import GENERATOR_REGISTRY
from backend.engine.generators.base import BaseGenerator

log = logging.getLogger(__name__)


# ── Source → vendor map for OCSF normalization ────────────────────────────────

_SOURCE_VENDOR_MAP: dict[str, tuple[str, str]] = {
    "windows_eventlog":  ("microsoft", "windows_security"),
    "sysmon":            ("microsoft", "sysmon"),
    "edr":               ("crowdstrike", "edr"),
    "crowdstrike_edr":   ("crowdstrike", "edr"),
    "crowdstrike":       ("crowdstrike", "edr"),
    "auth":              ("okta", "identity"),
    "okta":              ("okta", "identity"),
    "okta_identity":     ("okta", "identity"),
    "firewall":          ("palo_alto", "ngfw"),
    "palo_alto":         ("palo_alto", "ngfw"),
    "dns":               ("crowdstrike", "dns"),
    "cloudtrail":        ("aws", "cloudtrail"),
    "cloud":             ("aws", "cloudtrail"),
    "aws_cloudtrail":    ("aws", "cloudtrail"),
}


def _infer_vendor_product(source_type: str) -> tuple[str, str]:
    """Map a source_type to (vendor, product) for OCSF normalization."""
    key = source_type.lower().replace(" ", "_").replace("-", "_")
    return _SOURCE_VENDOR_MAP.get(key, ("", ""))


# ── LLM-based event generation ────────────────────────────────────────────────

_LOG_SYSTEM_PROMPT = """You are a cybersecurity simulation engine that generates realistic SIEM log events.
Generate logs in JSON format that look exactly like real security telemetry.
Each log must represent a specific stage of an adversary's attack chain.
Return a JSON array of log events. Each event must have these exact fields:
- source_type: string (e.g. "windows_eventlog", "sysmon", "firewall", "edr", "proxy", "dns", "auth")
- technique_id: string (MITRE ATT&CK ID like "T1059.001")
- severity: string ("critical", "high", "medium", "low", "info")
- title: string (concise event description)
- timestamp: string (ISO 8601, spaced realistically over the attack timeline)
- payload: object with realistic fields matching the source_type

For windows_eventlog include: EventID, Computer, SubjectUserName, ProcessName, CommandLine
For sysmon include: EventID, Image, CommandLine, ParentImage, Hashes, NetworkConnections
For firewall include: src_ip, dst_ip, dst_port, action, bytes_out, protocol
For dns include: query, query_type, answer, client_ip
For auth include: user, src_ip, auth_type, result, domain
For edr include: process_name, hash, parent_process, alert_name, action_taken
For proxy include: url, method, status_code, user_agent, bytes

Return ONLY the JSON array. No markdown, no explanation."""


async def _call_llm_for_events(
    user_prompt: str,
    event_count: int,
) -> list[dict[str, Any]]:
    """Call LLM and return parsed events list. Raises on failure (caller decides fallback)."""
    from backend.llm.config import LLMFunction
    from backend.llm.router import get_router

    router = get_router()
    client = router.get_client(LLMFunction.LOG_GENERATION)
    response = await client.complete(
        messages=[{"role": "user", "content": user_prompt}],
        system=_LOG_SYSTEM_PROMPT,
        max_tokens=max(1200, event_count * 160),
        temperature=0.7,
        json_mode=True,
    )
    text = response.text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    events = json.loads(text)
    if isinstance(events, dict) and "events" in events:
        events = events["events"]
    if not isinstance(events, list):
        events = [events]
    return events


async def _generate_events_llm_targeted(
    technique_ids: list[str],
    event_count: int,
    config: dict[str, Any],
    asset_pool: dict[str, Any],
    ioc_pool: list[dict[str, Any]],
    context: Any = None,   # SimulationContext | None
) -> list[dict[str, Any]]:
    """Generate events specifically for techniques with no library templates.

    Builds a technique-specific prompt with per-TTP behavior hints, real hostnames,
    real IPs/users from the asset_pool, and actual IOCs from ioc_pool.
    When a SimulationContext is provided, its fixed entities take priority over pool picks.
    """
    from backend.engine.ttp_library import TECHNIQUE_BEHAVIOR_HINTS

    if not technique_ids or event_count <= 0:
        return []

    # Build asset context block for the prompt
    endpoints = asset_pool.get("endpoints") or []
    servers = asset_pool.get("servers") or []
    users = asset_pool.get("users") or []
    domain = asset_pool.get("domain", "corp.local")

    # Prefer SimulationContext fixed values so the LLM uses the session's canonical entities
    if context is not None:
        victim_host = context.victim_hostname or (endpoints[0]["hostname"] if endpoints else "CORP-WS-01")
        victim_ip = context.victim_ip or (endpoints[0]["ip_address"] if endpoints else "192.168.1.10")
        victim_user = context.victim_username or (users[0]["username"] if users else "jsmith")
        attacker_ip = context.attacker_ip or "185.220.101.42"
        c2_domain = context.c2_domain or "updates.malicious-cdn.ru"
        domain = context.domain or domain
        lateral_host = context.lateral_hostname or (servers[0]["hostname"] if servers else "SERVER-DC01")
        hostnames = [victim_host, lateral_host] + [e["hostname"] for e in (endpoints + servers)[2:6]]
        ips = [victim_ip] + [e["ip_address"] for e in endpoints[1:4]] + [e["ip_address"] for e in servers[:2]]
        usernames = [victim_user] + [u["username"] for u in users[1:4]]
        context_detail = (
            f"\n  Attacker IP: {attacker_ip} | C2 Domain: {c2_domain}"
            + (f" | Malware: {context.malware_filename}" if context.malware_filename else "")
            + (f" | Hash: {context.malware_hash_sha256[:16]}..." if context.malware_hash_sha256 else "")
        )
    else:
        hostnames = [e["hostname"] for e in (endpoints + servers)[:6]]
        ips = [e["ip_address"] for e in endpoints[:4]] + [e["ip_address"] for e in servers[:2]]
        usernames = [u["username"] for u in users[:4]]
        context_detail = ""

    asset_block = (
        f"ENVIRONMENT ASSETS (use these real values — do NOT invent different ones):\n"
        f"  Hostnames: {', '.join(hostnames) if hostnames else 'CORP-WS-01, SERVER-DC01'}\n"
        f"  Internal IPs: {', '.join(ips) if ips else '192.168.1.10, 192.168.1.5'}\n"
        f"  Usernames: {', '.join(usernames) if usernames else 'jsmith, agarcia'}\n"
        f"  Domain: {domain}"
        + context_detail
    )

    # Build IOC context block
    c2_ips = [i.get("value") for i in ioc_pool if (i.get("type") or "").lower() in ("ip", "ipv4") and i.get("value")]
    c2_domains = [i.get("value") for i in ioc_pool if (i.get("type") or "").lower() in ("domain", "hostname") and i.get("value")]
    file_hashes = [i.get("value") for i in ioc_pool if (i.get("type") or "").lower() in ("sha256", "md5", "hash") and i.get("value")]

    ioc_block = ""
    if c2_ips or c2_domains or file_hashes:
        ioc_parts = []
        if c2_ips:
            ioc_parts.append(f"C2 IPs: {', '.join(c2_ips[:3])}")
        if c2_domains:
            ioc_parts.append(f"C2 Domains: {', '.join(c2_domains[:3])}")
        if file_hashes:
            ioc_parts.append(f"Malware hashes: {', '.join(file_hashes[:2])}")
        ioc_block = (
            "\nTHREAT ACTOR IOCs (embed these exact values in the events):\n  "
            + "\n  ".join(ioc_parts)
        )

    # Build per-technique behavior hints
    actor_name = config.get("threat_actor_name", "")
    actor_prefix = f" ({actor_name})" if actor_name else ""

    ttp_lines: list[str] = []
    events_per_ttp = max(1, event_count // max(len(technique_ids), 1))
    remainder = event_count - events_per_ttp * len(technique_ids)

    for i, tid in enumerate(technique_ids):
        hint = TECHNIQUE_BEHAVIOR_HINTS.get(tid, "")
        # Try parent technique hint if no exact match
        if not hint and "." in tid:
            hint = TECHNIQUE_BEHAVIOR_HINTS.get(tid.split(".")[0], "")
        count = events_per_ttp + (1 if i < remainder else 0)
        if hint:
            ttp_lines.append(f"  - {tid} ({count} events): {hint}")
        else:
            ttp_lines.append(f"  - {tid} ({count} events)")

    ttp_block = "\n".join(ttp_lines)

    user_prompt = f"""Generate {event_count} realistic SIEM log events for adversary techniques{actor_prefix}.

TECHNIQUES TO SIMULATE (generate the specified number of events for each):
{ttp_block}

{asset_block}
{ioc_block}

RULES:
- Use the environment hostnames, IPs, and usernames above — NOT invented ones
- Embed the real C2 IPs/domains/hashes from the IOC list wherever events reference external infrastructure
- Each event must have field "technique_id" set to the exact MITRE ID (e.g. "T1059.001")
- Use realistic source types: windows_eventlog, sysmon, firewall, edr, proxy, dns, auth
- Timestamps should progress chronologically across a 2-8 hour attack window
- Vary severity: critical/high for credential access and impact; medium for lateral movement; low/info for discovery
- Payload fields must match the source_type (EventID for windows/sysmon, src_ip/dst_ip for firewall, etc.)
- Generate events for EVERY technique listed above"""

    try:
        return await _call_llm_for_events(user_prompt, event_count)
    except Exception as exc:
        log.warning("Targeted LLM generation failed for %s: %s", technique_ids, exc)
        return []


async def _generate_events_llm(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Call the LLM to generate log events for the given simulation config (generic fallback)."""
    try:
        mode = config.get("simulation_mode", "attack_chain")
        event_count = min(int(config.get("event_count", 50)), 200)
        actor_name = config.get("threat_actor_name", "Unknown Threat Actor")
        technique_ids = config.get("technique_ids", []) or config.get("threat_actor_ttps", [])
        iocs = config.get("iocs", [])

        if mode == "threat_actor":
            ttps_str = ", ".join(technique_ids[:20]) if technique_ids else "T1566, T1059, T1078, T1021"
            ioc_str = ""
            if iocs:
                ioc_values = [i.get("value", i) if isinstance(i, dict) else str(i) for i in iocs[:10]]
                ioc_str = f"\n\nUse these real IOCs: {', '.join(ioc_values)}"
            user_prompt = f"""Generate {event_count} realistic SIEM log events for a {actor_name} attack simulation.

TTPs (use these MITRE IDs, set technique_id field per event): {ttps_str}
{ioc_str}

Attack timeline: initial access → execution → persistence → lateral movement → collection → exfiltration.
Use realistic hostnames (CORP-WS-01, SERVER-DC01), IPs (192.168.x.x internal), usernames (jsmith, agarcia)."""

        elif mode == "ttps":
            ttps_str = ", ".join(technique_ids[:20]) if technique_ids else "T1059, T1078"
            user_prompt = f"""Generate {event_count} realistic SIEM log events for these adversary techniques: {ttps_str}

Show realistic artifacts for each technique. Include process creation, network connections, registry changes.
Use internal network 192.168.0.0/16, hostnames CORP-PC-xxx / DC01 / FILESERVER."""

        else:
            chains = config.get("attack_chains", ["apt29_cred"])
            user_prompt = f"""Generate {event_count} realistic SIEM log events for attack chain(s): {', '.join(chains)}.

Full kill chain from initial access through exfiltration. Map each event to a MITRE ATT&CK technique_id."""

        return await _call_llm_for_events(user_prompt, event_count)

    except Exception as exc:
        log.warning("LLM event generation failed: %s — using fallback", exc)
        return _fallback_events(config)


def _fallback_events(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate basic fallback events when LLM is unavailable."""
    mode = config.get("simulation_mode", "attack_chain")
    count = min(int(config.get("event_count", 20)), 50)
    ttps = config.get("technique_ids") or config.get("threat_actor_ttps") or ["T1059.001", "T1078", "T1021.001"]
    actor = config.get("threat_actor_name", "Threat Actor")

    templates = [
        {"source_type": "windows_eventlog", "technique_id": "T1059.001", "severity": "high",
         "title": "PowerShell execution with suspicious flags",
         "payload": {"EventID": 4688, "ProcessName": "powershell.exe", "CommandLine": "powershell -enc <base64>", "Computer": "CORP-WS-01"}},
        {"source_type": "sysmon", "technique_id": "T1078", "severity": "high",
         "title": "Logon with privileged account from unusual host",
         "payload": {"EventID": 4624, "SubjectUserName": "svc_backup", "LogonType": 3, "IpAddress": "10.0.0.52"}},
        {"source_type": "firewall", "technique_id": "T1041", "severity": "critical",
         "title": "Large data transfer to external IP",
         "payload": {"src_ip": "192.168.1.10", "dst_ip": "185.220.101.42", "dst_port": 443, "bytes_out": 524288, "action": "allow"}},
        {"source_type": "dns", "technique_id": "T1071.004", "severity": "medium",
         "title": "DNS query to suspicious domain",
         "payload": {"query": "c2.malicious-domain.ru", "query_type": "A", "answer": "185.220.101.42", "client_ip": "192.168.1.10"}},
        {"source_type": "edr", "technique_id": "T1003.001", "severity": "critical",
         "title": "LSASS memory access detected",
         "payload": {"process_name": "mimikatz.exe", "alert_name": "Credential Dumping", "action_taken": "blocked", "parent_process": "cmd.exe"}},
    ]

    from datetime import timedelta
    now = datetime.utcnow()
    events = []
    for i in range(count):
        tpl = templates[i % len(templates)].copy()
        ttp = ttps[i % len(ttps)] if ttps else tpl["technique_id"]
        tpl["technique_id"] = ttp
        tpl["timestamp"] = (now + timedelta(seconds=i * 30)).isoformat()
        tpl["title"] = f"[{actor}] {tpl['title']}"
        events.append(tpl)
    return events


def _session_row_to_dict(row: SimulationSession) -> dict[str, Any]:
    """Convert a SimulationSession ORM row to a plain dict."""
    return {
        "session_id": str(row.id),
        "name": row.name,
        "status": row.status,
        "config": row.config or {},
        "events_sent": row.events_sent,
        "errors": row.errors,
        "last_event_at": row.last_event_at.isoformat() if row.last_event_at else None,
        "stopped_at": row.stopped_at.isoformat() if row.stopped_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


class SessionManager:
    """Manages the lifecycle of simulation sessions.

    Uses PostgreSQL (via SQLAlchemy async) as the source of truth with an
    in-memory write-through cache for running sessions.
    """

    def __init__(self) -> None:
        # In-memory cache: session_id (str) -> dict
        self._sessions: dict[str, dict[str, Any]] = {}
        # Generator registry: session_id -> {product_id -> generator}
        self.generators: dict[str, dict[str, BaseGenerator]] = {}

    # ── Session CRUD ─────────────────────────────────────────────────────

    async def create_session(self, config: Any) -> dict[str, Any]:
        """Create a new simulation session, persisting it to the DB.

        Args:
            config: A SessionConfig-like object with at minimum
                    `session_id`, `name`, `products`, and `targets`.

        Returns:
            Session dict with all persisted fields.
        """
        # Derive a stable UUID from the provided session_id if available
        session_uuid: uuid.UUID
        sid = getattr(config, "session_id", None)
        if sid:
            try:
                session_uuid = uuid.UUID(str(sid))
            except ValueError:
                session_uuid = uuid.uuid4()
        else:
            session_uuid = uuid.uuid4()

        config_dict: dict[str, Any] = {}
        if hasattr(config, "dict"):
            try:
                config_dict = config.dict()
            except Exception:
                pass
        elif hasattr(config, "__dict__"):
            config_dict = {k: v for k, v in config.__dict__.items() if not k.startswith("_")}

        async with async_session() as db:
            row = SimulationSession(
                id=session_uuid,
                name=getattr(config, "name", "Untitled Session"),
                config=config_dict,
                status="running",
                events_sent=0,
                errors=0,
            )
            db.add(row)
            await db.commit()
            await db.refresh(row)
            session_dict = _session_row_to_dict(row)

        # Populate cache with the original config object for generator access
        self._sessions[session_dict["session_id"]] = session_dict
        # Keep original config object under a private key so build_generators works
        self._sessions[session_dict["session_id"]]["_config"] = config
        log.info("Session created: %s (%s)", session_dict["session_id"], row.name)
        return session_dict

    async def get_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a session by ID — checks cache first, then DB.

        Args:
            session_id: UUID string of the session.

        Returns:
            Session dict or None if not found.
        """
        # Check in-memory cache first
        cached = self._sessions.get(session_id)
        if cached is not None:
            return cached

        # Fall back to DB
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return None

        async with async_session() as db:
            row = await db.get(SimulationSession, session_uuid)
            if row is None:
                return None
            return _session_row_to_dict(row)

    async def list_sessions(
        self, status: Optional[str] = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """List sessions, optionally filtered by status.

        Args:
            status: If provided, only return sessions with this status.
            limit: Maximum number of sessions to return (default 50).

        Returns:
            List of session dicts ordered by created_at DESC.
        """
        async with async_session() as db:
            query = (
                select(SimulationSession)
                .order_by(SimulationSession.created_at.desc())
                .limit(limit)
            )
            if status is not None:
                query = query.where(SimulationSession.status == status)
            result = await db.execute(query)
            rows = result.scalars().all()
            return [_session_row_to_dict(r) for r in rows]

    async def update_session(
        self, session_id: str, **fields: Any
    ) -> Optional[dict[str, Any]]:
        """Update arbitrary fields on a session row.

        Supported field names match SimulationSession columns:
        name, config, status, events_sent, errors, last_event_at, stopped_at.

        Args:
            session_id: UUID string of the session.
            **fields: Column-name/value pairs to update.

        Returns:
            Updated session dict or None if not found.
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return None

        allowed = {
            "name", "config", "status", "events_sent",
            "errors", "last_event_at", "stopped_at",
        }
        update_kwargs = {k: v for k, v in fields.items() if k in allowed}
        if not update_kwargs:
            return await self.get_session(session_id)

        async with async_session() as db:
            row = await db.get(SimulationSession, session_uuid)
            if row is None:
                return None
            for key, value in update_kwargs.items():
                setattr(row, key, value)
            await db.commit()
            await db.refresh(row)
            session_dict = _session_row_to_dict(row)

        # Update cache if present
        if session_id in self._sessions:
            cfg = self._sessions[session_id].get("_config")
            self._sessions[session_id] = session_dict
            if cfg is not None:
                self._sessions[session_id]["_config"] = cfg

        return session_dict

    async def store_event(
        self, session_id: str, event_data: dict[str, Any]
    ) -> Optional[dict[str, Any]]:
        """Persist a generated event to the DB and update session counters.

        Args:
            session_id: UUID string of the owning session.
            event_data: Dict containing at minimum product_type, severity,
                        title, payload, target_url, status_code, success.

        Returns:
            Dict representation of the inserted event row, or None on failure.
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            log.warning("store_event: invalid session_id %s", session_id)
            return None

        async with async_session() as db:
            event = GeneratedEvent(
                session_id=session_uuid,
                product_type=event_data.get("product_type", "unknown"),
                severity=event_data.get("severity", "medium"),
                title=event_data.get("title", ""),
                payload=event_data.get("payload"),
                target_url=event_data.get("target_url", ""),
                status_code=int(event_data.get("status_code", 0)),
                success=bool(event_data.get("success", False)),
            )
            db.add(event)

            # Increment session counters in the same transaction
            row = await db.get(SimulationSession, session_uuid)
            if row is not None:
                row.events_sent = (row.events_sent or 0) + 1
                if not event.success:
                    row.errors = (row.errors or 0) + 1
                row.last_event_at = datetime.utcnow()

            await db.commit()
            await db.refresh(event)

            event_dict = {
                "id": str(event.id),
                "session_id": str(event.session_id),
                "product_type": event.product_type,
                "severity": event.severity,
                "title": event.title,
                "payload": event.payload,
                "target_url": event.target_url,
                "status_code": event.status_code,
                "success": event.success,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            }

        # Refresh cache counters
        if session_id in self._sessions and row is not None:
            self._sessions[session_id]["events_sent"] = row.events_sent
            self._sessions[session_id]["errors"] = row.errors
            self._sessions[session_id]["last_event_at"] = (
                row.last_event_at.isoformat() if row.last_event_at else None
            )

        return event_dict

    async def get_events(
        self,
        session_id: str,
        since_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve generated events for a session.

        Args:
            session_id: UUID string of the session.
            since_id: If provided, return only events created after this event ID.
            limit: Maximum events to return.

        Returns:
            List of event dicts ordered by created_at ASC.
        """
        try:
            session_uuid = uuid.UUID(session_id)
        except ValueError:
            return []

        async with async_session() as db:
            query = (
                select(GeneratedEvent)
                .where(GeneratedEvent.session_id == session_uuid)
                .order_by(GeneratedEvent.created_at.asc())
                .limit(limit)
            )

            if since_id is not None:
                try:
                    since_uuid = uuid.UUID(since_id)
                    # Fetch the reference event's created_at for cursor pagination
                    ref = await db.get(GeneratedEvent, since_uuid)
                    if ref is not None:
                        query = query.where(
                            GeneratedEvent.created_at > ref.created_at
                        )
                except ValueError:
                    pass

            result = await db.execute(query)
            rows = result.scalars().all()

        return [
            {
                "id": str(r.id),
                "session_id": str(r.session_id),
                "product_type": r.product_type,
                "severity": r.severity,
                "title": r.title,
                "payload": r.payload,
                "target_url": r.target_url,
                "status_code": r.status_code,
                "success": r.success,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]

    # ── Generator management ─────────────────────────────────────────────

    def build_generators(self, session_id: str) -> dict[str, BaseGenerator]:
        """Instantiate generators for all products in a session.

        Reads the original config object stored in the cache under _config.

        Args:
            session_id: UUID string of the session.

        Returns:
            Dict mapping product_id -> generator instance.
        """
        cached = self._sessions.get(session_id)
        if not cached:
            return {}
        config = cached.get("_config")
        if config is None:
            return {}

        gens: dict[str, BaseGenerator] = {}
        for product in getattr(config, "products", []):
            gen_cls = GENERATOR_REGISTRY.get(product.product_type)
            if gen_cls:
                gens[product.id] = gen_cls(product.config)
        self.generators[session_id] = gens
        return gens

    # ── LLM-backed simulation ─────────────────────────────────────────────────

    async def start_session(self, session_id: str, config: dict[str, Any]) -> None:
        """Launch LLM-based event generation for the session as a background task.

        Generates realistic SIEM log events using the configured LLM in batches
        of BATCH_SIZE so the first events appear within ~10s. Persists each batch
        immediately so the SSE stream picks them up in real time.

        Library-first optimisation: if technique_ids are present, the TTP event
        template library is checked first. If it has templates covering all
        requested techniques, all events are generated from the library with zero
        LLM calls. Otherwise the normal LLM batch loop runs and its output is
        saved back to the library for future sessions.
        """
        self._active_tasks = getattr(self, "_active_tasks", {})

        async def _run() -> None:
            from backend.engine.ttp_library import (
                get_asset_pool,
                get_templates_for_techniques,
                generate_events_from_library,
                save_llm_events_as_templates,
                seed_builtin_templates,
            )
            from backend.engine.benign_library import generate_benign_events
            from backend.engine.simulation_context import ContextBuilder, save_context
            from backend.engine.topology_graph import build_topology, topology_aware_event_filter

            total_target = min(int(config.get("event_count", 50)), 500)
            emitted = 0

            # Ratio: 60% benign baseline + 40% attack events (min 5 attack per TTP)
            BENIGN_RATIO = 0.60
            ATTACK_WINDOW_SECONDS = 28800  # 8-hour work day

            log.info("start_session sid=%s mode=%s target=%d", session_id, config.get("simulation_mode"), total_target)

            # Seed builtin templates and load asset/IOC pools
            async with async_session() as db:
                await seed_builtin_templates(db)
                asset_pool = await get_asset_pool(db, config.get("environment_id"))

            # Build SimulationContext — tries CMDB first, falls back to synthetic
            sim_ctx = None
            try:
                import os
                import redis.asyncio as aioredis
                _redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
                _redis = aioredis.from_url(_redis_url, decode_responses=True)
                async with async_session() as db:
                    sim_ctx = await ContextBuilder.build(
                        session_id=session_id,
                        environment_id=config.get("environment_id"),
                        db=db,
                        products=asset_pool.get("products") or {},
                    )
                await save_context(sim_ctx, _redis)
                # Mirror context entities back into asset_pool so legacy code paths
                # (LLM prompts that read asset_pool directly) also see the fixed values
                if sim_ctx.victim_hostname:
                    ep = {"hostname": sim_ctx.victim_hostname, "ip_address": sim_ctx.victim_ip or "192.168.1.10"}
                    if not asset_pool.get("endpoints"):
                        asset_pool["endpoints"] = [ep]
                    else:
                        asset_pool["endpoints"] = [ep] + asset_pool["endpoints"][1:]
                if sim_ctx.victim_username:
                    u = {"username": sim_ctx.victim_username, "email": sim_ctx.victim_email or ""}
                    if not asset_pool.get("users"):
                        asset_pool["users"] = [u]
                    else:
                        asset_pool["users"] = [u] + asset_pool["users"][1:]
                if sim_ctx.domain:
                    asset_pool["domain"] = sim_ctx.domain
                log.info("session %s: SimulationContext built (CMDB=%s) victim=%s@%s",
                         session_id, sim_ctx.from_cmdb, sim_ctx.victim_username, sim_ctx.victim_hostname)
                # Persist context summary in the session cache so the API can expose it.
                # Create the in-memory entry even if this session was started via REST
                # (where mgr.create_session() was never called and _sessions has no entry).
                ctx_summary = {
                    "victim_username": sim_ctx.victim_username,
                    "victim_hostname": sim_ctx.victim_hostname,
                    "victim_ip": sim_ctx.victim_ip,
                    "attacker_ip": sim_ctx.attacker_ip,
                    "c2_domain": sim_ctx.c2_domain,
                    "malware_filename": sim_ctx.malware_filename,
                    "domain": sim_ctx.domain,
                    "from_cmdb": sim_ctx.from_cmdb,
                }
                if session_id not in self._sessions:
                    self._sessions[session_id] = {}
                self._sessions[session_id]["simulation_context"] = ctx_summary
            except Exception as exc:
                log.warning("session %s: SimulationContext build failed (%s) — proceeding without context", session_id, exc)
                sim_ctx = None

            ioc_pool: list[dict[str, Any]] = config.get("iocs", []) or []

            technique_ids: list[str] = list(
                config.get("technique_ids", [])
                or config.get("threat_actor_ttps", [])
                or []
            )

            try:
                attack_events: list[dict[str, Any]] = []

                if technique_ids:
                    # How many attack events to generate
                    attack_target = max(len(technique_ids) * 3, int(total_target * (1 - BENIGN_RATIO)))

                    # ── Step 1: find which techniques have library coverage ────
                    async with async_session() as db:
                        templates_by_tech = await get_templates_for_techniques(db, technique_ids)

                    matched = [t for t in technique_ids if t in templates_by_tech]
                    unmatched = [t for t in technique_ids if t not in templates_by_tech]

                    log.info(
                        "session %s: %d/%d techniques covered by library, %d need LLM",
                        session_id, len(matched), len(technique_ids), len(unmatched),
                    )

                    # ── Step 2: generate from library for matched techniques ───
                    if matched:
                        lib_target = max(
                            len(matched) * 3,
                            int(attack_target * len(matched) / len(technique_ids)),
                        )
                        library_events = generate_events_from_library(
                            templates_by_tech, matched, lib_target, asset_pool, ioc_pool,
                            context=sim_ctx,
                        )
                        # Re-anchor attack events to the SECOND HALF of the work day
                        # (attacker strikes mid-to-late in the business day)
                        attack_start = ATTACK_WINDOW_SECONDS // 2
                        for ev in library_events:
                            ts_base = datetime.utcnow() - timedelta(seconds=ATTACK_WINDOW_SECONDS)
                            offset = random.randint(attack_start, ATTACK_WINDOW_SECONDS - 60)
                            ev["timestamp"] = (ts_base + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                        attack_events.extend(library_events)
                        log.info("session %s: library generated %d attack events", session_id, len(library_events))

                    # ── Step 3: LLM for unmatched techniques ──────────────────
                    if unmatched:
                        llm_target = max(len(unmatched) * 3, attack_target - len(attack_events))
                        llm_events = await _generate_events_llm_targeted(
                            unmatched, llm_target, config, asset_pool, ioc_pool,
                            context=sim_ctx,
                        )
                        if llm_events:
                            attack_events.extend(llm_events)
                            log.info("session %s: LLM generated %d events for %d techniques",
                                     session_id, len(llm_events), len(unmatched))
                            async with async_session() as db:
                                for tid in unmatched:
                                    tid_events = [e for e in llm_events if e.get("technique_id") == tid]
                                    if tid_events:
                                        await save_llm_events_as_templates(db, tid, tid_events)
                        else:
                            log.warning("session %s: LLM returned nothing for unmatched TTPs", session_id)
                            if templates_by_tech:
                                fill = generate_events_from_library(
                                    templates_by_tech, matched,
                                    attack_target - len(attack_events), asset_pool, ioc_pool,
                                    context=sim_ctx,
                                )
                                attack_events.extend(fill)

                else:
                    # No technique_ids — generic LLM generation (no benign mix for generic)
                    FIRST_BATCH = 8
                    BATCH_SIZE = 20
                    while emitted < total_target:
                        async with async_session() as db:
                            row = await db.get(SimulationSession, uuid.UUID(session_id))
                            if row is None or row.status != "running":
                                return

                        batch_limit = FIRST_BATCH if emitted == 0 else BATCH_SIZE
                        this_batch = min(batch_limit, total_target - emitted)
                        batch_events = await _generate_events_llm({**config, "event_count": this_batch})
                        if not batch_events:
                            break
                        attack_events.extend(batch_events)
                        emitted += len(batch_events)

                # ── Step 3b: Topology filter — discard events from products that
                #            have no line-of-sight to the techniques simulated ───
                products_cfg = asset_pool.get("products") or {}
                if products_cfg and technique_ids:
                    topology = build_topology(products_cfg)
                    filtered_attack: list[dict[str, Any]] = []
                    for ev in attack_events:
                        tid = ev.get("technique_id") or ev.get("_technique", "")
                        if tid:
                            valid_srcs = set(topology.resolve_log_sources(tid))
                            src = ev.get("source_type", ev.get("log_source", ""))
                            if not valid_srcs or not src or src in valid_srcs:
                                filtered_attack.append(ev)
                        else:
                            filtered_attack.append(ev)
                    if filtered_attack:
                        discarded = len(attack_events) - len(filtered_attack)
                        if discarded:
                            log.info("session %s: topology filter discarded %d events (wrong tier)",
                                     session_id, discarded)
                        attack_events = filtered_attack

                # ── Step 4: Generate benign baseline events ──────────────────
                benign_count = int(total_target * BENIGN_RATIO) if technique_ids else 0
                benign_events = generate_benign_events(
                    benign_count, asset_pool, ATTACK_WINDOW_SECONDS, context=sim_ctx
                )
                log.info("session %s: generated %d benign baseline events", session_id, len(benign_events))

                # ── Step 5: Merge, sort by timestamp, trim to total_target ────
                all_events = benign_events + attack_events
                all_events.sort(key=lambda e: e.get("timestamp", ""))
                if len(all_events) > total_target:
                    # Keep all attack events; trim benign to fit
                    attack_set = [e for e in all_events if not e.get("_benign")]
                    benign_set = [e for e in all_events if e.get("_benign")]
                    trim_benign = max(0, total_target - len(attack_set))
                    all_events = sorted(
                        attack_set + benign_set[:trim_benign],
                        key=lambda e: e.get("timestamp", "")
                    )

                interval = max(0.05, min(0.5, 30.0 / max(len(all_events), 1)))

                for i, evt in enumerate(all_events):
                    if i % 10 == 0:
                        async with async_session() as db:
                            row = await db.get(SimulationSession, uuid.UUID(session_id))
                            if row is None or row.status != "running":
                                return

                    payload = dict(evt.get("payload") or {})
                    payload["event_title"] = evt.get("title", "")
                    payload["_technique"] = evt.get("technique_id", "")
                    payload["_actor"] = config.get("threat_actor_name", "")
                    payload["_simulated"] = True
                    if evt.get("_benign"):
                        payload["_type"] = "baseline"
                    else:
                        payload["_type"] = "attack"

                    # Attach OCSF-normalized representation (best-effort, never blocks)
                    try:
                        from backend.engine.ocsf_normalizer import normalize_to_ocsf
                        src_type = evt.get("source_type", "")
                        vendor, product = _infer_vendor_product(src_type)
                        if vendor:
                            payload["_ocsf"] = normalize_to_ocsf(
                                payload,
                                vendor=vendor,
                                product=product,
                                source_type=src_type,
                            )
                    except Exception:
                        pass

                    # Run event through state machines and threat graph
                    try:
                        from backend.engine.edr_state_machine import get_machine
                        from backend.engine.threat_graph import get_graph
                        from backend.engine.product_state_machines import get_bundle
                        machine = get_machine(session_id)
                        bundle = get_bundle(session_id)
                        graph = get_graph(session_id)
                        # Ingest into threat graph
                        graph.ingest_event(evt)
                        # State machines: only attack events drive transitions
                        if not evt.get("_benign"):
                            secondary_evts = machine.process_event(evt)
                            secondary_evts.extend(bundle.process_event(evt))
                            for sec in secondary_evts:
                                sec_payload = dict(sec.get("payload") or {})
                                sec_payload["_simulated"] = True
                                sec_payload["_type"] = "state_transition"
                                sec_payload["_technique"] = sec.get("technique_id", "")
                                await self.store_event(session_id, {
                                    "product_type": sec.get("source_type", "edr"),
                                    "severity": sec.get("severity", "medium"),
                                    "title": sec.get("technique_id", "") or sec.get("title", ""),
                                    "payload": sec_payload,
                                    "target_url": "",
                                    "status_code": 200,
                                    "success": True,
                                })
                    except Exception:
                        pass

                    await self.store_event(session_id, {
                        "product_type": evt.get("source_type", "generic"),
                        "severity": evt.get("severity", "info"),
                        "title": evt.get("technique_id") or evt.get("title", ""),
                        "payload": payload,
                        "target_url": "",
                        "status_code": 200,
                        "success": True,
                    })
                    emitted += 1
                    await asyncio.sleep(interval)

                # Mark session complete
                async with async_session() as db:
                    row = await db.get(SimulationSession, uuid.UUID(session_id))
                    if row and row.status == "running":
                        row.status = "completed"
                        row.stopped_at = datetime.utcnow()
                        await db.commit()
                log.info("session %s completed (%d events emitted)", session_id, emitted)

            except Exception as exc:
                log.error("session %s generation error: %s", session_id, exc, exc_info=True)
                async with async_session() as db:
                    row = await db.get(SimulationSession, uuid.UUID(session_id))
                    if row:
                        row.status = "failed"
                        row.stopped_at = datetime.utcnow()
                        await db.commit()
            finally:
                self._active_tasks.pop(session_id, None)

        task = asyncio.create_task(_run())
        self._active_tasks[session_id] = task

    async def stop_session(self, session_id: str) -> Optional[dict[str, Any]]:
        """Stop a session — cancels active generation task and marks stopped."""
        # Cancel any running generation task
        active_tasks = getattr(self, "_active_tasks", {})
        task = active_tasks.pop(session_id, None)
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        now = datetime.utcnow()
        result = await self.update_session(
            session_id, status="stopped", stopped_at=now
        )
        self._sessions.pop(session_id, None)
        self.generators.pop(session_id, None)
        # Clean up per-session state machines and threat graph
        try:
            from backend.engine.edr_state_machine import drop_machine
            from backend.engine.threat_graph import drop_graph
            from backend.engine.product_state_machines import drop_bundle
            drop_machine(session_id)
            drop_graph(session_id)
            drop_bundle(session_id)
        except Exception:
            pass
        return result


# ── Singleton ─────────────────────────────────────────────────────────────────

_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Return the process-level singleton SessionManager."""
    global _manager
    if _manager is None:
        _manager = SessionManager()
    return _manager
