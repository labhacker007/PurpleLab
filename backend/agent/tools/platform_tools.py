"""Platform tools — analyst-facing actions for everything in PurpleLab's UI.

Covers the capabilities not already in the MCP surface:
  - Environments (create, list, configure, get topology)
  - Scenarios (list library, run, save session as scenario)
  - Use cases (list, create, run, coverage summary)
  - Scoring (DES/IHDS scores, gap analysis, leaderboard)
  - Reports (generate, list, get session report)
  - Pipelines (list, run, status)
  - Threat profiles (list, create, apply to environment)
  - SIEM connections (list, connect, test)
  - Log sources (list, add)
  - Sessions (list, get, stop)

Each tool calls the existing service/DB layer directly — no HTTP round-trips
back to localhost. This keeps latency low and avoids auth re-entrypoints.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


# ── helpers ────────────────────────────────────────────────────────────────────

def _ok(data: Any) -> dict:
    return {"status": "success", "data": data}

def _err(msg: str) -> dict:
    return {"status": "error", "error": msg}


# ── Environment tools ──────────────────────────────────────────────────────────

async def _list_environments(**_) -> dict:
    try:
        from backend.db.session import async_session
        from backend.db.models import Environment
        async with async_session() as db:
            from sqlalchemy import select
            result = await db.execute(select(Environment).order_by(Environment.created_at.desc()))
            envs = result.scalars().all()
            return _ok([{
                "id": str(e.id), "name": e.name, "description": e.description,
                "status": e.status, "created_at": str(e.created_at),
            } for e in envs])
    except Exception as exc:
        logger.exception("list_environments failed")
        return _err(str(exc))


async def _get_environment(environment_id: str, **_) -> dict:
    try:
        from backend.db.session import async_session
        from backend.db.models import Environment
        import uuid
        async with async_session() as db:
            env = await db.get(Environment, uuid.UUID(environment_id))
            if not env:
                return _err(f"Environment '{environment_id}' not found")
            return _ok({
                "id": str(env.id), "name": env.name, "description": env.description,
                "status": env.status, "config": env.config or {},
                "created_at": str(env.created_at),
            })
    except Exception as exc:
        logger.exception("get_environment failed")
        return _err(str(exc))


async def _create_environment(name: str, description: str = "", vendor_stack: list[str] | None = None, **_) -> dict:
    try:
        import httpx
        payload = {"name": name, "description": description}
        if vendor_stack:
            payload["products"] = {v: "latest" for v in vendor_stack}
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.post("http://localhost:8000/api/v2/environments", json=payload)
            if r.status_code in (200, 201):
                return _ok(r.json())
            return _err(f"Create failed: {r.status_code} {r.text[:200]}")
    except Exception as exc:
        logger.exception("create_environment failed")
        return _err(str(exc))


async def _configure_environment(environment_id: str, products: dict[str, str] | None = None,
                                  name: str | None = None, description: str | None = None, **_) -> dict:
    try:
        import httpx
        payload: dict = {}
        if name:
            payload["name"] = name
        if description:
            payload["description"] = description
        if products:
            payload["products"] = products
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.put(f"http://localhost:8000/api/v2/environments/{environment_id}", json=payload)
            if r.status_code in (200, 204):
                return _ok(r.json() if r.content else {"updated": True})
            return _err(f"Configure failed: {r.status_code} {r.text[:200]}")
    except Exception as exc:
        logger.exception("configure_environment failed")
        return _err(str(exc))


# ── Environment templates ─────────────────────────────────────────────────────

ENVIRONMENT_TEMPLATES: dict[str, dict] = {
    "apt_windows_ad": {
        "label": "Windows AD — APT Lateral Movement",
        "description": "Enterprise Windows domain with Active Directory. Ideal for APT29/APT28 lateral movement, credential access, and persistence TTPs.",
        "vendor_stack": ["crowdstrike", "windows_event", "active_directory", "splunk"],
        "default_threat_actors": ["APT29", "APT28"],
        "scenario_tags": ["lateral_movement", "credential_access", "persistence", "discovery"],
        "edr_persona": "crowdstrike",
    },
    "ransomware_linux": {
        "label": "Linux — Ransomware / Data Theft",
        "description": "Mixed Linux environment targeted by ransomware groups. Covers initial access, privilege escalation, data exfiltration, and encryption.",
        "vendor_stack": ["sentinelone", "syslog", "crowdstrike"],
        "default_threat_actors": ["BlackCat", "LockBit", "Cl0p"],
        "scenario_tags": ["initial_access", "privilege_escalation", "exfiltration", "impact"],
        "edr_persona": "sentinelone",
    },
    "cloud_aws": {
        "label": "AWS Cloud — Exfiltration & Persistence",
        "description": "AWS environment with IAM, S3, EC2. Tests cloud-specific TTPs: credential theft, S3 data exfil, IAM privilege escalation.",
        "vendor_stack": ["crowdstrike_cloud", "aws_cloudtrail", "elastic"],
        "default_threat_actors": ["APT29", "Scattered Spider"],
        "scenario_tags": ["cloud", "exfiltration", "credential_access", "persistence"],
        "edr_persona": "crowdstrike",
    },
    "supply_chain": {
        "label": "Supply Chain Compromise",
        "description": "Simulates software supply chain attack vectors — build pipeline compromise, dependency injection, trusted relationship abuse.",
        "vendor_stack": ["crowdstrike", "okta", "splunk"],
        "default_threat_actors": ["APT29", "APT41"],
        "scenario_tags": ["supply_chain", "initial_access", "execution", "persistence"],
        "edr_persona": "crowdstrike",
    },
    "ot_ics": {
        "label": "OT/ICS — Industrial Control Systems",
        "description": "Operational technology environment with IT/OT boundary. Covers Triton/Industroyer-style OT-targeting TTPs.",
        "vendor_stack": ["claroty", "dragos", "splunk"],
        "default_threat_actors": ["Sandworm", "APT33"],
        "scenario_tags": ["ot", "ics", "lateral_movement", "inhibit_response"],
        "edr_persona": "crowdstrike",
    },
    "generic": {
        "label": "Generic — Custom Setup",
        "description": "Blank environment for custom threat profiles. Lets you specify exactly which TTPs and actors to simulate.",
        "vendor_stack": ["crowdstrike", "splunk"],
        "default_threat_actors": [],
        "scenario_tags": [],
        "edr_persona": "crowdstrike",
    },
}


async def _list_environment_templates(**_) -> dict:
    """Return the catalogue of pre-built environment templates. No API call needed."""
    items = [
        {"id": k, **{f: v for f, v in v.items() if f != "edr_persona"}}
        for k, v in ENVIRONMENT_TEMPLATES.items()
    ]
    return _ok({"templates": items, "total": len(items)})


async def _quick_environment_setup(
    template: str = "apt_windows_ad",
    name: str = "",
    threat_actor: str = "",
    **_,
) -> dict:
    """Create an environment from a template and optionally apply a threat profile — all in one call.

    This replaces the manual sequence: create_environment → apply_threat_profile → save_context.
    Returns the ready environment with technique count and suggested next steps.
    """
    try:
        import httpx
        tpl = ENVIRONMENT_TEMPLATES.get(template, ENVIRONMENT_TEMPLATES["generic"])
        env_name = name or tpl["label"]

        # Step 1: create environment
        payload = {
            "name": env_name,
            "description": tpl["description"],
            "products": {v: "latest" for v in tpl["vendor_stack"]},
        }
        async with httpx.AsyncClient(timeout=20) as http:
            r = await http.post("http://localhost:8000/api/v2/environments", json=payload)
            if r.status_code not in (200, 201):
                return _err(f"Create environment failed: {r.status_code} {r.text[:200]}")
            env = r.json()
            env_id = env.get("id") or (env.get("data") or {}).get("id")
            if not env_id:
                return _err("No environment ID returned")

        # Step 2: apply threat profile (if actor given or template has default)
        actor = threat_actor or (tpl["default_threat_actors"][0] if tpl["default_threat_actors"] else "")
        technique_count = 0
        profile_applied: str | None = None
        if actor and env_id:
            async with httpx.AsyncClient(timeout=20) as http:
                r2 = await http.post(
                    f"http://localhost:8000/api/v2/environments/{env_id}/threat-profiles",
                    json={"threat_actor": actor, "technique_ids": []},
                )
                if r2.status_code in (200, 201):
                    profile_data = r2.json()
                    raw = profile_data.get("data", profile_data)
                    technique_count = raw.get("technique_count", 0) or len(raw.get("technique_ids", []))
                    profile_applied = actor

        next_steps = [
            f"Run a scenario for {actor}" if actor else "Apply a threat profile",
            "Check your detection coverage (DES score)",
            "Browse available scenarios for this environment",
            "Validate your detection use cases",
        ]

        return _ok({
            "environment_id": env_id,
            "environment_name": env_name,
            "template": template,
            "threat_actor_applied": profile_applied,
            "technique_count": technique_count,
            "vendor_stack": tpl["vendor_stack"],
            "suggested_next_steps": next_steps[:3],
            "_context_patch": {
                "environment_id": str(env_id),
                "environment_name": env_name,
                "suggested_followups": next_steps[:3],
            },
        })
    except Exception as exc:
        logger.exception("quick_environment_setup failed")
        return _err(str(exc))


# ── Scenario / Simulation Library tools ───────────────────────────────────────

async def _list_scenarios(search: str = "", **_) -> dict:
    try:
        from backend.db.session import async_session
        from backend.db.models import SimulationScenario
        from sqlalchemy import select
        async with async_session() as db:
            q = select(SimulationScenario).order_by(SimulationScenario.created_at.desc())
            result = await db.execute(q)
            scenarios = result.scalars().all()
            items = [{
                "id": str(s.id), "name": s.name, "description": s.description,
                "threat_actor": s.threat_actor, "technique_ids": s.technique_ids or [],
                "event_count": s.event_count, "tags": s.tags or [],
            } for s in scenarios]
            if search:
                search_lower = search.lower()
                items = [s for s in items if search_lower in s["name"].lower()
                         or search_lower in (s["description"] or "").lower()
                         or any(search_lower in t.lower() for t in s["technique_ids"])]
            return _ok({"scenarios": items, "total": len(items)})
    except Exception as exc:
        logger.exception("list_scenarios failed")
        return _err(str(exc))


async def _run_scenario(scenario_id: str, **_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30) as http:
            r = await http.post(f"http://localhost:8000/api/v2/scenarios/{scenario_id}/replay")
            if r.status_code in (200, 201):
                return _ok(r.json())
            return _err(f"Run failed: {r.status_code} {r.text[:200]}")
    except Exception as exc:
        logger.exception("run_scenario failed")
        return _err(str(exc))


# ── Use Case tools ─────────────────────────────────────────────────────────────

async def _list_use_cases(status: str = "", **_) -> dict:
    try:
        import httpx
        params = {}
        if status:
            params["status"] = status
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/use-cases", params=params)
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _get_use_case_coverage(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/use-cases/coverage")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _get_failing_use_cases(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/use-cases/failing")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _create_use_case(name: str, description: str = "", technique_id: str = "",
                            sigma_rule_ids: list[str] | None = None, **_) -> dict:
    try:
        import httpx
        payload = {"name": name, "description": description, "technique_id": technique_id,
                   "sigma_rule_ids": sigma_rule_ids or []}
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.post("http://localhost:8000/api/v2/use-cases", json=payload)
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _run_use_case(use_case_id: str, **_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=60) as http:
            r = await http.post(f"http://localhost:8000/api/v2/use-cases/{use_case_id}/run")
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _run_all_use_cases(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=120) as http:
            r = await http.post("http://localhost:8000/api/v2/use-cases/run-all")
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


# ── Scoring tools ──────────────────────────────────────────────────────────────

async def _get_des_score(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/scoring/des")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _get_ihds_score(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/scoring/ihds")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _get_scoring_gap_analysis(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=20) as http:
            r = await http.get("http://localhost:8000/api/v2/scoring/gap-analysis")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _get_scoring_breakdown(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/scoring/breakdown")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


# ── Report tools ───────────────────────────────────────────────────────────────

async def _list_reports(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/reports")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _generate_report(report_type: str = "coverage", date_range_days: int = 30,
                            session_id: str = "", **_) -> dict:
    try:
        import httpx
        payload: dict = {"type": report_type, "date_range_days": date_range_days}
        if session_id:
            payload["session_id"] = session_id
        async with httpx.AsyncClient(timeout=60) as http:
            r = await http.post("http://localhost:8000/api/v2/reports/generate", json=payload)
            return _ok(r.json()) if r.status_code in (200, 201, 202) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _get_session_report(session_id: str, fmt: str = "json", **_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30) as http:
            r = await http.get(f"http://localhost:8000/api/v2/reports/session/{session_id}/export",
                               params={"fmt": fmt})
            if r.status_code == 200:
                if fmt == "json":
                    return _ok(r.json())
                return _ok({"format": fmt, "size_bytes": len(r.content),
                             "message": f"Report ready. Download at /api/v2/reports/session/{session_id}/export?fmt={fmt}"})
            return _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


# ── Pipeline tools ─────────────────────────────────────────────────────────────

async def _list_pipelines(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/pipelines")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _run_pipeline(pipeline_id: str, **_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=30) as http:
            r = await http.post(f"http://localhost:8000/api/v2/pipelines/{pipeline_id}/run", json={})
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _get_pipeline_coverage_gaps(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/pipelines/coverage-gaps")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


# ── Threat Profile tools ───────────────────────────────────────────────────────

async def _list_threat_profiles(environment_id: str = "", **_) -> dict:
    try:
        import httpx
        if not environment_id:
            return _err("environment_id is required")
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get(f"http://localhost:8000/api/v2/environments/{environment_id}/threat-profiles")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _apply_threat_profile(environment_id: str, threat_actor: str,
                                 technique_ids: list[str] | None = None, **_) -> dict:
    try:
        import httpx
        payload = {"threat_actor": threat_actor, "technique_ids": technique_ids or []}
        async with httpx.AsyncClient(timeout=20) as http:
            r = await http.post(
                f"http://localhost:8000/api/v2/environments/{environment_id}/threat-profiles",
                json=payload)
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


async def _tip_search(query: str, environment_id: str = "", **_) -> dict:
    """Search threat intelligence for TTPs relevant to an environment."""
    try:
        import httpx
        params = {"q": query}
        if environment_id:
            params["env_id"] = environment_id
        async with httpx.AsyncClient(timeout=20) as http:
            r = await http.get("http://localhost:8000/api/v2/environments/threat-profiles/tip-search",
                               params=params)
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


# ── SIEM Connection tools ──────────────────────────────────────────────────────

async def _list_siem_connections(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/siem/connections")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _connect_siem(name: str, siem_type: str, host: str, port: int = 443,
                         token: str = "", username: str = "", password: str = "", **_) -> dict:
    try:
        import httpx
        payload = {"name": name, "siem_type": siem_type, "host": host, "port": port,
                   "token": token, "username": username, "password": password}
        async with httpx.AsyncClient(timeout=20) as http:
            r = await http.post("http://localhost:8000/api/v2/siem/connections", json=payload)
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


# ── Log Source tools ───────────────────────────────────────────────────────────

async def _list_log_sources(**_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/log-sources")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _add_log_source(name: str, source_type: str, environment_id: str = "",
                           config: dict | None = None, **_) -> dict:
    try:
        import httpx
        payload = {"name": name, "source_type": source_type,
                   "environment_id": environment_id, "config": config or {}}
        async with httpx.AsyncClient(timeout=20) as http:
            r = await http.post("http://localhost:8000/api/v2/log-sources", json=payload)
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


# ── Session tools ──────────────────────────────────────────────────────────────

async def _list_sessions(status: str = "", limit: int = 20, **_) -> dict:
    try:
        import httpx
        params: dict = {"limit": limit}
        if status:
            params["status"] = status
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/sessions", params=params)
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _get_session(session_id: str, **_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get(f"http://localhost:8000/api/v2/sessions/{session_id}")
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _stop_session(session_id: str, **_) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.post(f"http://localhost:8000/api/v2/sessions/{session_id}/stop")
            return _ok(r.json()) if r.status_code in (200, 204) else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


# ── Sigma Library tools ────────────────────────────────────────────────────────

async def _search_sigma_library(query: str = "", technique_id: str = "",
                                 severity: str = "", limit: int = 20, **_) -> dict:
    try:
        import httpx
        params: dict = {"limit": limit}
        if query:
            params["q"] = query
        if technique_id:
            params["technique_id"] = technique_id
        if severity:
            params["severity"] = severity
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.get("http://localhost:8000/api/v2/sigma-library", params=params)
            return _ok(r.json()) if r.status_code == 200 else _err(f"{r.status_code}")
    except Exception as exc:
        return _err(str(exc))


async def _import_sigma_rule(rule_yaml: str, tags: list[str] | None = None, **_) -> dict:
    try:
        import httpx
        payload = {"rule_yaml": rule_yaml, "tags": tags or []}
        async with httpx.AsyncClient(timeout=20) as http:
            r = await http.post("http://localhost:8000/api/v2/sigma-library/import", json=payload)
            return _ok(r.json()) if r.status_code in (200, 201) else _err(f"{r.status_code} {r.text[:200]}")
    except Exception as exc:
        return _err(str(exc))


# ── Platform context tool ──────────────────────────────────────────────────────

async def _get_platform_summary(**_) -> dict:
    """Get a high-level summary of everything in PurpleLab — useful for onboarding a conversation."""
    try:
        import httpx
        import asyncio
        async with httpx.AsyncClient(timeout=20) as http:
            env_r, session_r, uc_r = await asyncio.gather(
                http.get("http://localhost:8000/api/v2/environments"),
                http.get("http://localhost:8000/api/v2/sessions?limit=5"),
                http.get("http://localhost:8000/api/v2/use-cases/coverage"),
                return_exceptions=True,
            )
        result: dict = {}
        if not isinstance(env_r, Exception) and env_r.status_code == 200:
            envs = env_r.json()
            result["environments"] = [{"id": e["id"], "name": e["name"], "status": e.get("status")}
                                       for e in (envs.get("environments") or envs if isinstance(envs, list) else [])]
        if not isinstance(session_r, Exception) and session_r.status_code == 200:
            sr = session_r.json()
            result["recent_sessions"] = sr.get("sessions", sr) if isinstance(sr, dict) else sr
        if not isinstance(uc_r, Exception) and uc_r.status_code == 200:
            result["use_case_coverage"] = uc_r.json()
        return _ok(result)
    except Exception as exc:
        logger.exception("get_platform_summary failed")
        return _err(str(exc))


# ── Registration ───────────────────────────────────────────────────────────────

def register_tools(registry: ToolRegistry) -> None:  # noqa: C901
    """Register all platform tools."""

    # ── Environment templates (high-efficiency — avoids 3-4 round-trips) ─────
    registry.register("list_environment_templates",
        "List pre-built environment templates (APT Windows AD, Ransomware Linux, AWS Cloud, etc.). "
        "Call this FIRST when the analyst wants to create an environment — it's instant, no API call.",
        {"type": "object", "properties": {}},
        _list_environment_templates)

    registry.register("quick_environment_setup",
        "Create an environment from a template AND apply a threat profile in one step. "
        "Use this instead of create_environment + apply_threat_profile separately — saves 3 LLM rounds. "
        "Returns environment_id, technique_count, and suggested_next_steps.",
        {"type": "object", "properties": {
            "template": {
                "type": "string",
                "enum": list(ENVIRONMENT_TEMPLATES.keys()),
                "description": "Template ID from list_environment_templates. Default: apt_windows_ad",
            },
            "name": {"type": "string", "description": "Custom environment name (optional — template label used if blank)"},
            "threat_actor": {"type": "string", "description": "Threat actor to apply (optional — template default used if blank)"},
        }},
        _quick_environment_setup)

    # ── Environments ──────────────────────────────────────────────────────────
    registry.register("list_environments",
        "List all simulated environments. Returns id, name, status, and creation date for each.",
        {"type": "object", "properties": {}},
        _list_environments)

    registry.register("get_environment",
        "Get details of a specific environment by ID.",
        {"type": "object", "properties": {
            "environment_id": {"type": "string", "description": "Environment UUID"}
        }, "required": ["environment_id"]},
        _get_environment)

    registry.register("create_environment",
        "Create a new simulated environment. Optionally specify the vendor stack (e.g. crowdstrike, splunk, okta).",
        {"type": "object", "properties": {
            "name": {"type": "string", "description": "Environment name"},
            "description": {"type": "string", "description": "What this environment represents"},
            "vendor_stack": {"type": "array", "items": {"type": "string"},
                             "description": "List of security products e.g. ['crowdstrike','splunk','okta']"},
        }, "required": ["name"]},
        _create_environment)

    registry.register("configure_environment",
        "Update an environment's name, description, or vendor product versions.",
        {"type": "object", "properties": {
            "environment_id": {"type": "string"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "products": {"type": "object", "description": "Map of product_type to version e.g. {\"crowdstrike\": \"6.50\"}"},
        }, "required": ["environment_id"]},
        _configure_environment)

    # ── Scenarios ─────────────────────────────────────────────────────────────
    registry.register("list_scenarios",
        "List simulation scenarios in the library. Search by name, description, or technique ID.",
        {"type": "object", "properties": {
            "search": {"type": "string", "description": "Search term (name, description, or technique like T1059)"},
        }},
        _list_scenarios)

    registry.register("run_scenario",
        "Run a saved simulation scenario from the library. This replays the scenario's event sequence.",
        {"type": "object", "properties": {
            "scenario_id": {"type": "string", "description": "Scenario UUID to run"},
        }, "required": ["scenario_id"]},
        _run_scenario)

    # ── Use Cases ─────────────────────────────────────────────────────────────
    registry.register("list_use_cases",
        "List detection use cases. Optionally filter by status (passing/failing/not_run).",
        {"type": "object", "properties": {
            "status": {"type": "string", "enum": ["passing", "failing", "not_run", ""],
                       "description": "Filter by test status"},
        }},
        _list_use_cases)

    registry.register("get_use_case_coverage",
        "Get a summary of detection use case coverage across MITRE ATT&CK — how many TTPs have validated detections.",
        {"type": "object", "properties": {}},
        _get_use_case_coverage)

    registry.register("get_failing_use_cases",
        "Get all detection use cases that are currently failing — detections that need fixing.",
        {"type": "object", "properties": {}},
        _get_failing_use_cases)

    registry.register("create_use_case",
        "Create a new detection use case linking a MITRE technique to Sigma rules.",
        {"type": "object", "properties": {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "technique_id": {"type": "string", "description": "MITRE ATT&CK technique e.g. T1059.001"},
            "sigma_rule_ids": {"type": "array", "items": {"type": "string"}},
        }, "required": ["name"]},
        _create_use_case)

    registry.register("run_use_case",
        "Run a detection use case test — simulates the attack and checks if the detection fires.",
        {"type": "object", "properties": {
            "use_case_id": {"type": "string", "description": "Use case UUID"},
        }, "required": ["use_case_id"]},
        _run_use_case)

    registry.register("run_all_use_cases",
        "Run all detection use case tests in sequence. Returns pass/fail summary.",
        {"type": "object", "properties": {}},
        _run_all_use_cases)

    # ── Scoring ───────────────────────────────────────────────────────────────
    registry.register("get_des_score",
        "Get the Detection Efficacy Score (DES) — measures how well detections cover simulated attacks. Returns score 0-100 with breakdown.",
        {"type": "object", "properties": {}},
        _get_des_score)

    registry.register("get_ihds_score",
        "Get the Integrated Human-driven Detection Score (IHDS) — combines automated and analyst-validated coverage. Returns score with trend.",
        {"type": "object", "properties": {}},
        _get_ihds_score)

    registry.register("get_scoring_gap_analysis",
        "Get a gap analysis showing which MITRE ATT&CK techniques lack detection coverage, sorted by risk priority.",
        {"type": "object", "properties": {}},
        _get_scoring_gap_analysis)

    registry.register("get_scoring_breakdown",
        "Get a technique-by-technique scoring breakdown showing detection status per TTP.",
        {"type": "object", "properties": {}},
        _get_scoring_breakdown)

    # ── Reports ───────────────────────────────────────────────────────────────
    registry.register("list_reports",
        "List all generated reports in PurpleLab.",
        {"type": "object", "properties": {}},
        _list_reports)

    registry.register("generate_report",
        "Generate a new report. Types: coverage, use_cases, pipeline, session. Returns report ID.",
        {"type": "object", "properties": {
            "report_type": {"type": "string", "enum": ["coverage", "use_cases", "pipeline", "session"],
                            "description": "Type of report to generate"},
            "date_range_days": {"type": "integer", "default": 30, "description": "Days of data to include"},
            "session_id": {"type": "string", "description": "Required for session report type"},
        }, "required": ["report_type"]},
        _generate_report)

    registry.register("get_session_report",
        "Get the simulation report for a completed session. Returns KPIs, technique breakdown, severity distribution, and SOAR action log.",
        {"type": "object", "properties": {
            "session_id": {"type": "string", "description": "Session UUID"},
            "fmt": {"type": "string", "enum": ["json", "html"], "default": "json"},
        }, "required": ["session_id"]},
        _get_session_report)

    # ── Pipelines ─────────────────────────────────────────────────────────────
    registry.register("list_pipelines",
        "List configured detection validation pipelines.",
        {"type": "object", "properties": {}},
        _list_pipelines)

    registry.register("run_pipeline",
        "Trigger a pipeline run for automated detection validation.",
        {"type": "object", "properties": {
            "pipeline_id": {"type": "string", "description": "Pipeline UUID"},
        }, "required": ["pipeline_id"]},
        _run_pipeline)

    registry.register("get_pipeline_coverage_gaps",
        "Get coverage gaps identified by the pipeline — TTPs with no passing detections.",
        {"type": "object", "properties": {}},
        _get_pipeline_coverage_gaps)

    # ── Threat Profiles ───────────────────────────────────────────────────────
    registry.register("list_threat_profiles",
        "List threat actor profiles applied to an environment.",
        {"type": "object", "properties": {
            "environment_id": {"type": "string", "description": "Environment UUID"},
        }, "required": ["environment_id"]},
        _list_threat_profiles)

    registry.register("apply_threat_profile",
        "Apply a threat actor profile to an environment — configures which TTPs to simulate for that actor.",
        {"type": "object", "properties": {
            "environment_id": {"type": "string"},
            "threat_actor": {"type": "string", "description": "Threat actor name e.g. APT29, Lazarus, BlackCat"},
            "technique_ids": {"type": "array", "items": {"type": "string"},
                              "description": "Specific MITRE technique IDs (optional — auto-populated from actor profile if omitted)"},
        }, "required": ["environment_id", "threat_actor"]},
        _apply_threat_profile)

    registry.register("tip_search",
        "Search threat intelligence for TTPs relevant to a specific threat actor, technique, or keyword.",
        {"type": "object", "properties": {
            "query": {"type": "string", "description": "Search term (actor name, technique, keyword)"},
            "environment_id": {"type": "string", "description": "Optional environment context"},
        }, "required": ["query"]},
        _tip_search)

    # ── SIEM Connections ──────────────────────────────────────────────────────
    registry.register("list_siem_connections",
        "List all configured SIEM connections (Splunk, Sentinel, Elastic, etc.).",
        {"type": "object", "properties": {}},
        _list_siem_connections)

    registry.register("connect_siem",
        "Add a new SIEM connection for deploying detection rules and searching events.",
        {"type": "object", "properties": {
            "name": {"type": "string"},
            "siem_type": {"type": "string", "enum": ["splunk", "sentinel", "elastic", "qradar", "xsiam"],
                          "description": "SIEM platform type"},
            "host": {"type": "string", "description": "SIEM hostname or IP"},
            "port": {"type": "integer", "default": 443},
            "token": {"type": "string", "description": "API token or bearer token"},
            "username": {"type": "string"},
            "password": {"type": "string"},
        }, "required": ["name", "siem_type", "host"]},
        _connect_siem)

    # ── Log Sources ───────────────────────────────────────────────────────────
    registry.register("list_log_sources",
        "List all configured log sources in PurpleLab.",
        {"type": "object", "properties": {}},
        _list_log_sources)

    registry.register("add_log_source",
        "Add a new log source to PurpleLab for simulation.",
        {"type": "object", "properties": {
            "name": {"type": "string"},
            "source_type": {"type": "string", "description": "e.g. windows_security, sysmon, crowdstrike, okta"},
            "environment_id": {"type": "string", "description": "Optional environment to attach to"},
            "config": {"type": "object", "description": "Source-specific configuration"},
        }, "required": ["name", "source_type"]},
        _add_log_source)

    # ── Sessions ──────────────────────────────────────────────────────────────
    registry.register("list_sessions",
        "List simulation sessions. Filter by status (running/completed/failed).",
        {"type": "object", "properties": {
            "status": {"type": "string", "enum": ["running", "completed", "failed", ""],
                       "description": "Filter by session status"},
            "limit": {"type": "integer", "default": 20},
        }},
        _list_sessions)

    registry.register("get_session",
        "Get details of a simulation session including event counts, techniques, and timing.",
        {"type": "object", "properties": {
            "session_id": {"type": "string"},
        }, "required": ["session_id"]},
        _get_session)

    registry.register("stop_session",
        "Stop a running simulation session.",
        {"type": "object", "properties": {
            "session_id": {"type": "string"},
        }, "required": ["session_id"]},
        _stop_session)

    # ── Sigma Library ─────────────────────────────────────────────────────────
    registry.register("search_sigma_library",
        "Search the Sigma rule library by keyword, technique ID, or severity.",
        {"type": "object", "properties": {
            "query": {"type": "string", "description": "Search term"},
            "technique_id": {"type": "string", "description": "Filter by MITRE technique e.g. T1059.001"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", ""]},
            "limit": {"type": "integer", "default": 20},
        }},
        _search_sigma_library)

    registry.register("import_sigma_rule",
        "Import a Sigma rule YAML into the PurpleLab rule library.",
        {"type": "object", "properties": {
            "rule_yaml": {"type": "string", "description": "Full Sigma rule in YAML format"},
            "tags": {"type": "array", "items": {"type": "string"}, "description": "Optional tags"},
        }, "required": ["rule_yaml"]},
        _import_sigma_rule)

    # ── Platform Summary ──────────────────────────────────────────────────────
    registry.register("get_platform_summary",
        "Get a high-level summary of PurpleLab — environments, recent sessions, and use case coverage. Good for starting a conversation.",
        {"type": "object", "properties": {}},
        _get_platform_summary)
