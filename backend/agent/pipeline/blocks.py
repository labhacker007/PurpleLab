"""Block registry — the atomic Lego pieces the pipeline engine can execute.

Every block declares:
  inputs  : {name → {type, required, description}}
  outputs : {name → {type, description}}          ← typed; validated at pipeline construction time

The LLM sees ONLY the schema (id, description, inputs, outputs) — never the implementation.
This is the minimal token payload needed to compose valid pipelines.

Type system (JSON Schema subset):
  "string", "integer", "number", "boolean", "array", "object"

Connection rule: output_type must be compatible with input_type (see executor._COMPAT).
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


# ── Block definition ──────────────────────────────────────────────────────────

class BlockDef:
    def __init__(
        self,
        block_id: str,
        category: str,
        label: str,
        description: str,
        inputs: dict[str, dict],
        outputs: dict[str, dict],
        fn: Callable[..., Awaitable[dict]],
        tags: list[str] | None = None,
    ) -> None:
        self.block_id = block_id
        self.category = category
        self.label = label
        self.description = description
        self.inputs = inputs
        self.outputs = outputs
        self.fn = fn
        self.tags = tags or []

    def schema(self) -> dict[str, Any]:
        """Minimal schema for LLM composition — no implementation details."""
        return {
            "id": self.block_id,
            "category": self.category,
            "label": self.label,
            "description": self.description,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "tags": self.tags,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.schema()


# ── Block functions ───────────────────────────────────────────────────────────

async def _blk_create_environment(name: str, description: str = "", **_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=20) as http:
        r = await http.post(
            "http://localhost:8000/api/v2/environments",
            json={"name": name, "description": description},
        )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_environment failed ({r.status_code}): {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {
        "environment_id": str(data.get("id", "")),
        "environment_name": data.get("name", name),
    }


async def _blk_add_product(environment_id: str, product: str, version: str = "latest", **_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=15) as http:
        r = await http.put(
            f"http://localhost:8000/api/v2/environments/{environment_id}",
            json={"products": {product: version}},
        )
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"add_product failed ({r.status_code}): {r.text[:200]}")
    return {"environment_id": environment_id, "product": product, "version": version}


async def _blk_apply_threat_profile(
    environment_id: str, threat_actor: str, technique_ids: list[str] | None = None, **_
) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=20) as http:
        r = await http.post(
            f"http://localhost:8000/api/v2/environments/{environment_id}/threat-profiles",
            json={"threat_actor": threat_actor, "technique_ids": technique_ids or []},
        )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"apply_threat_profile failed ({r.status_code}): {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    tids = data.get("technique_ids", [])
    return {
        "environment_id": environment_id,
        "threat_actor": threat_actor,
        "technique_ids": tids,
        "technique_count": data.get("technique_count", len(tids)),
    }


async def _blk_list_scenarios(
    environment_id: str = "",
    tags: list[str] | None = None,
    technique_ids: list[str] | None = None,
    **_,
) -> dict:
    from backend.db.session import async_session
    from backend.db.models import SimulationScenario
    from sqlalchemy import select

    async with async_session() as db:
        result = await db.execute(select(SimulationScenario))
        all_scenarios = result.scalars().all()

    items = [
        {"id": str(s.id), "name": s.name, "tags": s.tags or [], "technique_ids": s.technique_ids or []}
        for s in all_scenarios
    ]
    if tags:
        items = [s for s in items if any(t in s["tags"] for t in tags)]
    if technique_ids:
        items = [s for s in items if any(t in s["technique_ids"] for t in technique_ids)]

    return {"scenarios": items, "scenario_ids": [s["id"] for s in items], "total": len(items)}


async def _blk_run_scenario(scenario_id: str, **_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=60) as http:
        r = await http.post(f"http://localhost:8000/api/v2/scenarios/{scenario_id}/replay")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"run_scenario failed ({r.status_code}): {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {
        "session_id": str(data.get("id", "")),
        "scenario_id": scenario_id,
        "status": data.get("status", "started"),
        "event_count": data.get("event_count", 0),
    }


async def _blk_run_scenario_batch(scenario_ids: list[str], **_) -> dict:
    """Run up to 10 scenarios concurrently within the batch."""
    import asyncio as _asyncio

    async def _one(sid: str) -> dict:
        return await _blk_run_scenario(scenario_id=sid)

    tasks = [_one(sid) for sid in scenario_ids[:10]]
    raw = await _asyncio.gather(*tasks, return_exceptions=True)

    sessions = []
    errors = []
    for sid, outcome in zip(scenario_ids[:10], raw):
        if isinstance(outcome, Exception):
            errors.append({"scenario_id": sid, "error": str(outcome)})
        else:
            sessions.append(outcome)

    return {
        "sessions": sessions,
        "session_ids": [s["session_id"] for s in sessions],
        "total_run": len(sessions),
        "errors": errors,
    }


async def _blk_create_use_case(
    name: str,
    technique_id: str = "",
    description: str = "",
    sigma_rule_ids: list[str] | None = None,
    **_,
) -> dict:
    import httpx
    payload = {
        "name": name,
        "description": description,
        "technique_id": technique_id,
        "sigma_rule_ids": sigma_rule_ids or [],
    }
    async with httpx.AsyncClient(timeout=15) as http:
        r = await http.post("http://localhost:8000/api/v2/use-cases", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_use_case failed ({r.status_code}): {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {
        "use_case_id": str(data.get("id", "")),
        "name": name,
        "technique_id": technique_id,
    }


async def _blk_run_use_case(use_case_id: str, **_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=60) as http:
        r = await http.post(f"http://localhost:8000/api/v2/use-cases/{use_case_id}/run")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"run_use_case failed ({r.status_code}): {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {
        "use_case_id": use_case_id,
        "status": data.get("status", "unknown"),
        "passed": data.get("passed", False),
        "detection_fired": data.get("detection_fired", False),
    }


async def _blk_run_all_use_cases(**_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=120) as http:
        r = await http.post("http://localhost:8000/api/v2/use-cases/run-all")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"run_all_use_cases failed ({r.status_code}): {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {
        "total": data.get("total", 0),
        "passed": data.get("passed", 0),
        "failed": data.get("failed", 0),
        "pass_rate": data.get("pass_rate", 0.0),
    }


async def _blk_calculate_scores(**_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=30) as http:
        des_r, ihds_r = await _asyncio_gather_http(http, [
            ("GET", "http://localhost:8000/api/v2/scoring/des"),
            ("GET", "http://localhost:8000/api/v2/scoring/ihds"),
        ])
    des_data = (des_r.json().get("data") if des_r.status_code == 200 else {}) or {}
    ihds_data = (ihds_r.json().get("data") if ihds_r.status_code == 200 else {}) or {}
    return {
        "des_score": des_data.get("score", 0),
        "ihds_score": ihds_data.get("score", 0),
        "des_trend": des_data.get("trend", "stable"),
        "ihds_trend": ihds_data.get("trend", "stable"),
        "des_grade": des_data.get("grade", ""),
    }


async def _asyncio_gather_http(client: Any, requests: list[tuple[str, str]]) -> list:
    import asyncio
    tasks = [
        client.get(url) if method == "GET" else client.post(url)
        for method, url in requests
    ]
    return await asyncio.gather(*tasks)


async def _blk_get_gap_analysis(**_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.get("http://localhost:8000/api/v2/scoring/gaps")
    if r.status_code != 200:
        raise RuntimeError(f"get_gap_analysis failed ({r.status_code})")
    d = r.json()
    data = d.get("data", d)
    gaps = data.get("gaps", [])
    return {
        "gaps": gaps[:20],
        "gap_count": len(gaps),
        "top_gap_techniques": [g.get("technique_id") for g in gaps[:5]],
    }


async def _blk_import_sigma_rules(technique_id: str = "", search: str = "", limit: int = 5, **_) -> dict:
    import httpx
    params: dict = {"limit": limit}
    if technique_id:
        params["technique_id"] = technique_id
    if search:
        params["search"] = search
    async with httpx.AsyncClient(timeout=15) as http:
        r = await http.get("http://localhost:8000/api/v2/sigma-rules/library", params=params)
    if r.status_code != 200:
        raise RuntimeError(f"import_sigma_rules failed ({r.status_code})")
    d = r.json()
    data = d.get("data", d)
    rules = data.get("rules", [])
    return {
        "rule_ids": [str(rule.get("id")) for rule in rules],
        "rule_count": len(rules),
        "rules_summary": [{"id": str(rule.get("id")), "title": rule.get("title", "")} for rule in rules[:5]],
    }


async def _blk_generate_report(report_type: str = "coverage", date_range_days: int = 30, **_) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.post(
            "http://localhost:8000/api/v2/reports/generate",
            json={"report_type": report_type, "date_range_days": date_range_days},
        )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"generate_report failed ({r.status_code}): {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {
        "report_id": str(data.get("id", "")),
        "report_type": report_type,
        "url": data.get("url", ""),
        "generated_at": data.get("generated_at", ""),
    }


async def _blk_deploy_to_siem(rule_ids: list[str], siem_connection_id: str = "", **_) -> dict:
    import httpx
    import asyncio

    async def _deploy_one(rid: str) -> dict:
        async with httpx.AsyncClient(timeout=15) as http:
            r = await http.post(
                f"http://localhost:8000/api/v2/sigma-rules/{rid}/deploy",
                json={"siem_connection_id": siem_connection_id},
            )
        return {"rule_id": rid, "deployed": r.status_code in (200, 201)}

    results = await asyncio.gather(*[_deploy_one(rid) for rid in rule_ids[:20]])
    deployed = sum(1 for r in results if r["deployed"])
    return {
        "deployed_count": deployed,
        "failed_count": len(rule_ids) - deployed,
        "total": len(rule_ids),
        "results": list(results),
    }


async def _blk_noop(**_) -> dict:
    return {"status": "ok"}


# ── Registry ──────────────────────────────────────────────────────────────────

BLOCK_REGISTRY: dict[str, BlockDef] = {}


def _reg(
    block_id: str,
    category: str,
    label: str,
    description: str,
    inputs: dict,
    outputs: dict,
    fn: Callable,
    tags: list[str] | None = None,
) -> None:
    BLOCK_REGISTRY[block_id] = BlockDef(
        block_id, category, label, description, inputs, outputs, fn, tags
    )


# ── Infrastructure ────────────────────────────────────────────────────────────

_reg(
    "create_environment", "infrastructure", "Create Environment",
    "Create a new simulation environment.",
    inputs={
        "name":        {"type": "string",  "required": True,  "description": "Environment name"},
        "description": {"type": "string",  "required": False, "description": "What this env represents"},
    },
    outputs={
        "environment_id":   {"type": "string", "description": "UUID of the created environment"},
        "environment_name": {"type": "string", "description": "Name of the created environment"},
    },
    fn=_blk_create_environment,
    tags=["setup", "quick-start"],
)

_reg(
    "add_product", "infrastructure", "Add Product",
    "Add a security product to an environment (crowdstrike, splunk, okta, defender, elastic…).",
    inputs={
        "environment_id": {"type": "string", "required": True,  "description": "Target environment UUID"},
        "product":        {"type": "string", "required": True,  "description": "Product type e.g. crowdstrike, splunk"},
        "version":        {"type": "string", "required": False, "description": "Version tag; default: latest"},
    },
    outputs={
        "environment_id": {"type": "string"},
        "product":        {"type": "string"},
        "version":        {"type": "string"},
    },
    fn=_blk_add_product,
    tags=["setup"],
)

# ── Threat intelligence ───────────────────────────────────────────────────────

_reg(
    "apply_threat_profile", "threat_intel", "Apply Threat Profile",
    "Apply a threat actor profile to an environment — loads their TTPs automatically.",
    inputs={
        "environment_id": {"type": "string", "required": True,  "description": "Target environment UUID"},
        "threat_actor":   {"type": "string", "required": True,  "description": "Actor name e.g. APT29, BlackCat, Lazarus"},
        "technique_ids":  {"type": "array",  "required": False, "description": "Override specific TTP IDs (auto-loaded if omitted)"},
    },
    outputs={
        "environment_id":  {"type": "string",  "description": "Same environment UUID (pass-through for chaining)"},
        "threat_actor":    {"type": "string"},
        "technique_ids":   {"type": "array",   "description": "List of MITRE technique IDs that were loaded"},
        "technique_count": {"type": "integer", "description": "Number of TTPs loaded"},
    },
    fn=_blk_apply_threat_profile,
    tags=["threat-intel", "setup"],
)

# ── Simulation ────────────────────────────────────────────────────────────────

_reg(
    "list_scenarios", "simulation", "List Scenarios",
    "Find simulation scenarios by tag or MITRE technique ID.",
    inputs={
        "environment_id": {"type": "string", "required": False, "description": "Filter by environment (optional)"},
        "tags":           {"type": "array",  "required": False, "description": "Filter tags e.g. ['lateral_movement', 'persistence']"},
        "technique_ids":  {"type": "array",  "required": False, "description": "Filter by MITRE technique IDs"},
    },
    outputs={
        "scenarios":    {"type": "array",   "description": "Full scenario objects"},
        "scenario_ids": {"type": "array",   "description": "UUID list — pass to run_scenario_batch"},
        "total":        {"type": "integer"},
    },
    fn=_blk_list_scenarios,
    tags=["simulation"],
)

_reg(
    "run_scenario", "simulation", "Run Scenario",
    "Run a single simulation scenario and return the session ID.",
    inputs={
        "scenario_id": {"type": "string", "required": True, "description": "Scenario UUID"},
    },
    outputs={
        "session_id":   {"type": "string"},
        "scenario_id":  {"type": "string"},
        "status":       {"type": "string"},
        "event_count":  {"type": "integer"},
    },
    fn=_blk_run_scenario,
    tags=["simulation"],
)

_reg(
    "run_scenario_batch", "simulation", "Run Scenario Batch",
    "Run up to 10 scenarios concurrently and return all session IDs.",
    inputs={
        "scenario_ids": {"type": "array", "required": True, "description": "List of scenario UUIDs"},
    },
    outputs={
        "sessions":    {"type": "array",   "description": "Per-session result objects"},
        "session_ids": {"type": "array",   "description": "UUID list of created sessions"},
        "total_run":   {"type": "integer"},
        "errors":      {"type": "array"},
    },
    fn=_blk_run_scenario_batch,
    tags=["simulation"],
)

# ── Detection ─────────────────────────────────────────────────────────────────

_reg(
    "import_sigma_rules", "detection", "Import Sigma Rules",
    "Find Sigma rules from the library matching a technique ID or search query.",
    inputs={
        "technique_id": {"type": "string",  "required": False, "description": "MITRE technique ID e.g. T1059.001"},
        "search":       {"type": "string",  "required": False, "description": "Keyword search"},
        "limit":        {"type": "integer", "required": False, "description": "Max results; default 5"},
    },
    outputs={
        "rule_ids":      {"type": "array",   "description": "UUID list — pass to create_use_case or deploy_to_siem"},
        "rule_count":    {"type": "integer"},
        "rules_summary": {"type": "array",   "description": "Brief {id, title} list for display"},
    },
    fn=_blk_import_sigma_rules,
    tags=["detection"],
)

_reg(
    "create_use_case", "detection", "Create Use Case",
    "Create a detection use case linking a MITRE technique to Sigma rules.",
    inputs={
        "name":           {"type": "string", "required": True,  "description": "Use case name"},
        "technique_id":   {"type": "string", "required": False},
        "description":    {"type": "string", "required": False},
        "sigma_rule_ids": {"type": "array",  "required": False, "description": "Sigma rule UUIDs to attach"},
    },
    outputs={
        "use_case_id":  {"type": "string"},
        "name":         {"type": "string"},
        "technique_id": {"type": "string"},
    },
    fn=_blk_create_use_case,
    tags=["detection"],
)

_reg(
    "run_use_case", "detection", "Run Use Case",
    "Run a detection use case test and return pass/fail.",
    inputs={
        "use_case_id": {"type": "string", "required": True},
    },
    outputs={
        "use_case_id":      {"type": "string"},
        "status":           {"type": "string",  "description": "passed | failed | error"},
        "passed":           {"type": "boolean"},
        "detection_fired":  {"type": "boolean"},
    },
    fn=_blk_run_use_case,
    tags=["detection"],
)

_reg(
    "run_all_use_cases", "detection", "Run All Use Cases",
    "Run every detection use case and return a pass/fail summary.",
    inputs={},
    outputs={
        "total":     {"type": "integer"},
        "passed":    {"type": "integer"},
        "failed":    {"type": "integer"},
        "pass_rate": {"type": "number",  "description": "0.0–1.0"},
    },
    fn=_blk_run_all_use_cases,
    tags=["detection", "coverage-drill"],
)

_reg(
    "deploy_to_siem", "detection", "Deploy Rules to SIEM",
    "Deploy Sigma rules to the connected SIEM (Splunk, Sentinel, QRadar…).",
    inputs={
        "rule_ids":          {"type": "array",  "required": True,  "description": "Sigma rule UUIDs"},
        "siem_connection_id":{"type": "string", "required": False, "description": "Target SIEM connection UUID"},
    },
    outputs={
        "deployed_count": {"type": "integer"},
        "failed_count":   {"type": "integer"},
        "total":          {"type": "integer"},
        "results":        {"type": "array"},
    },
    fn=_blk_deploy_to_siem,
    tags=["detection", "siem"],
)

# ── Scoring ───────────────────────────────────────────────────────────────────

_reg(
    "calculate_scores", "scoring", "Calculate Scores",
    "Calculate DES (Detection Effectiveness Score) and IHDS scores for the current state.",
    inputs={},
    outputs={
        "des_score":  {"type": "number",  "description": "Detection Effectiveness Score 0–100"},
        "ihds_score": {"type": "number",  "description": "Intrusion Hunt Detection Score 0–100"},
        "des_trend":  {"type": "string",  "description": "improving | stable | declining"},
        "ihds_trend": {"type": "string"},
        "des_grade":  {"type": "string",  "description": "A–F letter grade"},
    },
    fn=_blk_calculate_scores,
    tags=["scoring"],
)

_reg(
    "get_gap_analysis", "scoring", "Get Gap Analysis",
    "Identify MITRE ATT&CK techniques with no detection coverage.",
    inputs={},
    outputs={
        "gaps":               {"type": "array",   "description": "Full gap objects with technique details"},
        "gap_count":          {"type": "integer"},
        "top_gap_techniques": {"type": "array",   "description": "Top-5 uncovered technique IDs — use to target sigma import or scenario run"},
    },
    fn=_blk_get_gap_analysis,
    tags=["scoring", "gap-closure"],
)

# ── Reporting ─────────────────────────────────────────────────────────────────

_reg(
    "generate_report", "reporting", "Generate Report",
    "Generate a coverage, use-case, pipeline, or session report.",
    inputs={
        "report_type":    {"type": "string",  "required": False,
                           "description": "coverage | use_cases | pipeline | session; default: coverage"},
        "date_range_days":{"type": "integer", "required": False, "description": "Days of data to include; default: 30"},
    },
    outputs={
        "report_id":    {"type": "string"},
        "report_type":  {"type": "string"},
        "url":          {"type": "string"},
        "generated_at": {"type": "string"},
    },
    fn=_blk_generate_report,
    tags=["reporting"],
)

# ── Utility ───────────────────────────────────────────────────────────────────

_reg(
    "noop", "utility", "No-Op Gate",
    "Synchronisation gate — completes instantly. Use as a fan-in merge point when parallel branches need to converge before the next step.",
    inputs={},
    outputs={
        "status": {"type": "string"},
    },
    fn=_blk_noop,
    tags=["utility"],
)


def get_block(block_id: str) -> BlockDef | None:
    return BLOCK_REGISTRY.get(block_id)
