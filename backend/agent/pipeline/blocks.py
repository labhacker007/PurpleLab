"""Block registry — the atomic Lego pieces the pipeline engine can execute.

Each block is a self-contained operation with declared:
  - inputs   : what it needs (some required, some resolved from upstream outputs)
  - outputs  : what it produces for downstream blocks
  - fn       : the async function that does the work
  - category : logical grouping for display and routing

Blocks are pure functions: same inputs → same outputs.
They never depend on global state — all context flows through the pipeline context dict.

Block input values support two forms:
  "my_env_id": "{{create_env.environment_id}}"   ← resolved from upstream output
  "my_env_id": "some-literal-value"              ← literal (from user or pipeline template)
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
        inputs: dict[str, dict],      # name → {type, required, description}
        outputs: dict[str, dict],     # name → {type, description}
        fn: Callable[..., Awaitable[dict]],
    ) -> None:
        self.block_id = block_id
        self.category = category
        self.label = label
        self.description = description
        self.inputs = inputs
        self.outputs = outputs
        self.fn = fn

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.block_id,
            "category": self.category,
            "label": self.label,
            "description": self.description,
            "inputs": self.inputs,
            "outputs": self.outputs,
        }


# ── Block functions ───────────────────────────────────────────────────────────

async def _blk_create_environment(name: str, description: str = "", **_) -> dict:
    import httpx
    r = await httpx.AsyncClient(timeout=20).post(
        "http://localhost:8000/api/v2/environments",
        json={"name": name, "description": description},
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_environment: {r.status_code} {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {"environment_id": str(data.get("id", "")), "environment_name": data.get("name", name)}


async def _blk_add_product(environment_id: str, product: str, version: str = "latest", **_) -> dict:
    import httpx
    r = await httpx.AsyncClient(timeout=15).put(
        f"http://localhost:8000/api/v2/environments/{environment_id}",
        json={"products": {product: version}},
    )
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"add_product: {r.status_code} {r.text[:200]}")
    return {"environment_id": environment_id, "product": product, "version": version}


async def _blk_apply_threat_profile(environment_id: str, threat_actor: str, technique_ids: list[str] | None = None, **_) -> dict:
    import httpx
    r = await httpx.AsyncClient(timeout=20).post(
        f"http://localhost:8000/api/v2/environments/{environment_id}/threat-profiles",
        json={"threat_actor": threat_actor, "technique_ids": technique_ids or []},
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"apply_threat_profile: {r.status_code} {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    tids = data.get("technique_ids", [])
    return {
        "environment_id": environment_id,
        "threat_actor": threat_actor,
        "technique_ids": tids,
        "technique_count": data.get("technique_count", len(tids)),
    }


async def _blk_list_scenarios(environment_id: str = "", tags: list[str] | None = None, technique_ids: list[str] | None = None, **_) -> dict:
    from backend.db.session import async_session
    from backend.db.models import SimulationScenario
    from sqlalchemy import select
    async with async_session() as db:
        result = await db.execute(select(SimulationScenario))
        all_scenarios = result.scalars().all()
    items = [{"id": str(s.id), "name": s.name, "tags": s.tags or [], "technique_ids": s.technique_ids or []}
             for s in all_scenarios]
    # filter by tags
    if tags:
        items = [s for s in items if any(t in s["tags"] for t in tags)]
    # filter by technique_ids
    if technique_ids:
        items = [s for s in items if any(t in s["technique_ids"] for t in technique_ids)]
    return {"scenarios": items, "total": len(items), "scenario_ids": [s["id"] for s in items]}


async def _blk_run_scenario(scenario_id: str, **_) -> dict:
    import httpx
    r = await httpx.AsyncClient(timeout=60).post(
        f"http://localhost:8000/api/v2/scenarios/{scenario_id}/replay"
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"run_scenario: {r.status_code} {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {"session_id": str(data.get("id", "")), "scenario_id": scenario_id, "status": data.get("status", "started")}


async def _blk_run_scenario_batch(scenario_ids: list[str], **_) -> dict:
    """Run multiple scenarios sequentially — returns a summary of all sessions."""
    sessions = []
    errors = []
    for sid in scenario_ids[:10]:  # cap at 10 per batch
        try:
            result = await _blk_run_scenario(scenario_id=sid)
            sessions.append(result)
        except Exception as exc:
            errors.append({"scenario_id": sid, "error": str(exc)})
    return {
        "sessions": sessions,
        "session_ids": [s["session_id"] for s in sessions],
        "total_run": len(sessions),
        "errors": errors,
    }


async def _blk_create_use_case(name: str, technique_id: str = "", description: str = "", sigma_rule_ids: list[str] | None = None, **_) -> dict:
    import httpx
    payload = {"name": name, "description": description, "technique_id": technique_id, "sigma_rule_ids": sigma_rule_ids or []}
    r = await httpx.AsyncClient(timeout=15).post("http://localhost:8000/api/v2/use-cases", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"create_use_case: {r.status_code} {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {"use_case_id": str(data.get("id", "")), "name": name, "technique_id": technique_id}


async def _blk_run_use_case(use_case_id: str, **_) -> dict:
    import httpx
    r = await httpx.AsyncClient(timeout=60).post(f"http://localhost:8000/api/v2/use-cases/{use_case_id}/run")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"run_use_case: {r.status_code} {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {"use_case_id": use_case_id, "status": data.get("status", "unknown"), "result": data}


async def _blk_run_all_use_cases(**_) -> dict:
    import httpx
    r = await httpx.AsyncClient(timeout=120).post("http://localhost:8000/api/v2/use-cases/run-all")
    if r.status_code not in (200, 201):
        raise RuntimeError(f"run_all_use_cases: {r.status_code} {r.text[:200]}")
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
        des = await http.get("http://localhost:8000/api/v2/scoring/des")
        ihds = await http.get("http://localhost:8000/api/v2/scoring/ihds")
    des_data = (des.json().get("data") if des.status_code == 200 else {}) or {}
    ihds_data = (ihds.json().get("data") if ihds.status_code == 200 else {}) or {}
    return {
        "des_score": des_data.get("score", 0),
        "ihds_score": ihds_data.get("score", 0),
        "des_trend": des_data.get("trend", "stable"),
        "ihds_trend": ihds_data.get("trend", "stable"),
    }


async def _blk_get_gap_analysis(**_) -> dict:
    import httpx
    r = await httpx.AsyncClient(timeout=30).get("http://localhost:8000/api/v2/scoring/gaps")
    if r.status_code != 200:
        raise RuntimeError(f"gap_analysis: {r.status_code}")
    d = r.json()
    data = d.get("data", d)
    gaps = data.get("gaps", [])
    return {"gaps": gaps[:20], "gap_count": len(gaps), "top_gap_techniques": [g.get("technique_id") for g in gaps[:5]]}


async def _blk_import_sigma_rules(technique_id: str = "", search: str = "", limit: int = 5, **_) -> dict:
    import httpx
    params: dict = {"limit": limit}
    if technique_id:
        params["technique_id"] = technique_id
    if search:
        params["search"] = search
    r = await httpx.AsyncClient(timeout=15).get("http://localhost:8000/api/v2/sigma-rules/library", params=params)
    if r.status_code != 200:
        raise RuntimeError(f"import_sigma_rules: {r.status_code}")
    d = r.json()
    data = d.get("data", d)
    rules = data.get("rules", [])
    return {"rule_ids": [str(r.get("id")) for r in rules], "rule_count": len(rules), "rules": rules[:5]}


async def _blk_generate_report(report_type: str = "coverage", date_range_days: int = 30, **_) -> dict:
    import httpx
    payload = {"report_type": report_type, "date_range_days": date_range_days}
    r = await httpx.AsyncClient(timeout=30).post("http://localhost:8000/api/v2/reports/generate", json=payload)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"generate_report: {r.status_code} {r.text[:200]}")
    d = r.json()
    data = d.get("data", d)
    return {"report_id": str(data.get("id", "")), "report_type": report_type, "url": data.get("url", "")}


async def _blk_deploy_to_siem(rule_ids: list[str], siem_connection_id: str = "", **_) -> dict:
    import httpx
    results = []
    for rid in rule_ids[:20]:
        r = await httpx.AsyncClient(timeout=15).post(
            f"http://localhost:8000/api/v2/sigma-rules/{rid}/deploy",
            json={"siem_connection_id": siem_connection_id},
        )
        results.append({"rule_id": rid, "deployed": r.status_code in (200, 201)})
    deployed = sum(1 for r in results if r["deployed"])
    return {"deployed_count": deployed, "total": len(rule_ids), "results": results}


async def _blk_noop(**_) -> dict:
    """No-op block — useful as a synchronisation gate in parallel pipelines."""
    return {"status": "ok"}


# ── Block registry ────────────────────────────────────────────────────────────

BLOCK_REGISTRY: dict[str, BlockDef] = {}


def _reg(block_id: str, category: str, label: str, description: str,
         inputs: dict, outputs: dict, fn: Callable) -> None:
    BLOCK_REGISTRY[block_id] = BlockDef(block_id, category, label, description, inputs, outputs, fn)


# Infrastructure
_reg("create_environment", "infrastructure", "Create Environment",
     "Create a new simulation environment.",
     inputs={"name": {"type": "string", "required": True, "description": "Environment name"},
             "description": {"type": "string", "required": False, "description": "What this env represents"}},
     outputs={"environment_id": {"type": "string"}, "environment_name": {"type": "string"}},
     fn=_blk_create_environment)

_reg("add_product", "infrastructure", "Add Product",
     "Add a security product to an environment (crowdstrike, splunk, okta, etc.).",
     inputs={"environment_id": {"type": "string", "required": True},
             "product": {"type": "string", "required": True, "description": "Product type e.g. crowdstrike"},
             "version": {"type": "string", "required": False, "description": "Version tag, default: latest"}},
     outputs={"environment_id": {"type": "string"}, "product": {"type": "string"}, "version": {"type": "string"}},
     fn=_blk_add_product)

# Threat intelligence
_reg("apply_threat_profile", "threat_intel", "Apply Threat Profile",
     "Apply a threat actor profile to an environment — loads their TTPs.",
     inputs={"environment_id": {"type": "string", "required": True},
             "threat_actor": {"type": "string", "required": True, "description": "Actor name e.g. APT29, BlackCat"},
             "technique_ids": {"type": "array", "required": False, "description": "Specific TTP IDs (auto-loaded if blank)"}},
     outputs={"environment_id": {"type": "string"}, "threat_actor": {"type": "string"},
              "technique_ids": {"type": "array"}, "technique_count": {"type": "integer"}},
     fn=_blk_apply_threat_profile)

# Scenarios
_reg("list_scenarios", "simulation", "List Scenarios",
     "Find simulation scenarios by tag or technique ID.",
     inputs={"environment_id": {"type": "string", "required": False},
             "tags": {"type": "array", "required": False, "description": "Filter by tags e.g. ['lateral_movement']"},
             "technique_ids": {"type": "array", "required": False, "description": "Filter by MITRE technique IDs"}},
     outputs={"scenarios": {"type": "array"}, "scenario_ids": {"type": "array"}, "total": {"type": "integer"}},
     fn=_blk_list_scenarios)

_reg("run_scenario", "simulation", "Run Scenario",
     "Run a single simulation scenario.",
     inputs={"scenario_id": {"type": "string", "required": True, "description": "Scenario UUID"}},
     outputs={"session_id": {"type": "string"}, "scenario_id": {"type": "string"}, "status": {"type": "string"}},
     fn=_blk_run_scenario)

_reg("run_scenario_batch", "simulation", "Run Scenario Batch",
     "Run multiple scenarios in sequence and return all session IDs.",
     inputs={"scenario_ids": {"type": "array", "required": True, "description": "List of scenario UUIDs to run"}},
     outputs={"sessions": {"type": "array"}, "session_ids": {"type": "array"},
              "total_run": {"type": "integer"}, "errors": {"type": "array"}},
     fn=_blk_run_scenario_batch)

# Detection
_reg("import_sigma_rules", "detection", "Import Sigma Rules",
     "Find and import Sigma rules from the library for a given technique.",
     inputs={"technique_id": {"type": "string", "required": False},
             "search": {"type": "string", "required": False},
             "limit": {"type": "integer", "required": False, "description": "Max rules to return, default 5"}},
     outputs={"rule_ids": {"type": "array"}, "rule_count": {"type": "integer"}},
     fn=_blk_import_sigma_rules)

_reg("create_use_case", "detection", "Create Use Case",
     "Create a detection use case linking a technique to Sigma rules.",
     inputs={"name": {"type": "string", "required": True},
             "technique_id": {"type": "string", "required": False},
             "description": {"type": "string", "required": False},
             "sigma_rule_ids": {"type": "array", "required": False}},
     outputs={"use_case_id": {"type": "string"}, "name": {"type": "string"}, "technique_id": {"type": "string"}},
     fn=_blk_create_use_case)

_reg("run_use_case", "detection", "Run Use Case",
     "Run a single detection use case test.",
     inputs={"use_case_id": {"type": "string", "required": True}},
     outputs={"use_case_id": {"type": "string"}, "status": {"type": "string"}},
     fn=_blk_run_use_case)

_reg("run_all_use_cases", "detection", "Run All Use Cases",
     "Run all detection use cases and return pass/fail summary.",
     inputs={},
     outputs={"total": {"type": "integer"}, "passed": {"type": "integer"},
              "failed": {"type": "integer"}, "pass_rate": {"type": "number"}},
     fn=_blk_run_all_use_cases)

_reg("deploy_to_siem", "detection", "Deploy Rules to SIEM",
     "Deploy a set of Sigma rules to the connected SIEM.",
     inputs={"rule_ids": {"type": "array", "required": True},
             "siem_connection_id": {"type": "string", "required": False}},
     outputs={"deployed_count": {"type": "integer"}, "total": {"type": "integer"}},
     fn=_blk_deploy_to_siem)

# Scoring
_reg("calculate_scores", "scoring", "Calculate Scores",
     "Calculate DES and IHDS scores for the current environment.",
     inputs={},
     outputs={"des_score": {"type": "number"}, "ihds_score": {"type": "number"},
              "des_trend": {"type": "string"}, "ihds_trend": {"type": "string"}},
     fn=_blk_calculate_scores)

_reg("get_gap_analysis", "scoring", "Get Gap Analysis",
     "Identify MITRE ATT&CK techniques with no detection coverage.",
     inputs={},
     outputs={"gaps": {"type": "array"}, "gap_count": {"type": "integer"},
              "top_gap_techniques": {"type": "array"}},
     fn=_blk_get_gap_analysis)

# Reporting
_reg("generate_report", "reporting", "Generate Report",
     "Generate a coverage, use-case, or session report.",
     inputs={"report_type": {"type": "string", "required": False,
                              "description": "coverage | use_cases | pipeline | session, default: coverage"},
             "date_range_days": {"type": "integer", "required": False, "description": "Days of data, default 30"}},
     outputs={"report_id": {"type": "string"}, "report_type": {"type": "string"}, "url": {"type": "string"}},
     fn=_blk_generate_report)

_reg("noop", "utility", "No-Op Gate",
     "Synchronisation gate — completes immediately. Use as a merge point for parallel branches.",
     inputs={},
     outputs={"status": {"type": "string"}},
     fn=_blk_noop)


def get_block(block_id: str) -> BlockDef | None:
    return BLOCK_REGISTRY.get(block_id)
