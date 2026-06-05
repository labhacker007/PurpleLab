"""Pipeline tools — give the AI agent the ability to compose and run modular pipelines.

Three tools:
  list_blocks()              → catalogue of all Lego pieces the agent can use
  run_pipeline(pipeline)     → execute a composed pipeline end-to-end
  get_pipeline_templates()   → pre-built pipeline recipes for common workflows
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Pre-built pipeline templates ─────────────────────────────────────────────

_PIPELINE_TEMPLATES = {
    "apt_red_team": {
        "name": "APT Red Team Exercise",
        "description": "Create an environment, apply a threat actor profile, run all matching scenarios, then score.",
        "steps": [
            {
                "id": "env",
                "block": "create_environment",
                "inputs": {"name": "APT Exercise", "description": "Automated APT red team pipeline"}
            },
            {
                "id": "profile",
                "block": "apply_threat_profile",
                "inputs": {"environment_id": "{{env.environment_id}}", "threat_actor": "APT29"}
            },
            {
                "id": "scenarios",
                "block": "list_scenarios",
                "inputs": {"technique_ids": "{{profile.technique_ids}}"}
            },
            {
                "id": "batch",
                "block": "run_scenario_batch",
                "inputs": {"scenario_ids": "{{scenarios.scenario_ids}}"}
            },
            {
                "id": "score",
                "block": "calculate_scores",
                "inputs": {}
            },
        ]
    },
    "detection_gap_close": {
        "name": "Detection Gap Closure",
        "description": "Find coverage gaps, import Sigma rules for the top undetected techniques, create use cases, and run them.",
        "steps": [
            {
                "id": "gaps",
                "block": "get_gap_analysis",
                "inputs": {}
            },
            {
                "id": "sigma",
                "block": "import_sigma_rules",
                "inputs": {"technique_id": "{{gaps.top_gap_techniques}}", "limit": 10}
            },
            {
                "id": "uc",
                "block": "create_use_case",
                "inputs": {
                    "name": "Auto Gap Use Case",
                    "sigma_rule_ids": "{{sigma.rule_ids}}"
                }
            },
            {
                "id": "run",
                "block": "run_use_case",
                "inputs": {"use_case_id": "{{uc.use_case_id}}"}
            },
            {
                "id": "report",
                "block": "generate_report",
                "inputs": {"report_type": "coverage", "date_range_days": 7}
            },
        ]
    },
    "full_coverage_drill": {
        "name": "Full Coverage Drill",
        "description": "Run every use case, score, then generate a coverage report.",
        "steps": [
            {
                "id": "run_all",
                "block": "run_all_use_cases",
                "inputs": {}
            },
            {
                "id": "score",
                "block": "calculate_scores",
                "inputs": {}
            },
            {
                "id": "report",
                "block": "generate_report",
                "inputs": {"report_type": "use_cases", "date_range_days": 1}
            },
        ]
    },
    "quick_assessment": {
        "name": "Quick Coverage Assessment",
        "description": "Score the current state, find gaps, and generate a report — no simulations.",
        "steps": [
            {
                "id": "score",
                "block": "calculate_scores",
                "inputs": {}
            },
            {
                "id": "gaps",
                "block": "get_gap_analysis",
                "inputs": {}
            },
            {
                "id": "report",
                "block": "generate_report",
                "inputs": {"report_type": "coverage", "date_range_days": 30}
            },
        ]
    },
}


# ── Tool implementations ──────────────────────────────────────────────────────

def _list_blocks() -> dict[str, Any]:
    from backend.agent.pipeline.blocks import BLOCK_REGISTRY
    by_category: dict[str, list[dict]] = {}
    for block in BLOCK_REGISTRY.values():
        by_category.setdefault(block.category, []).append({
            "id": block.block_id,
            "label": block.label,
            "description": block.description,
            "inputs": {
                k: {"type": v.get("type", "string"), "required": v.get("required", False),
                    "description": v.get("description", "")}
                for k, v in block.inputs.items()
            },
            "outputs": {k: v.get("type", "string") for k, v in block.outputs.items()},
            "tags": block.tags,
        })
    total = sum(len(v) for v in by_category.values())
    return {
        "categories": by_category,
        "total_blocks": total,
        "hint": (
            "To run a pipeline: compose a JSON with {name, steps:[{id, block, inputs}]} "
            "and call run_pipeline(). Use {{step_id.output_key}} to chain outputs as inputs. "
            "Independent steps run in parallel automatically. "
            "Or call get_pipeline_templates() for 4 ready-to-run recipes."
        ),
    }


async def _run_pipeline(pipeline: dict[str, Any]) -> dict[str, Any]:
    from backend.agent.pipeline.executor import PipelineExecutor
    executor = PipelineExecutor()
    try:
        result = await executor.run(pipeline)
    except Exception as exc:
        logger.error("pipeline_executor_error: %s", exc, exc_info=True)
        return {"error": str(exc), "pipeline_name": pipeline.get("name", "?"), "steps_run": 0,
                "steps_succeeded": 0, "steps_failed": 0, "outputs": {}, "step_results": [],
                "summary": f"Pipeline executor crashed: {exc}"}
    return result


def _get_pipeline_templates() -> dict[str, Any]:
    templates = []
    for key, t in _PIPELINE_TEMPLATES.items():
        templates.append({
            "id": key,
            "name": t["name"],
            "description": t["description"],
            "step_count": len(t["steps"]),
            "step_blocks": [s["block"] for s in t["steps"]],
        })
    return {
        "templates": templates,
        "usage": "Pass the 'definition' key of any template directly to run_pipeline() to execute it."
                 " You can also modify a template before running — e.g. change the threat_actor input.",
        "template_definitions": _PIPELINE_TEMPLATES,
    }


# ── Registration ──────────────────────────────────────────────────────────────

def register_pipeline_tools(tool_map: dict, schema_list: list) -> None:
    """Called from platform_tools.register_tools() to add pipeline tools."""

    tool_map["list_blocks"] = lambda **_: _list_blocks()
    schema_list.append({
        "name": "list_blocks",
        "description": (
            "List all available pipeline blocks (atomic Lego pieces) that can be chained together "
            "into a pipeline. Returns blocks grouped by category with their input/output specs."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    })

    tool_map["run_pipeline"] = lambda pipeline, **_: _run_pipeline(pipeline)
    schema_list.append({
        "name": "run_pipeline",
        "description": (
            "Execute a modular pipeline — a sequence of named blocks chained via {{step_id.output_key}} templates. "
            "The engine runs all steps server-side in one call, returning per-step results and a summary. "
            "Use list_blocks() to see available blocks, or get_pipeline_templates() for pre-built recipes. "
            "Structure: {name: str, steps: [{id: str, block: str, inputs: {key: value|{{ref}}}}]}"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pipeline": {
                    "type": "object",
                    "description": "Pipeline definition with name and steps array",
                    "properties": {
                        "name": {"type": "string", "description": "Human-readable pipeline name"},
                        "steps": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": {"type": "string", "description": "Unique step ID used by downstream {{id.key}} templates"},
                                    "block": {"type": "string", "description": "Block ID from list_blocks()"},
                                    "inputs": {"type": "object", "description": "Block inputs — values can be literals or {{step_id.output_key}} templates"},
                                },
                                "required": ["id", "block"],
                            }
                        }
                    },
                    "required": ["name", "steps"],
                }
            },
            "required": ["pipeline"],
        },
    })

    tool_map["get_pipeline_templates"] = lambda **_: _get_pipeline_templates()
    schema_list.append({
        "name": "get_pipeline_templates",
        "description": (
            "Return pre-built pipeline templates for common workflows: APT red team, detection gap closure, "
            "full coverage drill, quick assessment. Templates are ready to run_pipeline() as-is or after "
            "customising inputs (e.g. change the threat_actor)."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    })
