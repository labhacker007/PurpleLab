"""Simulation engine tools for the agent orchestrator.

Provides tools for starting, stopping, and monitoring simulation
sessions that generate security product events, and for running
attack chain simulations.

HIGH-RISK OPERATIONS (run_attack_chain) require L1_SOFT HITL approval.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


async def _require_approval(action_type: str, summary: str, payload: dict) -> dict[str, Any] | None:
    """HITL gate helper (mirrors siem_tools version for independence)."""
    try:
        from backend.hitl.engine import get_hitl_engine
        from backend.hitl.models import HITLLevel

        engine = get_hitl_engine()
        config = engine.get_config(action_type)

        if config.level == HITLLevel.L0_AUTO:
            return None

        pending = await engine.list_pending(100)
        for req_dict in pending:
            if req_dict.get("action_type") == action_type and req_dict.get("status") in (
                "approved", "auto_approved"
            ):
                return None

        level_name = config.level.name
        return {
            "error": "approval_required",
            "message": (
                f"Action '{action_type}' requires {level_name} approval before execution. "
                f"Call check_approval_requirement('{action_type}') to see what is needed, "
                f"then request_approval('{action_type}', ...) followed by wait_for_approval(). "
                f"Do NOT retry this tool until approval is granted."
            ),
            "action_type": action_type,
            "required_level": int(config.level),
            "required_level_name": level_name,
        }
    except Exception as exc:
        logger.warning("HITL gate check failed for '%s': %s — proceeding without gate", action_type, exc)
        return None

# Module-level session tracking for active simulations started via tools.
# The SessionManager requires typed config objects; this lightweight tracker
# lets the agent manage sessions without full Pydantic model wiring.
_active_sessions: dict[str, dict[str, Any]] = {}


def register_tools(registry: ToolRegistry) -> None:
    """Register all simulation engine tools."""

    registry.register(
        name="start_simulation",
        description=(
            "Start a new simulation session that generates security product "
            "events. Specify which products to simulate (e.g., 'splunk', "
            "'crowdstrike') and optionally a target URL for webhook delivery."
        ),
        parameters={
            "type": "object",
            "properties": {
                "products": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of product types to simulate (e.g., "
                        "['splunk', 'crowdstrike', 'elastic']). "
                        "Use 'list_available_generators' to see all options."
                    ),
                },
                "target_url": {
                    "type": "string",
                    "description": (
                        "Target URL for event delivery via webhooks. "
                        "Leave empty to generate events without dispatching."
                    ),
                    "default": "",
                },
                "config": {
                    "type": "object",
                    "description": (
                        "Optional configuration overrides. Supported keys: "
                        "'events_per_minute' (float), 'severity_weights' (dict), "
                        "'name' (str, session name)."
                    ),
                    "default": {},
                },
            },
            "required": ["products"],
        },
        handler=_start_simulation,
    )

    registry.register(
        name="stop_simulation",
        description="Stop a running simulation session by its session ID.",
        parameters={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to stop.",
                },
            },
            "required": ["session_id"],
        },
        handler=_stop_simulation,
    )

    registry.register(
        name="list_active_simulations",
        description=(
            "List all currently running simulation sessions with their "
            "configuration and event statistics."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_list_active_simulations,
    )

    registry.register(
        name="get_simulation_status",
        description=(
            "Get the detailed status of a simulation session including "
            "product configurations, event counts, and runtime info."
        ),
        parameters={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to query.",
                },
            },
            "required": ["session_id"],
        },
        handler=_get_simulation_status,
    )

    registry.register(
        name="list_attack_chains",
        description=(
            "List all available built-in attack chain templates. "
            "Returns chain IDs, names, descriptions, stages, and MITRE technique mappings. "
            "Use this to discover available chains before calling run_attack_chain."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_list_attack_chains,
    )

    registry.register(
        name="run_attack_chain",
        description=(
            "Execute a multi-stage attack chain simulation. Runs a predefined or custom "
            "attack chain that generates correlated log events across multiple techniques. "
            "Each stage generates events tagged with the chain correlation ID. "
            "IMPORTANT: This requires L1_SOFT approval. Call request_approval('run_attack_chain', ...) "
            "first — the chain will auto-execute after the grace period unless rejected."
        ),
        parameters={
            "type": "object",
            "properties": {
                "chain_id": {
                    "type": "string",
                    "description": (
                        "ID of a built-in attack chain to run. "
                        "Use list_attack_chains to see available options. "
                        "Leave empty to use chain_yaml instead."
                    ),
                },
                "chain_yaml": {
                    "type": "string",
                    "description": (
                        "Custom attack chain definition in YAML format. "
                        "Use this to define a custom chain instead of a built-in one."
                    ),
                },
                "simulate_delays": {
                    "type": "boolean",
                    "description": "Whether to simulate realistic timing delays between stages (default: false).",
                    "default": False,
                },
                "parallelise": {
                    "type": "boolean",
                    "description": "Whether to run independent stages in parallel (default: false).",
                    "default": False,
                },
            },
            "required": [],
        },
        handler=_run_attack_chain,
    )


async def _start_simulation(
    products: list[str],
    target_url: str = "",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Start a simulation session."""
    config = config or {}

    try:
        from backend.engine.generators import GENERATOR_REGISTRY
        from backend.engine.generators.base import GeneratorConfig

        # Validate product types
        invalid = [p for p in products if p not in GENERATOR_REGISTRY]
        if invalid:
            available = sorted(GENERATOR_REGISTRY.keys())
            return {
                "error": (
                    f"Unknown product types: {', '.join(invalid)}. "
                    f"Available: {', '.join(available)}"
                ),
            }

        session_id = f"sim-{uuid.uuid4().hex[:12]}"
        session_name = config.get("name", f"Simulation {session_id}")
        events_per_minute = config.get("events_per_minute", 2.0)
        severity_weights = config.get("severity_weights", {
            "critical": 0.05,
            "high": 0.20,
            "medium": 0.50,
            "low": 0.25,
        })

        # Build generators for each product
        generators_info = []
        generators = {}
        for product_type in products:
            gen_cls = GENERATOR_REGISTRY[product_type]
            gen_config = GeneratorConfig(
                product_type=product_type,
                target_url=target_url,
                events_per_minute=events_per_minute,
                severity_weights=severity_weights,
            )
            generator = gen_cls(gen_config)
            gen_id = f"{session_id}_{product_type}"
            generators[gen_id] = generator
            generators_info.append({
                "id": gen_id,
                "product_type": product_type,
                "product_name": getattr(gen_cls, "product_name", product_type),
                "category": getattr(gen_cls, "product_category", "unknown"),
                "events_per_minute": events_per_minute,
            })

        # Track the session
        session = {
            "session_id": session_id,
            "name": session_name,
            "products": products,
            "target_url": target_url,
            "generators": generators,
            "generators_info": generators_info,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "events_generated": 0,
            "status": "running" if target_url else "generating",
        }
        _active_sessions[session_id] = session

        # If no target URL, generate an initial batch so the user
        # gets immediate results
        sample_events = []
        if not target_url:
            for gen in generators.values():
                sample_events.extend(gen.generate_batch(count=2))
            session["events_generated"] = len(sample_events)

        result: dict[str, Any] = {
            "status": "success",
            "session_id": session_id,
            "name": session_name,
            "products": generators_info,
            "target_url": target_url or "(no dispatch — generate-only mode)",
            "started_at": session["started_at"],
        }

        if sample_events:
            result["sample_events"] = sample_events
            result["message"] = (
                f"Session created in generate-only mode with {len(sample_events)} "
                "sample events. Set a target_url to enable webhook dispatch."
            )
        else:
            result["message"] = (
                f"Session started. Events will be dispatched to {target_url} "
                f"at ~{events_per_minute} events/minute per product."
            )

        return result

    except Exception as exc:
        logger.exception("start_simulation failed")
        return {"error": f"Failed to start simulation: {exc}"}


async def _stop_simulation(session_id: str) -> dict[str, Any]:
    """Stop a running simulation session."""
    try:
        session = _active_sessions.pop(session_id, None)
        if session is None:
            # Also try the engine's session manager
            try:
                from backend.engine.scheduler import EventScheduler
                scheduler = EventScheduler()
                stopped = scheduler.stop_session(session_id)
                if stopped:
                    return {
                        "status": "success",
                        "session_id": session_id,
                        "message": "Simulation session stopped via scheduler.",
                    }
            except Exception:
                pass

            return {
                "error": f"Session '{session_id}' not found.",
                "active_sessions": list(_active_sessions.keys()),
            }

        return {
            "status": "success",
            "session_id": session_id,
            "name": session.get("name", ""),
            "events_generated": session.get("events_generated", 0),
            "started_at": session.get("started_at", ""),
            "stopped_at": datetime.now(timezone.utc).isoformat(),
            "message": "Simulation session stopped.",
        }
    except Exception as exc:
        logger.exception("stop_simulation failed for '%s'", session_id)
        return {"error": f"Failed to stop simulation '{session_id}': {exc}"}


async def _list_active_simulations() -> dict[str, Any]:
    """List all active simulation sessions."""
    try:
        sessions = []
        for sid, session in _active_sessions.items():
            sessions.append({
                "session_id": sid,
                "name": session.get("name", ""),
                "products": session.get("products", []),
                "target_url": session.get("target_url", ""),
                "started_at": session.get("started_at", ""),
                "events_generated": session.get("events_generated", 0),
                "status": session.get("status", "unknown"),
            })

        return {
            "status": "success",
            "count": len(sessions),
            "sessions": sessions,
        }
    except Exception as exc:
        logger.exception("list_active_simulations failed")
        return {"error": f"Failed to list simulations: {exc}"}


async def _get_simulation_status(session_id: str) -> dict[str, Any]:
    """Get detailed status of a simulation session."""
    try:
        session = _active_sessions.get(session_id)
        if session is None:
            return {
                "error": f"Session '{session_id}' not found.",
                "active_sessions": list(_active_sessions.keys()),
            }

        return {
            "status": "success",
            "session_id": session_id,
            "name": session.get("name", ""),
            "products": session.get("generators_info", []),
            "target_url": session.get("target_url", ""),
            "started_at": session.get("started_at", ""),
            "events_generated": session.get("events_generated", 0),
            "simulation_status": session.get("status", "unknown"),
        }
    except Exception as exc:
        logger.exception("get_simulation_status failed for '%s'", session_id)
        return {"error": f"Failed to get simulation status: {exc}"}


async def _list_attack_chains() -> dict[str, Any]:
    """List all available attack chain templates."""
    try:
        from backend.attack_chains.orchestrator import AttackChainOrchestrator

        orch = AttackChainOrchestrator()
        chains = []
        for chain_id, chain in orch.builtin_chains.items():
            chains.append({
                "chain_id": chain_id,
                "name": chain.name,
                "description": chain.description,
                "threat_actor": chain.threat_actor,
                "stage_count": len(chain.stages),
                "stages": [
                    {
                        "stage_id": s.stage_id,
                        "name": s.name,
                        "technique_id": s.technique_id,
                        "tactic": s.tactic,
                        "source_ids": s.source_ids,
                    }
                    for s in chain.stages
                ],
                "mitre_techniques": list({s.technique_id for s in chain.stages if s.technique_id}),
            })

        return {
            "status": "success",
            "count": len(chains),
            "chains": chains,
        }
    except Exception as exc:
        logger.exception("list_attack_chains failed")
        return {"error": f"Failed to list attack chains: {exc}"}


async def _run_attack_chain(
    chain_id: str = "",
    chain_yaml: str = "",
    simulate_delays: bool = False,
    parallelise: bool = False,
) -> dict[str, Any]:
    """Execute an attack chain simulation (HITL L1_SOFT gated)."""
    if not chain_id and not chain_yaml:
        return {
            "error": "Provide either a chain_id (use list_attack_chains) or a chain_yaml definition.",
        }

    # Identify what we're about to run for the HITL payload
    run_label = chain_id or "custom chain"

    # HITL gate
    gate_error = await _require_approval(
        "run_attack_chain",
        f"Execute attack chain simulation: '{run_label}'",
        {"chain_id": chain_id, "has_custom_yaml": bool(chain_yaml)},
    )
    if gate_error:
        return gate_error

    try:
        from backend.attack_chains.orchestrator import AttackChainOrchestrator

        orch = AttackChainOrchestrator()

        if chain_yaml:
            result = await orch.run_yaml(
                chain_yaml,
                simulate_delays=simulate_delays,
                parallelise=parallelise,
            )
        else:
            chain = orch.builtin_chains.get(chain_id)
            if not chain:
                available = list(orch.builtin_chains.keys())
                return {
                    "error": f"Unknown chain_id '{chain_id}'.",
                    "available_chains": available,
                }
            result = await orch.run(
                chain,
                simulate_delays=simulate_delays,
                parallelise=parallelise,
            )

        return {
            "status": "success",
            "chain_id": chain_id or "custom",
            "chain_name": result.get("chain_name", ""),
            "correlation_id": result.get("correlation_id", ""),
            "stages_completed": result.get("stages_completed", 0),
            "total_events": result.get("total_events", 0),
            "duration_seconds": result.get("duration_seconds", 0),
            "stage_results": result.get("stage_results", []),
            "mitre_techniques": result.get("mitre_techniques", []),
        }
    except Exception as exc:
        logger.exception("run_attack_chain failed")
        return {"error": f"Failed to run attack chain: {exc}"}
