"""Log generation tools for the agent orchestrator.

Provides tools for generating synthetic attack and sample logs using
both the log source generators and the simulation engine generators.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.agent.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

# Log source types from backend/log_sources/sources/
_LOG_SOURCE_TYPES = {
    "sysmon": "Microsoft Sysmon telemetry events",
    "windows_eventlog": "Windows Security/System/Application Event Logs",
    "linux_audit": "Linux auditd events",
    "dns": "DNS query/response logs",
    "firewall": "Network firewall logs",
    "proxy": "Web proxy logs",
    "cloud_trail": "AWS CloudTrail events",
}

# Engine generator types from backend/engine/generators/
_ENGINE_GENERATOR_TYPES = {
    "splunk": "Splunk SIEM alerts and events",
    "crowdstrike": "CrowdStrike Falcon EDR detections",
    "sentinel": "Microsoft Sentinel alerts",
    "okta": "Okta identity events",
    "proofpoint": "Proofpoint email security events",
    "servicenow": "ServiceNow security incidents",
    "carbon_black": "VMware Carbon Black EDR events",
    "defender_endpoint": "Microsoft Defender for Endpoint alerts",
    "entra_id": "Microsoft Entra ID (Azure AD) sign-in events",
    "qradar": "IBM QRadar SIEM offenses",
    "elastic": "Elastic Security alerts",
    "guardduty": "AWS GuardDuty findings",
}


def register_tools(registry: ToolRegistry) -> None:
    """Register all log generation tools."""

    registry.register(
        name="generate_attack_logs",
        description=(
            "Generate synthetic logs containing attack indicators for a "
            "specific MITRE ATT&CK technique. Uses the simulation engine "
            "generators to produce realistic vendor-format events."
        ),
        parameters={
            "type": "object",
            "properties": {
                "technique": {
                    "type": "string",
                    "description": (
                        "MITRE ATT&CK technique ID or name "
                        "(e.g., 'T1059.001' or 'PowerShell')."
                    ),
                },
                "source_type": {
                    "type": "string",
                    "description": (
                        "Generator type to use (e.g., 'splunk', 'crowdstrike', "
                        "'elastic', 'sentinel'). Use 'list_available_generators' "
                        "to see all options."
                    ),
                },
                "count": {
                    "type": "integer",
                    "description": "Number of log events to generate (1-100).",
                    "default": 5,
                },
            },
            "required": ["technique", "source_type"],
        },
        handler=_generate_attack_logs,
    )

    registry.register(
        name="generate_sample_logs",
        description=(
            "Generate sample log events from a specific simulation engine "
            "generator. Produces realistic vendor-format events with a mix of "
            "severities."
        ),
        parameters={
            "type": "object",
            "properties": {
                "source_type": {
                    "type": "string",
                    "description": (
                        "Generator type (e.g., 'splunk', 'crowdstrike', "
                        "'elastic', 'sentinel', 'okta', 'guardduty')."
                    ),
                },
                "count": {
                    "type": "integer",
                    "description": "Number of log events to generate (1-100).",
                    "default": 10,
                },
            },
            "required": ["source_type"],
        },
        handler=_generate_sample_logs,
    )

    registry.register(
        name="list_available_generators",
        description=(
            "List all available log source generators and simulation engine "
            "generators with their descriptions and capabilities."
        ),
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=_list_available_generators,
    )


async def _generate_attack_logs(
    technique: str, source_type: str, count: int = 5
) -> dict[str, Any]:
    """Generate attack-pattern logs for a specific technique."""
    count = max(1, min(count, 100))

    try:
        from backend.engine.generators import GENERATOR_REGISTRY
        from backend.engine.generators.base import GeneratorConfig

        gen_cls = GENERATOR_REGISTRY.get(source_type)
        if gen_cls is None:
            available = sorted(GENERATOR_REGISTRY.keys())
            return {
                "error": (
                    f"Unknown generator type '{source_type}'. "
                    f"Available: {', '.join(available)}"
                ),
            }

        config = GeneratorConfig(
            product_type=source_type,
            target_url="",  # not dispatching, just generating
            severity_weights={
                "critical": 0.30,
                "high": 0.50,
                "medium": 0.15,
                "low": 0.05,
            },
        )
        generator = gen_cls(config)
        events = generator.generate_batch(count=count)

        # Tag events with the requested technique
        for event in events:
            event["_purplelab_technique"] = technique
            event["_purplelab_source"] = source_type

        return {
            "status": "success",
            "technique": technique,
            "source_type": source_type,
            "count": len(events),
            "events": events,
        }
    except Exception as exc:
        logger.exception("generate_attack_logs failed")
        return {"error": f"Failed to generate attack logs: {exc}"}


async def _generate_sample_logs(
    source_type: str, count: int = 10
) -> dict[str, Any]:
    """Generate sample logs from a simulation engine generator."""
    count = max(1, min(count, 100))

    try:
        from backend.engine.generators import GENERATOR_REGISTRY
        from backend.engine.generators.base import GeneratorConfig

        gen_cls = GENERATOR_REGISTRY.get(source_type)
        if gen_cls is None:
            available = sorted(GENERATOR_REGISTRY.keys())
            return {
                "error": (
                    f"Unknown generator type '{source_type}'. "
                    f"Available: {', '.join(available)}"
                ),
            }

        config = GeneratorConfig(
            product_type=source_type,
            target_url="",
        )
        generator = gen_cls(config)
        events = generator.generate_batch(count=count)

        for event in events:
            event["_purplelab_source"] = source_type

        return {
            "status": "success",
            "source_type": source_type,
            "count": len(events),
            "events": events,
        }
    except Exception as exc:
        logger.exception("generate_sample_logs failed")
        return {"error": f"Failed to generate sample logs: {exc}"}


async def _list_available_generators() -> dict[str, Any]:
    """List all available generators with their capabilities."""
    try:
        from backend.engine.generators import GENERATOR_REGISTRY
        from backend.engine.generators.base import BaseGenerator

        engine_generators = []
        for name, gen_cls in sorted(GENERATOR_REGISTRY.items()):
            engine_generators.append({
                "type": name,
                "product_name": getattr(gen_cls, "product_name", name),
                "category": getattr(gen_cls, "product_category", "unknown"),
                "description": _ENGINE_GENERATOR_TYPES.get(name, ""),
            })

        log_sources = [
            {"type": k, "description": v}
            for k, v in sorted(_LOG_SOURCE_TYPES.items())
        ]

        return {
            "status": "success",
            "engine_generators": {
                "count": len(engine_generators),
                "generators": engine_generators,
            },
            "log_sources": {
                "count": len(log_sources),
                "sources": log_sources,
                "note": (
                    "Log source generators (sysmon, windows_eventlog, etc.) "
                    "are not yet fully implemented. Use engine generators "
                    "(splunk, crowdstrike, elastic, etc.) for production-quality "
                    "event generation."
                ),
            },
        }
    except Exception as exc:
        logger.exception("list_available_generators failed")
        return {"error": f"Failed to list generators: {exc}"}
