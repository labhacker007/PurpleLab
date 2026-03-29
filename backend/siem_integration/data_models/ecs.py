"""Elastic Common Schema (ECS) field mapping for PurpleLab events.

Provides:
- to_ecs(event, source_id)        — normalize a PurpleLab event to ECS
- ecs_event_category(source_id)   — return ECS event.category list for a source
- ecs_dataset(source_id)          — return the ecs.dataset string
- ECSNormalizer class (backward compat wrapper)

ECS reference: https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
ECS version targeted: 8.x
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ── Source-to-ECS metadata ────────────────────────────────────────────────────

# Maps PurpleLab source_id → (event.category list, event.type list, event.kind)
_SOURCE_ECS_MAP: dict[str, dict[str, Any]] = {
    # SIEM / Log aggregation
    "splunk": {"category": ["process"], "type": ["info"], "kind": "event", "dataset": "splunk.alert"},
    "qradar": {"category": ["process"], "type": ["info"], "kind": "event", "dataset": "qradar.offense"},
    # EDR
    "crowdstrike": {"category": ["malware", "process"], "type": ["info", "indicator"], "kind": "alert", "dataset": "crowdstrike.detection"},
    "defender_endpoint": {"category": ["malware", "process"], "type": ["info"], "kind": "alert", "dataset": "defender.alert"},
    "carbon_black": {"category": ["process"], "type": ["start", "info"], "kind": "event", "dataset": "carbon_black.endpoint_event"},
    # Identity / ITDR
    "okta": {"category": ["authentication", "iam"], "type": ["start", "end", "change"], "kind": "event", "dataset": "okta.system"},
    "entra_id": {"category": ["authentication", "iam"], "type": ["start", "change"], "kind": "event", "dataset": "azure.auditlogs"},
    # Email
    "proofpoint": {"category": ["email"], "type": ["info", "indicator"], "kind": "event", "dataset": "proofpoint.tap"},
    # Cloud
    "guardduty": {"category": ["network", "intrusion_detection"], "type": ["info", "indicator"], "kind": "alert", "dataset": "aws.guardduty"},
    "sentinel": {"category": ["process", "authentication"], "type": ["info"], "kind": "alert", "dataset": "azure.sentinel"},
    "elastic": {"category": ["process"], "type": ["info"], "kind": "event", "dataset": "elastic.siem"},
    # ITSM / Vuln
    "servicenow": {"category": ["configuration"], "type": ["change"], "kind": "event", "dataset": "servicenow.incident"},
    # Generic / default
    "generic": {"category": ["process"], "type": ["info"], "kind": "event", "dataset": "purplelab.generic"},
}

# Severity string → ECS event.severity integer (0–100)
_SEVERITY_MAP: dict[str, int] = {
    "critical": 99,
    "high": 73,
    "medium": 47,
    "low": 21,
    "informational": 5,
    "info": 5,
    "unknown": 0,
}

# ECS outcome values
_OUTCOME_MAP: dict[str, str] = {
    "success": "success",
    "failure": "failure",
    "fail": "failure",
    "failed": "failure",
    "blocked": "failure",
    "allowed": "success",
    "unknown": "unknown",
}


# ── Public functions ──────────────────────────────────────────────────────────

def ecs_event_category(source_id: str) -> list[str]:
    """Return the ECS event.category list for a given PurpleLab source_id.

    Args:
        source_id: PurpleLab log source identifier, e.g. "crowdstrike".

    Returns:
        List of ECS event category strings.
    """
    meta = _SOURCE_ECS_MAP.get(source_id.lower(), _SOURCE_ECS_MAP["generic"])
    return list(meta["category"])


def ecs_dataset(source_id: str) -> str:
    """Return the ecs.dataset string for a given PurpleLab source_id.

    Args:
        source_id: PurpleLab log source identifier.

    Returns:
        ECS dataset string, e.g. "crowdstrike.detection".
    """
    meta = _SOURCE_ECS_MAP.get(source_id.lower(), _SOURCE_ECS_MAP["generic"])
    return meta["dataset"]


def to_ecs(event: dict[str, Any], source_id: str) -> dict[str, Any]:
    """Normalize a PurpleLab event dict to Elastic Common Schema (ECS) format.

    Maps common PurpleLab fields to their ECS equivalents.  Unknown fields are
    preserved under a ``purplelab`` namespace to avoid data loss.

    Args:
        event: Raw PurpleLab event dict (may originate from any generator).
        source_id: PurpleLab log source identifier, e.g. "crowdstrike".

    Returns:
        ECS-normalised dict ready for indexing in Elasticsearch.
    """
    src = source_id.lower()
    meta = _SOURCE_ECS_MAP.get(src, _SOURCE_ECS_MAP["generic"])

    # ── @timestamp ────────────────────────────────────────────────────────────
    timestamp = (
        event.get("@timestamp")
        or event.get("timestamp")
        or event.get("time")
        or event.get("created_at")
        or event.get("event_time")
        or datetime.now(timezone.utc).isoformat()
    )

    # ── Severity ──────────────────────────────────────────────────────────────
    raw_severity = str(
        event.get("severity")
        or event.get("alert_severity")
        or event.get("risk_level")
        or "unknown"
    ).lower()
    severity_int = _SEVERITY_MAP.get(raw_severity, _SEVERITY_MAP["unknown"])

    # ── Outcome ───────────────────────────────────────────────────────────────
    raw_outcome = str(
        event.get("outcome")
        or event.get("result")
        or event.get("action_result")
        or "unknown"
    ).lower()
    outcome = _OUTCOME_MAP.get(raw_outcome, "unknown")

    # ── Host ──────────────────────────────────────────────────────────────────
    host_name = (
        event.get("host")
        or event.get("hostname")
        or event.get("device_id")
        or event.get("computer_name")
        or ""
    )

    # ── Network ───────────────────────────────────────────────────────────────
    src_ip = (
        event.get("src_ip")
        or event.get("source_ip")
        or event.get("src")
        or event.get("local_ip")
        or ""
    )
    dst_ip = (
        event.get("dst_ip")
        or event.get("dest_ip")
        or event.get("dest")
        or event.get("remote_ip")
        or ""
    )
    network_protocol = (
        event.get("protocol")
        or event.get("network_protocol")
        or ""
    )

    # ── User ─────────────────────────────────────────────────────────────────
    user_name = (
        event.get("user")
        or event.get("username")
        or event.get("user_name")
        or event.get("actor")
        or ""
    )
    user_domain = event.get("user_domain") or event.get("domain") or ""

    # ── Process ───────────────────────────────────────────────────────────────
    proc_name = (
        event.get("process_name")
        or event.get("process")
        or event.get("image_file_name")
        or ""
    )
    proc_pid = event.get("pid") or event.get("process_id")
    proc_cmdline = (
        event.get("command_line")
        or event.get("cmdline")
        or event.get("cmd")
        or ""
    )
    proc_hash = event.get("sha256") or event.get("md5") or ""

    # ── File ─────────────────────────────────────────────────────────────────
    file_path = (
        event.get("file_path")
        or event.get("file_name")
        or event.get("target_path")
        or ""
    )
    file_hash_sha256 = event.get("sha256") or ""
    file_hash_md5 = event.get("md5") or ""

    # ── Threat / MITRE ────────────────────────────────────────────────────────
    technique_id = event.get("technique_id") or event.get("tactic_id") or ""
    technique_name = event.get("technique") or event.get("tactic") or ""

    # ── Assemble ECS doc ──────────────────────────────────────────────────────
    ecs_doc: dict[str, Any] = {
        "@timestamp": timestamp,
        "ecs": {
            "version": "8.11.0",
        },
        "event": {
            "kind": meta["kind"],
            "category": list(meta["category"]),
            "type": list(meta["type"]),
            "outcome": outcome,
            "severity": severity_int,
            "dataset": meta["dataset"],
            "module": src,
            "provider": src,
            "original": event.get("raw_log") or event.get("original") or "",
            "id": event.get("event_id") or event.get("id") or "",
            "action": event.get("event_type") or event.get("action") or "",
            "reason": event.get("description") or event.get("reason") or "",
        },
        "host": {
            "name": host_name,
            "hostname": host_name,
            "os": {
                "platform": event.get("os_platform") or event.get("platform") or "",
                "type": event.get("os_type") or "",
                "version": event.get("os_version") or "",
            },
            "ip": [src_ip] if src_ip else [],
        },
        "source": {"ip": src_ip} if src_ip else {},
        "destination": {"ip": dst_ip} if dst_ip else {},
        "user": {
            "name": user_name,
            "domain": user_domain,
            "id": event.get("user_id") or "",
            "email": event.get("user_email") or event.get("email") or "",
        },
        "process": {
            "name": proc_name,
            "pid": proc_pid,
            "command_line": proc_cmdline,
            "hash": {"sha256": proc_hash} if proc_hash else {},
            "parent": {
                "name": event.get("parent_process") or "",
                "pid": event.get("parent_pid"),
            },
        },
        "file": {
            "path": file_path,
            "name": _basename(file_path),
            "hash": {
                "sha256": file_hash_sha256,
                "md5": file_hash_md5,
            },
        },
        "network": {
            "protocol": network_protocol,
            "direction": event.get("network_direction") or event.get("direction") or "",
            "bytes": event.get("bytes_total") or event.get("bytes"),
        },
        "url": {
            "full": event.get("url") or event.get("request_url") or "",
            "domain": event.get("domain") or event.get("url_domain") or "",
        },
        "dns": {
            "question": {
                "name": event.get("dns_query") or event.get("domain") or "",
                "type": event.get("dns_type") or "",
            },
            "answers": event.get("dns_answers") or [],
        },
        "threat": {
            "technique": {
                "id": [technique_id] if technique_id else [],
                "name": [technique_name] if technique_name else [],
                "reference": [
                    f"https://attack.mitre.org/techniques/{technique_id}/"
                ] if technique_id else [],
            },
            "tactic": {
                "name": [event.get("tactic") or ""],
                "id": [event.get("tactic_id") or ""],
            },
            "indicator": {
                "ip": event.get("indicator_ip") or "",
                "domain": event.get("indicator_domain") or "",
                "file": {"hash": {"sha256": event.get("indicator_hash") or ""}},
            },
        },
        "rule": {
            "name": event.get("rule_name") or event.get("alert_name") or event.get("title") or "",
            "description": event.get("rule_description") or "",
            "id": event.get("rule_id") or event.get("detection_id") or "",
            "author": ["PurpleLab"],
            "license": "Apache 2.0",
        },
        "message": (
            event.get("message")
            or event.get("description")
            or event.get("alert_name")
            or ""
        ),
        "tags": [src, "purplelab"] + (event.get("tags") or []),
        "labels": {
            "source_id": src,
            "purplelab": "true",
        },
        # Preserve unmapped PurpleLab-specific fields
        "purplelab": {
            "source_id": src,
            "scenario_id": event.get("scenario_id") or "",
            "session_id": event.get("session_id") or "",
            "raw": {
                k: v for k, v in event.items()
                if k not in _KNOWN_SOURCE_FIELDS
            },
        },
    }

    # Clean up empty nested objects
    _drop_empty(ecs_doc)
    return ecs_doc


# ── ECSNormalizer class (backward-compat) ─────────────────────────────────────

class ECSNormalizer:
    """Normalizes events to/from Elastic ECS format.

    Thin wrapper around the module-level ``to_ecs`` function for object-oriented
    usage patterns.
    """

    def __init__(self, source_id: str = "generic") -> None:
        self.source_id = source_id

    def normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        """Normalize event to ECS format."""
        return to_ecs(event, self.source_id)

    def denormalize(self, ecs_event: dict[str, Any], target_format: str = "raw") -> dict[str, Any]:
        """Extract key fields from an ECS event back to a flat dict.

        This is a best-effort reversal — not all ECS nesting is perfectly flat.
        """
        flat: dict[str, Any] = {
            "timestamp": ecs_event.get("@timestamp", ""),
            "message": ecs_event.get("message", ""),
            "severity": ecs_event.get("event", {}).get("severity"),
            "outcome": ecs_event.get("event", {}).get("outcome", ""),
            "action": ecs_event.get("event", {}).get("action", ""),
            "hostname": ecs_event.get("host", {}).get("name", ""),
            "src_ip": ecs_event.get("source", {}).get("ip", ""),
            "dst_ip": ecs_event.get("destination", {}).get("ip", ""),
            "username": ecs_event.get("user", {}).get("name", ""),
            "process_name": ecs_event.get("process", {}).get("name", ""),
            "pid": ecs_event.get("process", {}).get("pid"),
            "file_path": ecs_event.get("file", {}).get("path", ""),
            "network_protocol": ecs_event.get("network", {}).get("protocol", ""),
            "technique_id": (ecs_event.get("threat", {}).get("technique", {}).get("id") or [""])[0],
            "rule_name": ecs_event.get("rule", {}).get("name", ""),
        }
        if target_format == "raw":
            # Merge purplelab.raw back in
            raw = ecs_event.get("purplelab", {}).get("raw", {})
            flat.update(raw)
        return {k: v for k, v in flat.items() if v not in (None, "", [], {})}


# ── Internal helpers ──────────────────────────────────────────────────────────

# Fields consumed during ECS mapping — used to identify "leftover" fields
_KNOWN_SOURCE_FIELDS = frozenset({
    "@timestamp", "timestamp", "time", "created_at", "event_time",
    "severity", "alert_severity", "risk_level",
    "outcome", "result", "action_result",
    "host", "hostname", "device_id", "computer_name",
    "src_ip", "source_ip", "src", "local_ip",
    "dst_ip", "dest_ip", "dest", "remote_ip",
    "protocol", "network_protocol",
    "user", "username", "user_name", "actor",
    "user_domain", "domain",
    "process_name", "process", "image_file_name",
    "pid", "process_id",
    "command_line", "cmdline", "cmd",
    "sha256", "md5",
    "file_path", "file_name", "target_path",
    "url", "request_url", "url_domain",
    "dns_query", "dns_type", "dns_answers",
    "technique_id", "tactic_id", "technique", "tactic",
    "rule_name", "alert_name", "title",
    "rule_id", "detection_id",
    "description", "reason",
    "event_id", "id",
    "event_type", "action",
    "os_platform", "platform", "os_type", "os_version",
    "user_id", "user_email", "email",
    "parent_process", "parent_pid",
    "bytes_total", "bytes",
    "network_direction", "direction",
    "indicator_ip", "indicator_domain", "indicator_hash",
    "raw_log", "original",
    "tags",
    "scenario_id", "session_id",
    "message",
})


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _drop_empty(obj: Any) -> None:
    """Recursively remove None and empty-string values from nested dicts."""
    if not isinstance(obj, dict):
        return
    keys_to_remove = [k for k, v in obj.items() if v is None or v == ""]
    for k in keys_to_remove:
        del obj[k]
    for v in obj.values():
        if isinstance(v, dict):
            _drop_empty(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    _drop_empty(item)
