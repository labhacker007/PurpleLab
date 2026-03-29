"""Splunk Common Information Model (CIM) field mapping for PurpleLab events.

Provides:
- to_cim(event, source_id)       — normalize a PurpleLab event to Splunk CIM
- cim_data_model(source_id)      — return the primary CIM data model for a source
- CIMNormalizer class (backward compat wrapper)

Key CIM data models implemented:
- Authentication       — login/logoff, auth failures
- Network_Traffic      — firewall, proxy, IDS/IPS flows
- Endpoint             — process, file system, registry activity
- Change               — account/config/system changes
- Malware              — malware detections

CIM reference: https://docs.splunk.com/Documentation/CIM/latest/User/Overview
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ── Source → CIM data model mapping ──────────────────────────────────────────

_SOURCE_DATAMODEL: dict[str, str] = {
    "okta": "Authentication",
    "entra_id": "Authentication",
    "crowdstrike": "Malware",
    "defender_endpoint": "Malware",
    "carbon_black": "Endpoint",
    "splunk": "Alerts",
    "qradar": "Alerts",
    "sentinel": "Alerts",
    "elastic": "Alerts",
    "guardduty": "Network_Traffic",
    "proofpoint": "Email",
    "servicenow": "Change",
    "generic": "Endpoint",
}

# CIM severity normalization
_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "unknown": "unknown",
}

# CIM action normalization
_ACTION_MAP: dict[str, str] = {
    "success": "success",
    "allowed": "allowed",
    "failure": "failure",
    "failed": "failure",
    "blocked": "blocked",
    "denied": "blocked",
    "unknown": "unknown",
}


# ── Public functions ──────────────────────────────────────────────────────────

def cim_data_model(source_id: str) -> str:
    """Return the primary CIM data model for a PurpleLab source_id.

    Args:
        source_id: PurpleLab log source identifier.

    Returns:
        CIM data model string, e.g. "Authentication", "Malware".
    """
    return _SOURCE_DATAMODEL.get(source_id.lower(), "Endpoint")


def to_cim(event: dict[str, Any], source_id: str) -> dict[str, Any]:
    """Normalize a PurpleLab event dict to Splunk CIM format.

    Selects the appropriate CIM data model based on source_id and maps
    PurpleLab fields to the CIM field set.  Extra fields are retained
    under a ``purplelab_`` prefix.

    Args:
        event: Raw PurpleLab event dict.
        source_id: PurpleLab log source identifier, e.g. "okta".

    Returns:
        CIM-normalised dict ready for Splunk indexing.
    """
    src = source_id.lower()
    data_model = cim_data_model(src)

    # ── _time (epoch) ─────────────────────────────────────────────────────────
    raw_time = (
        event.get("timestamp")
        or event.get("@timestamp")
        or event.get("time")
        or event.get("created_at")
        or ""
    )
    if isinstance(raw_time, (int, float)):
        _time = float(raw_time)
    elif raw_time:
        try:
            from datetime import datetime as _dt
            dt = _dt.fromisoformat(str(raw_time).replace("Z", "+00:00"))
            _time = dt.timestamp()
        except Exception:
            _time = datetime.now(timezone.utc).timestamp()
    else:
        _time = datetime.now(timezone.utc).timestamp()

    # ── Common CIM fields (shared across all data models) ─────────────────────
    severity_raw = str(
        event.get("severity") or event.get("alert_severity") or "unknown"
    ).lower()
    severity = _SEVERITY_MAP.get(severity_raw, "unknown")

    action_raw = str(
        event.get("action")
        or event.get("result")
        or event.get("outcome")
        or event.get("action_result")
        or "unknown"
    ).lower()
    action = _ACTION_MAP.get(action_raw, action_raw)

    src_ip = (
        event.get("src_ip")
        or event.get("source_ip")
        or event.get("src")
        or event.get("local_ip")
        or ""
    )
    dest = (
        event.get("dst_ip")
        or event.get("dest_ip")
        or event.get("dest")
        or event.get("remote_ip")
        or ""
    )
    user = (
        event.get("user")
        or event.get("username")
        or event.get("user_name")
        or ""
    )
    host = (
        event.get("host")
        or event.get("hostname")
        or event.get("computer_name")
        or event.get("device_id")
        or ""
    )
    app = (
        event.get("app")
        or event.get("application")
        or event.get("product")
        or src
    )

    # Build base CIM event
    cim: dict[str, Any] = {
        "_time": _time,
        "index": event.get("index") or "purplelab",
        "sourcetype": f"purplelab:{src}",
        "source": src,
        "host": host,
        "user": user,
        "src": src_ip,
        "dest": dest,
        "action": action,
        "severity": severity,
        "app": app,
        "signature": (
            event.get("rule_name")
            or event.get("alert_name")
            or event.get("title")
            or event.get("signature")
            or ""
        ),
        "signature_id": event.get("rule_id") or event.get("detection_id") or "",
        "vendor_product": src.replace("_", " ").title(),
        "purplelab_source_id": src,
        "purplelab_scenario_id": event.get("scenario_id") or "",
        "purplelab_session_id": event.get("session_id") or "",
    }

    # ── Data-model–specific fields ────────────────────────────────────────────
    if data_model == "Authentication":
        cim.update(_map_authentication(event, user, src_ip, dest, action, host))
    elif data_model == "Network_Traffic":
        cim.update(_map_network_traffic(event, src_ip, dest, action))
    elif data_model in ("Endpoint", "Malware"):
        cim.update(_map_endpoint(event, user, host, action))
        if data_model == "Malware":
            cim.update(_map_malware(event, user, host))
    elif data_model == "Change":
        cim.update(_map_change(event, user, host, action))
    elif data_model == "Email":
        cim.update(_map_email(event, user))
    # Alerts / generic — base fields are sufficient

    return {k: v for k, v in cim.items() if v not in (None, "")}


# ── Data-model field mappers ──────────────────────────────────────────────────

def _map_authentication(
    event: dict[str, Any],
    user: str,
    src: str,
    dest: str,
    action: str,
    host: str,
) -> dict[str, Any]:
    """Map to CIM Authentication data model fields."""
    return {
        # Required CIM Authentication fields
        "user": user,
        "src": src,
        "dest": dest,
        "action": action,
        "app": event.get("app") or event.get("service") or "",
        # Extended authentication fields
        "src_user": event.get("src_user") or event.get("initiated_by") or "",
        "user_agent": event.get("user_agent") or "",
        "src_ip": src,
        "dest_nt_host": dest or host,
        "authentication_service": event.get("auth_service") or event.get("protocol") or "",
        "authentication_method": event.get("auth_method") or event.get("factor") or "",
        "reason": event.get("reason") or event.get("failure_reason") or "",
        "session_id": event.get("session_id") or "",
        "duration": event.get("duration"),
        "logon_type": event.get("logon_type") or "",
        "mfa_result": event.get("mfa_result") or event.get("factor_result") or "",
        "country": event.get("country") or event.get("geo_country") or "",
        "city": event.get("city") or event.get("geo_city") or "",
    }


def _map_network_traffic(
    event: dict[str, Any],
    src_ip: str,
    dest: str,
    action: str,
) -> dict[str, Any]:
    """Map to CIM Network_Traffic data model fields."""
    return {
        # Required CIM Network_Traffic fields
        "src_ip": src_ip,
        "src_port": event.get("src_port") or event.get("source_port"),
        "dest_ip": dest,
        "dest_port": event.get("dst_port") or event.get("dest_port") or event.get("port"),
        "transport": event.get("protocol") or event.get("transport") or "",
        "action": action,
        # Extended fields
        "bytes_in": event.get("bytes_in") or event.get("bytes_received"),
        "bytes_out": event.get("bytes_out") or event.get("bytes_sent"),
        "packets_in": event.get("packets_in"),
        "packets_out": event.get("packets_out"),
        "direction": event.get("direction") or event.get("network_direction") or "",
        "dvc": event.get("firewall") or event.get("device") or "",
        "rule": event.get("rule_name") or "",
        "interface": event.get("interface") or "",
        "url": event.get("url") or event.get("request_url") or "",
        "category": event.get("category") or event.get("url_category") or "",
    }


def _map_endpoint(
    event: dict[str, Any],
    user: str,
    host: str,
    action: str,
) -> dict[str, Any]:
    """Map to CIM Endpoint data model fields (process + filesystem + registry)."""
    return {
        # Process fields
        "process": event.get("process_name") or event.get("process") or "",
        "process_id": event.get("pid") or event.get("process_id"),
        "process_path": event.get("process_path") or event.get("image_path") or "",
        "process_hash": event.get("sha256") or event.get("md5") or "",
        "parent_process": event.get("parent_process") or "",
        "parent_process_id": event.get("parent_pid"),
        "process_exec": event.get("command_line") or event.get("cmdline") or "",
        # Filesystem fields
        "file_path": event.get("file_path") or event.get("target_path") or "",
        "file_name": event.get("file_name") or _basename(event.get("file_path") or ""),
        "file_hash": event.get("sha256") or event.get("md5") or "",
        "file_size": event.get("file_size"),
        # Registry fields
        "registry_path": event.get("registry_path") or "",
        "registry_key_name": event.get("registry_key") or "",
        "registry_value_name": event.get("registry_value") or "",
        # Context
        "dest": host,
        "user": user,
        "action": action,
        "os": event.get("os_platform") or event.get("platform") or "",
    }


def _map_malware(
    event: dict[str, Any],
    user: str,
    host: str,
) -> dict[str, Any]:
    """Map additional Malware data model fields (extends Endpoint)."""
    return {
        "malware": event.get("malware_name") or event.get("threat_name") or event.get("signature") or "",
        "malware_type": event.get("malware_type") or event.get("threat_type") or "",
        "category": event.get("category") or event.get("malware_category") or "",
        "dest": host,
        "user": user,
        "vendor": event.get("vendor") or "",
        "product": event.get("product") or "",
        "threat_actor": event.get("threat_actor") or "",
        "technique_id": event.get("technique_id") or "",
        "technique_name": event.get("technique") or "",
    }


def _map_change(
    event: dict[str, Any],
    user: str,
    host: str,
    action: str,
) -> dict[str, Any]:
    """Map to CIM Change data model fields."""
    return {
        "action": action,
        "user": user,
        "dest": host,
        "object_category": event.get("object_category") or event.get("change_type") or "",
        "object": event.get("object") or event.get("resource") or event.get("target") or "",
        "object_path": event.get("object_path") or "",
        "object_id": event.get("object_id") or "",
        "status": event.get("status") or "",
        "result": event.get("result") or "",
        "change_type": event.get("change_type") or "",
        "command": event.get("command") or "",
        "src": event.get("src_ip") or event.get("source_ip") or "",
    }


def _map_email(event: dict[str, Any], user: str) -> dict[str, Any]:
    """Map to CIM Email data model fields."""
    return {
        "recipient": event.get("recipient") or event.get("to") or user,
        "sender": event.get("sender") or event.get("from") or "",
        "subject": event.get("subject") or "",
        "message_id": event.get("message_id") or "",
        "attachment": event.get("attachment") or event.get("filename") or "",
        "file_hash": event.get("sha256") or event.get("md5") or "",
        "url": event.get("url") or "",
        "malicious_url": event.get("malicious_url") or "",
        "src_user": event.get("sender") or "",
        "recipient_count": event.get("recipient_count"),
        "filter_action": event.get("disposition") or event.get("filter_action") or "",
    }


# ── CIMNormalizer class (backward-compat) ─────────────────────────────────────

class CIMNormalizer:
    """Normalizes events to/from Splunk CIM format.

    Thin wrapper around the module-level ``to_cim`` function for object-oriented
    usage patterns.
    """

    def __init__(self, source_id: str = "generic") -> None:
        self.source_id = source_id

    def normalize(self, event: dict[str, Any], data_model: str = "") -> dict[str, Any]:
        """Normalize event to CIM format.

        Args:
            event: Raw PurpleLab event dict.
            data_model: Optional CIM data model override (ignored if empty).
        """
        return to_cim(event, self.source_id)

    def denormalize(self, cim_event: dict[str, Any], target_format: str = "raw") -> dict[str, Any]:
        """Extract core fields from a CIM event back to a flat dict."""
        return {
            "timestamp": cim_event.get("_time", ""),
            "host": cim_event.get("host", ""),
            "user": cim_event.get("user", ""),
            "src_ip": cim_event.get("src", ""),
            "dest": cim_event.get("dest", ""),
            "action": cim_event.get("action", ""),
            "severity": cim_event.get("severity", ""),
            "signature": cim_event.get("signature", ""),
            "app": cim_event.get("app", ""),
            "source_id": cim_event.get("purplelab_source_id", ""),
        }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]
