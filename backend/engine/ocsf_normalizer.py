"""OCSF (Open Cybersecurity Schema Framework) Normalizer.

Translates vendor-specific log fields to OCSF canonical fields so Joti
can receive simulated logs from PurpleLab and run detection rules without
knowing which vendor produced the event.

OCSF event class mapping used:
  1001 — File Activity
  1002 — Kernel Activity
  1003 — Memory Activity
  1004 — Module Activity
  1005 — Scheduled Job Activity
  1006 — Process Activity  (process_creation, process_injection)
  1007 — Process Activity (network connection from process)
  2001 — Security Finding (EDR alert/detection)
  3001 — Account Change
  3002 — Authentication    (logon, logoff, MFA)
  3003 — Authorize Session
  3004 — Entity Management
  4001 — Network Activity  (firewall allow/block)
  4002 — HTTP Activity     (proxy/WAF)
  4003 — DNS Activity
  4004 — DHCP Activity
  5001 — Inventory Info
  6001 — API Activity      (cloud API calls, CloudTrail)
  6002 — Cloud Storage Activity
  6003 — Cloud Virtual Machine Activity

Reference: https://schema.ocsf.io/

Usage::

    from backend.engine.ocsf_normalizer import normalize_to_ocsf

    crowdstrike_event = {
        "event_simpleName": "ProcessRollup2",
        "ComputerName": "WKSTN-FIN-042",
        "UserName": "CORP\\jsmith",
        "ImageFileName": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -enc JABX...",
    }
    ocsf_event = normalize_to_ocsf(crowdstrike_event, vendor="crowdstrike", product="edr")
    # → {"class_uid": 1006, "class_name": "Process Activity", ...}
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ── OCSF class UID catalogue ──────────────────────────────────────────────────

OCSF_CLASSES: dict[int, str] = {
    1006: "Process Activity",
    2001: "Security Finding",
    3002: "Authentication",
    3003: "Authorize Session",
    3004: "Entity Management",
    4001: "Network Activity",
    4002: "HTTP Activity",
    4003: "DNS Activity",
    6001: "API Activity",
    6002: "Cloud Storage Activity",
}

OCSF_ACTIVITY: dict[str, int] = {
    "process_create":   1,
    "process_terminate": 2,
    "process_inject":   99,
    "logon_success":    1,
    "logon_failure":    2,
    "logoff":           3,
    "auth_mfa":         6,
    "network_connect":  1,
    "network_deny":     2,
    "dns_query":        1,
    "api_call":         1,
    "api_error":        2,
    "object_create":    1,
    "object_delete":    4,
    "object_read":      2,
}


# ── Vendor field → OCSF field translation tables ──────────────────────────────

# Each entry: (ocsf_field_path, transform_fn | None)
# transform_fn: optional callable(value) → ocsf_value

_CROWDSTRIKE_PROCESS_MAP: dict[str, tuple[str, Any]] = {
    "ComputerName":        ("device.hostname", None),
    "UserName":            ("actor.user.name", lambda v: v.split("\\")[-1] if "\\" in v else v),
    "ImageFileName":       ("process.file.path", None),
    "CommandLine":         ("process.cmd_line", None),
    "TargetProcessId":     ("process.pid", int),
    "ParentProcessId":     ("process.parent_process.pid", int),
    "SHA256HashData":      ("process.file.hashes.sha256", None),
    "MD5HashData":         ("process.file.hashes.md5", None),
    "IntegrityLevel":      ("process.integrity_info", None),
    "SessionId":           ("process.session.id", None),
    "aid":                 ("device.uid", None),
    "cid":                 ("metadata.tenant_uid", None),
}

_CROWDSTRIKE_NETWORK_MAP: dict[str, tuple[str, Any]] = {
    "ComputerName":        ("device.hostname", None),
    "UserName":            ("actor.user.name", lambda v: v.split("\\")[-1] if "\\" in v else v),
    "LocalAddressIP4":     ("src_endpoint.ip", None),
    "LocalPort":           ("src_endpoint.port", int),
    "RemoteAddressIP4":    ("dst_endpoint.ip", None),
    "RemotePort":          ("dst_endpoint.port", int),
    "Protocol":            ("connection_info.protocol_name", None),
}

_CROWDSTRIKE_DNS_MAP: dict[str, tuple[str, Any]] = {
    "ComputerName":        ("device.hostname", None),
    "UserName":            ("actor.user.name", None),
    "DomainName":          ("query.hostname", None),
    "RequestType":         ("query.type", None),
    "ResponseCode":        ("rcode", None),
    "ResolvedAddressIPV4": ("answers[0].rdata", None),
}

_OKTA_AUTH_MAP: dict[str, tuple[str, Any]] = {
    "actor.alternateId":       ("actor.user.email_addr", None),
    "actor.displayName":       ("actor.user.full_name", None),
    "client.ipAddress":        ("src_endpoint.ip", None),
    "client.userAgent.rawUserAgent": ("http_request.user_agent", None),
    "client.geographicalContext.city": ("src_endpoint.location.city", None),
    "client.geographicalContext.country": ("src_endpoint.location.country", None),
    "outcome.result":          ("status_id", lambda v: 1 if v == "SUCCESS" else 2),
    "outcome.reason":          ("status_detail", None),
    "target[0].alternateId":   ("dst_endpoint.uid", None),
    "displayMessage":          ("message", None),
    "eventType":               ("type_uid", None),
    "published":               ("time", None),
    "uuid":                    ("activity_id", None),
}

_PALO_ALTO_TRAFFIC_MAP: dict[str, tuple[str, Any]] = {
    "src":         ("src_endpoint.ip", None),
    "dst":         ("dst_endpoint.ip", None),
    "sport":       ("src_endpoint.port", int),
    "dport":       ("dst_endpoint.port", int),
    "proto":       ("connection_info.protocol_name", lambda v: v.upper()),
    "action":      ("action_id", lambda v: 1 if v.lower() == "allow" else 2),
    "bytes_sent":  ("traffic.bytes_out", int),
    "bytes_rcvd":  ("traffic.bytes_in", int),
    "pkts_sent":   ("traffic.packets_out", int),
    "pkts_rcvd":   ("traffic.packets_in", int),
    "sessionid":   ("connection_info.uid", None),
    "app":         ("app_name", None),
    "from":        ("src_endpoint.zone", None),
    "to":          ("dst_endpoint.zone", None),
    "rule":        ("firewall_rule.name", None),
    "type":        ("category_name", None),
    "subtype":     ("subcategory_name", None),
    "serial":      ("device.serial_number", None),
    "devname":     ("device.name", None),
    "vsys":        ("device.vsys", None),
    "receive_time": ("time", None),
    "start":       ("start_time", None),
    "elapsed":     ("duration", int),
    "threatid":    ("analytic.uid", None),
    "severity":    ("severity_id", None),
    "direction":   ("direction_id", lambda v: 1 if v.lower() == "inbound" else 2),
}

_AWS_CLOUDTRAIL_MAP: dict[str, tuple[str, Any]] = {
    "eventName":        ("api.operation", None),
    "eventSource":      ("api.service.name", None),
    "awsRegion":        ("region", None),
    "sourceIPAddress":  ("src_endpoint.ip", None),
    "userAgent":        ("http_request.user_agent", None),
    "errorCode":        ("api.response.error", None),
    "errorMessage":     ("api.response.message", None),
    "eventType":        ("type_uid", None),
    "eventTime":        ("time", None),
    "userIdentity.type": ("actor.user.type", None),
    "userIdentity.arn":  ("actor.user.uid", None),
    "userIdentity.accountId": ("actor.user.account_uid", None),
    "userIdentity.userName":  ("actor.user.name", None),
    "requestParameters": ("api.request", None),
    "responseElements":  ("api.response", None),
    "resources":         ("resources", None),
    "eventID":           ("activity_id", None),
}

_WINDOWS_EVENTLOG_MAP: dict[str, tuple[str, Any]] = {
    "EventID":            ("type_uid", None),
    "Computer":           ("device.hostname", None),
    "SubjectUserName":    ("actor.user.name", None),
    "SubjectDomainName":  ("actor.user.domain", None),
    "TargetUserName":     ("user.name", None),
    "ProcessName":        ("process.file.path", None),
    "CommandLine":        ("process.cmd_line", None),
    "ParentProcessName":  ("process.parent_process.file.path", None),
    "IpAddress":          ("src_endpoint.ip", None),
    "IpPort":             ("src_endpoint.port", int),
    "LogonType":          ("logon_type_id", int),
    "NewProcessId":       ("process.pid", lambda v: int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)),
    "WorkstationName":    ("src_endpoint.hostname", None),
    "TimeCreated":        ("time", None),
}


# ── Compound vendor map ───────────────────────────────────────────────────────

VENDOR_FIELD_MAPS: dict[str, dict[str, dict[str, tuple[str, Any]]]] = {
    "crowdstrike": {
        "ProcessRollup2":     _CROWDSTRIKE_PROCESS_MAP,
        "ProcessRollup2V2":   _CROWDSTRIKE_PROCESS_MAP,
        "NetworkConnectIP4":  _CROWDSTRIKE_NETWORK_MAP,
        "DnsRequest":         _CROWDSTRIKE_DNS_MAP,
        "UserLogon":          {**_CROWDSTRIKE_PROCESS_MAP,
                               "LogonDomain": ("actor.user.domain", None),
                               "LogonType": ("logon_type_id", int)},
        "default":            _CROWDSTRIKE_PROCESS_MAP,
    },
    "okta": {
        "user.session.start":         _OKTA_AUTH_MAP,
        "user.authentication.sso":    _OKTA_AUTH_MAP,
        "user.authentication.factor": _OKTA_AUTH_MAP,
        "policy.evaluate_sign_on":    _OKTA_AUTH_MAP,
        "default":                    _OKTA_AUTH_MAP,
    },
    "palo_alto": {
        "TRAFFIC":   _PALO_ALTO_TRAFFIC_MAP,
        "THREAT":    _PALO_ALTO_TRAFFIC_MAP,
        "URL":       _PALO_ALTO_TRAFFIC_MAP,
        "default":   _PALO_ALTO_TRAFFIC_MAP,
    },
    "aws": {
        "default":   _AWS_CLOUDTRAIL_MAP,
    },
    "microsoft": {
        "windows_security": _WINDOWS_EVENTLOG_MAP,
        "default":          _WINDOWS_EVENTLOG_MAP,
    },
}


# ── OCSF class selection heuristic ────────────────────────────────────────────

def _infer_ocsf_class(vendor: str, event_type: str, payload: dict) -> int:
    """Infer the best OCSF class UID for a given event."""
    et = event_type.lower()
    if "process" in et or "rollup" in et:
        return 1006
    if "network" in et or "connect" in et or "traffic" in et:
        return 4001
    if "dns" in et:
        return 4003
    if "logon" in et or "logoff" in et or "auth" in et or "sso" in et:
        return 3002
    if "http" in et or "url" in et:
        return 4002
    if "cloudtrail" in vendor.lower() or "api" in et:
        return 6001
    if "s3" in et or "storage" in et:
        return 6002
    if "alert" in et or "detection" in et or "finding" in et:
        return 2001
    return 1006  # Default to Process Activity


def _set_nested(obj: dict, path: str, value: Any) -> None:
    """Set a nested dict value using dot-notation path."""
    parts = path.split(".")
    cur = obj
    for part in parts[:-1]:
        if "[" in part:
            # Handle array access like "answers[0].rdata" — skip for now
            return
        cur = cur.setdefault(part, {})
    last = parts[-1]
    if "[" in last:
        return
    cur[last] = value


# ── Public API ────────────────────────────────────────────────────────────────

def normalize_to_ocsf(
    payload: dict[str, Any],
    vendor: str,
    product: str = "default",
    source_type: str = "",
) -> dict[str, Any]:
    """Normalize a vendor-specific event payload to OCSF canonical format.

    Args:
        payload:     Raw vendor event payload dict.
        vendor:      Vendor key, e.g. "crowdstrike", "okta", "palo_alto".
        product:     Product/table name hint (e.g. "edr", "cloudtrail").
        source_type: The log source type hint (e.g. "ProcessRollup2").

    Returns:
        OCSF-normalized event dict with ``class_uid``, ``class_name``, and
        canonical fields. Original vendor payload preserved under ``unmapped``.
    """
    vendor_key = vendor.lower().replace(" ", "_").replace("-", "_")
    vendor_maps = VENDOR_FIELD_MAPS.get(vendor_key, {})

    # Find the right field map
    field_map = vendor_maps.get(source_type) or vendor_maps.get("default") or {}

    ocsf: dict[str, Any] = {
        "metadata": {
            "version": "1.1.0",
            "product": {"vendor_name": vendor, "name": product},
            "original_time": None,
        },
    }

    unmapped: dict[str, Any] = {}
    mapped_keys: set[str] = set()

    for vendor_field, (ocsf_path, transform) in field_map.items():
        value = payload.get(vendor_field)
        if value is None:
            continue
        mapped_keys.add(vendor_field)
        if transform is not None:
            try:
                value = transform(value)
            except Exception:
                pass
        _set_nested(ocsf, ocsf_path, value)

    # Collect unmapped fields
    for k, v in payload.items():
        if k not in mapped_keys and not k.startswith("_"):
            unmapped[k] = v
    if unmapped:
        ocsf["unmapped"] = unmapped

    # Infer OCSF class
    event_type = source_type or payload.get("event_simpleName", "") or payload.get("eventType", "")
    class_uid = _infer_ocsf_class(vendor_key, event_type, payload)
    ocsf["class_uid"] = class_uid
    ocsf["class_name"] = OCSF_CLASSES.get(class_uid, "Unknown")
    ocsf["time"] = ocsf.get("time") or datetime.now(timezone.utc).isoformat()

    return ocsf


def get_ocsf_field_map(vendor: str, event_type: str = "default") -> dict[str, str]:
    """Return a vendor-field → ocsf-field mapping for documentation/frontend.

    Args:
        vendor:     Vendor key.
        event_type: Event type or "default".

    Returns:
        Dict mapping vendor field name → OCSF canonical path.
    """
    vendor_maps = VENDOR_FIELD_MAPS.get(vendor.lower(), {})
    field_map = vendor_maps.get(event_type) or vendor_maps.get("default") or {}
    return {vf: ocsf_path for vf, (ocsf_path, _) in field_map.items()}


def list_supported_vendors() -> list[dict[str, Any]]:
    """Return metadata about all vendors with OCSF mappings."""
    return [
        {
            "vendor": vendor,
            "event_types": [et for et in maps.keys() if et != "default"],
            "field_count": len(maps.get("default", {})),
        }
        for vendor, maps in VENDOR_FIELD_MAPS.items()
    ]
