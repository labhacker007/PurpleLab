"""Microsoft Advanced SIEM Information Model (ASIM) field mapping for PurpleLab.

Provides:
- to_asim(event, source_id)      — normalize a PurpleLab event to ASIM
- asim_schema(source_id)         — return the primary ASIM schema for a source
- ASIMNormalizer class (backward compat wrapper)

ASIM schemas implemented:
- AuditEvent       — admin / configuration changes
- Authentication   — logon/logoff, MFA, SSO events
- NetworkSession   — network flows, firewall, proxy
- ProcessEvent     — process creation and termination
- FileEvent        — file create/modify/delete
- DnsActivity      — DNS queries and responses (bonus)

ASIM reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-about-schemas
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ── Source → ASIM schema mapping ─────────────────────────────────────────────

_SOURCE_SCHEMA: dict[str, str] = {
    "okta": "Authentication",
    "entra_id": "Authentication",
    "crowdstrike": "ProcessEvent",
    "defender_endpoint": "ProcessEvent",
    "carbon_black": "ProcessEvent",
    "splunk": "AuditEvent",
    "qradar": "AuditEvent",
    "sentinel": "AuditEvent",
    "elastic": "AuditEvent",
    "guardduty": "NetworkSession",
    "proofpoint": "NetworkSession",
    "servicenow": "AuditEvent",
    "generic": "AuditEvent",
}

# ASIM EventSeverity normalization
_SEVERITY_MAP: dict[str, str] = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
    "unknown": "Informational",
}

# ASIM EventResult normalization
_RESULT_MAP: dict[str, str] = {
    "success": "Success",
    "allowed": "Success",
    "failure": "Failure",
    "failed": "Failure",
    "blocked": "Failure",
    "denied": "Failure",
    "partial": "Partial",
    "na": "NA",
    "unknown": "NA",
}


# ── Public functions ──────────────────────────────────────────────────────────

def asim_schema(source_id: str) -> str:
    """Return the primary ASIM schema name for a PurpleLab source_id.

    Args:
        source_id: PurpleLab log source identifier.

    Returns:
        ASIM schema string, e.g. "Authentication", "ProcessEvent".
    """
    return _SOURCE_SCHEMA.get(source_id.lower(), "AuditEvent")


def to_asim(event: dict[str, Any], source_id: str) -> dict[str, Any]:
    """Normalize a PurpleLab event dict to Microsoft ASIM format.

    Selects the most appropriate ASIM schema based on source_id and maps
    PurpleLab fields to their ASIM equivalents.  Unknown fields are retained
    under a ``AdditionalFields`` dict per ASIM convention.

    Args:
        event: Raw PurpleLab event dict.
        source_id: PurpleLab log source identifier, e.g. "okta".

    Returns:
        ASIM-normalised dict ready for ingestion into Microsoft Sentinel.
    """
    src = source_id.lower()
    schema = asim_schema(src)

    # ── TimeGenerated ─────────────────────────────────────────────────────────
    raw_time = (
        event.get("TimeGenerated")
        or event.get("timestamp")
        or event.get("@timestamp")
        or event.get("time")
        or event.get("created_at")
        or ""
    )
    if raw_time:
        try:
            from datetime import datetime as _dt
            if isinstance(raw_time, (int, float)):
                time_generated = _dt.fromtimestamp(float(raw_time), tz=timezone.utc).isoformat()
            else:
                time_generated = str(raw_time)
        except Exception:
            time_generated = datetime.now(timezone.utc).isoformat()
    else:
        time_generated = datetime.now(timezone.utc).isoformat()

    # ── Common ASIM mandatory fields ──────────────────────────────────────────
    severity_raw = str(
        event.get("severity") or event.get("alert_severity") or "unknown"
    ).lower()
    event_severity = _SEVERITY_MAP.get(severity_raw, "Informational")

    result_raw = str(
        event.get("result") or event.get("outcome") or event.get("action") or "unknown"
    ).lower()
    event_result = _RESULT_MAP.get(result_raw, "NA")

    src_ip = (
        event.get("src_ip") or event.get("source_ip")
        or event.get("src") or event.get("local_ip") or ""
    )
    dst_ip = (
        event.get("dst_ip") or event.get("dest_ip")
        or event.get("dest") or event.get("remote_ip") or ""
    )
    src_username = (
        event.get("user") or event.get("username")
        or event.get("user_name") or event.get("actor") or ""
    )
    dst_username = event.get("dst_user") or event.get("target_user") or ""

    # ── Base ASIM document ────────────────────────────────────────────────────
    asim_doc: dict[str, Any] = {
        # Mandatory common fields
        "TimeGenerated": time_generated,
        "EventProduct": _product_name(src),
        "EventVendor": _vendor_name(src),
        "EventSchema": schema,
        "EventSchemaVersion": "0.1.3",
        "EventCount": 1,
        "EventStartTime": time_generated,
        "EventEndTime": time_generated,
        "EventType": event.get("event_type") or event.get("action") or "Info",
        "EventSubType": event.get("event_subtype") or "",
        "EventResult": event_result,
        "EventResultDetails": event.get("reason") or event.get("failure_reason") or "",
        "EventSeverity": event_severity,
        "EventOriginalSeverity": str(event.get("severity") or ""),
        "EventOriginalType": event.get("event_type") or "",
        "EventOriginalUid": event.get("event_id") or event.get("id") or "",
        "EventOriginalSubType": event.get("event_subtype") or "",
        # Source / destination user
        "SrcUsername": src_username,
        "SrcUsernameType": "UPN" if "@" in src_username else "Simple",
        "DstUsername": dst_username,
        "DstUsernameType": "UPN" if "@" in dst_username else "Simple",
        # Source / destination IP
        "SrcIpAddr": src_ip,
        "DstIpAddr": dst_ip,
        "SrcHostname": (
            event.get("host") or event.get("hostname")
            or event.get("computer_name") or ""
        ),
        "DstHostname": (
            event.get("dest_hostname") or event.get("target_host") or dst_ip
        ),
        # Geo / network
        "SrcGeoCountry": event.get("country") or event.get("geo_country") or "",
        "SrcGeoCity": event.get("city") or event.get("geo_city") or "",
        "NetworkProtocol": event.get("protocol") or event.get("network_protocol") or "",
        "NetworkApplicationProtocol": event.get("app_protocol") or "",
        # Rule / alert
        "RuleName": event.get("rule_name") or event.get("alert_name") or event.get("title") or "",
        "RuleNumber": event.get("rule_id") or event.get("detection_id") or "",
        # MITRE
        "ThreatId": event.get("technique_id") or "",
        "ThreatName": event.get("technique") or event.get("threat_name") or "",
        "ThreatCategory": event.get("tactic") or "",
        "ThreatConfidence": event.get("confidence") or event.get("threat_confidence"),
        "ThreatFirstReportedTime": event.get("first_seen") or "",
        "ThreatLastReportedTime": event.get("last_seen") or "",
        # PurpleLab provenance
        "AdditionalFields": {
            "purplelab_source_id": src,
            "purplelab_scenario_id": event.get("scenario_id") or "",
            "purplelab_session_id": event.get("session_id") or "",
            **{
                k: v for k, v in event.items()
                if k not in _KNOWN_SOURCE_FIELDS and v not in (None, "")
            },
        },
    }

    # ── Schema-specific fields ────────────────────────────────────────────────
    if schema == "Authentication":
        asim_doc.update(_map_authentication(event, src_username, src_ip, dst_ip))
    elif schema == "NetworkSession":
        asim_doc.update(_map_network_session(event, src_ip, dst_ip))
    elif schema == "ProcessEvent":
        asim_doc.update(_map_process_event(event, src_username))
    elif schema == "FileEvent":
        asim_doc.update(_map_file_event(event, src_username))
    elif schema == "AuditEvent":
        asim_doc.update(_map_audit_event(event, src_username))
    elif schema == "DnsActivity":
        asim_doc.update(_map_dns_activity(event, src_ip))

    # Remove empty/None values
    return {k: v for k, v in asim_doc.items() if v not in (None, "", [])}


# ── Schema-specific field mappers ─────────────────────────────────────────────

def _map_authentication(
    event: dict[str, Any],
    src_username: str,
    src_ip: str,
    dst_ip: str,
) -> dict[str, Any]:
    """Map to ASIM Authentication schema extended fields."""
    return {
        # Authentication-specific
        "LogonMethod": event.get("auth_method") or event.get("factor") or "",
        "LogonProtocol": event.get("protocol") or event.get("auth_protocol") or "",
        "SrcDvcType": "Computer",
        "TargetUsername": event.get("target_user") or src_username,
        "TargetUsernameType": "Simple",
        "TargetUserId": event.get("user_id") or "",
        "TargetUserIdType": event.get("user_id_type") or "UID",
        "TargetUserType": event.get("user_type") or "Regular",
        "TargetSessionId": event.get("session_id") or "",
        "SrcDvcOs": event.get("os_platform") or event.get("platform") or "",
        "TargetAppName": event.get("app") or event.get("service") or "",
        "TargetAppType": event.get("app_type") or "SaaS app",
        "TargetAppId": event.get("app_id") or "",
        "ImpersonatedUsername": event.get("impersonated_user") or "",
        "MFAAuthMethod": event.get("mfa_method") or event.get("factor_type") or "",
        "RiskLevel": event.get("risk_level") or "",
        "RiskLevelOriginal": event.get("risk_score") or "",
    }


def _map_network_session(
    event: dict[str, Any],
    src_ip: str,
    dst_ip: str,
) -> dict[str, Any]:
    """Map to ASIM NetworkSession schema extended fields."""
    return {
        "SrcPortNumber": event.get("src_port") or event.get("source_port"),
        "DstPortNumber": event.get("dst_port") or event.get("dest_port") or event.get("port"),
        "NetworkDirection": event.get("direction") or event.get("network_direction") or "Unknown",
        "NetworkIcmpType": event.get("icmp_type"),
        "NetworkIcmpCode": event.get("icmp_code"),
        "NetworkDuration": event.get("duration"),
        "SrcBytes": event.get("bytes_out") or event.get("bytes_sent"),
        "DstBytes": event.get("bytes_in") or event.get("bytes_received"),
        "SrcPackets": event.get("packets_out"),
        "DstPackets": event.get("packets_in"),
        "SrcVlanId": event.get("src_vlan"),
        "DstVlanId": event.get("dst_vlan"),
        "NetworkSessionId": event.get("session_id") or event.get("connection_id") or "",
        "TcpFlagsStr": event.get("tcp_flags") or "",
        "DvcAction": event.get("action") or "",
        "DvcHostname": event.get("firewall") or event.get("device") or "",
        "InspectionFields": event.get("inspection_fields") or "",
        "UrlCategory": event.get("url_category") or event.get("category") or "",
        "Url": event.get("url") or event.get("request_url") or "",
    }


def _map_process_event(
    event: dict[str, Any],
    acting_user: str,
) -> dict[str, Any]:
    """Map to ASIM ProcessEvent schema extended fields."""
    return {
        "ActingProcessName": event.get("parent_process") or "",
        "ActingProcessId": str(event.get("parent_pid") or ""),
        "ActingProcessCommandLine": event.get("parent_cmdline") or "",
        "TargetProcessName": event.get("process_name") or event.get("process") or "",
        "TargetProcessId": str(event.get("pid") or event.get("process_id") or ""),
        "TargetProcessCommandLine": (
            event.get("command_line") or event.get("cmdline") or ""
        ),
        "TargetProcessCurrentDirectory": event.get("current_directory") or "",
        "TargetProcessFilename": event.get("process_name") or "",
        "TargetProcessFilepath": event.get("process_path") or event.get("image_path") or "",
        "TargetProcessSHA256": event.get("sha256") or "",
        "TargetProcessMD5": event.get("md5") or "",
        "TargetProcessCreationTime": event.get("process_start_time") or "",
        "TargetUsername": acting_user,
        "TargetUsernameType": "Simple",
        "TargetUserId": event.get("user_id") or "",
        "TargetUserSessionId": event.get("logon_id") or "",
        "TargetProcessIntegrityLevel": event.get("integrity_level") or "",
        "TargetProcessTokenElevation": event.get("token_elevation") or "",
    }


def _map_file_event(
    event: dict[str, Any],
    acting_user: str,
) -> dict[str, Any]:
    """Map to ASIM FileEvent schema extended fields."""
    file_path = (
        event.get("file_path") or event.get("target_path") or event.get("file_name") or ""
    )
    return {
        "TargetFilePath": file_path,
        "TargetFileName": _basename(file_path),
        "TargetFileSize": event.get("file_size"),
        "TargetFileSHA256": event.get("sha256") or "",
        "TargetFileMD5": event.get("md5") or "",
        "TargetFileCreationTime": event.get("file_created") or "",
        "TargetFileModificationTime": event.get("file_modified") or "",
        "TargetFileExtension": _file_extension(file_path),
        "SrcFilePath": event.get("src_file_path") or "",
        "SrcFileName": _basename(event.get("src_file_path") or ""),
        "ActorUsername": acting_user,
        "ActorUsernameType": "Simple",
        "ActorUserId": event.get("user_id") or "",
        "ActorProcessName": event.get("process_name") or event.get("process") or "",
        "ActorProcessId": str(event.get("pid") or ""),
    }


def _map_audit_event(
    event: dict[str, Any],
    acting_user: str,
) -> dict[str, Any]:
    """Map to ASIM AuditEvent schema extended fields."""
    return {
        "Operation": event.get("operation") or event.get("action") or event.get("event_type") or "",
        "Object": event.get("object") or event.get("resource") or event.get("target") or "",
        "ObjectType": event.get("object_type") or event.get("resource_type") or "",
        "OldValue": event.get("old_value") or "",
        "NewValue": event.get("new_value") or "",
        "ValueType": event.get("value_type") or "",
        "ActorUsername": acting_user,
        "ActorUsernameType": "Simple",
        "ActorUserId": event.get("user_id") or "",
        "ActorUserType": event.get("user_type") or "Regular",
        "ActorSessionId": event.get("session_id") or "",
        "ActorOriginalUserType": event.get("original_user_type") or "",
        "TargetUsername": event.get("target_user") or "",
        "TargetUsernameType": "Simple",
        "TargetUserId": event.get("target_user_id") or "",
        "TargetUserType": event.get("target_user_type") or "",
        "TargetAppId": event.get("app_id") or "",
        "TargetAppName": event.get("app") or event.get("service") or "",
        "TargetAppType": event.get("app_type") or "",
    }


def _map_dns_activity(
    event: dict[str, Any],
    src_ip: str,
) -> dict[str, Any]:
    """Map to ASIM DnsActivity schema extended fields."""
    return {
        "DnsQuery": event.get("dns_query") or event.get("domain") or "",
        "DnsQueryType": event.get("dns_type") or event.get("record_type") or "",
        "DnsQueryTypeName": event.get("dns_type_name") or "",
        "DnsResponseCode": event.get("response_code") or event.get("rcode"),
        "DnsResponseCodeName": event.get("rcode_name") or "",
        "DnsAnswerCount": event.get("answer_count"),
        "DnsFlagsAuthoritative": event.get("authoritative"),
        "DnsFlagsRecursionDesired": event.get("recursion_desired"),
        "DnsFlagsRecursionAvailable": event.get("recursion_available"),
        "DnsSessionId": event.get("session_id") or "",
        "SrcIpAddr": src_ip,
        "SrcPortNumber": event.get("src_port"),
        "DstIpAddr": event.get("dns_server") or event.get("resolver_ip") or "",
        "DstPortNumber": 53,
        "TransactionIdHex": event.get("transaction_id") or "",
        "IpAddresses": event.get("resolved_ips") or [],
    }


# ── ASIMNormalizer class (backward-compat) ────────────────────────────────────

class ASIMNormalizer:
    """Normalizes events to/from Microsoft ASIM format.

    Thin wrapper around the module-level ``to_asim`` function for object-oriented
    usage patterns.
    """

    def __init__(self, source_id: str = "generic") -> None:
        self.source_id = source_id

    def normalize(self, event: dict[str, Any], schema: str = "") -> dict[str, Any]:
        """Normalize event to ASIM format.

        Args:
            event: Raw PurpleLab event dict.
            schema: Optional ASIM schema override (ignored if empty).
        """
        return to_asim(event, self.source_id)

    def denormalize(self, asim_event: dict[str, Any], target_format: str = "raw") -> dict[str, Any]:
        """Extract core ASIM fields back to a flat dict."""
        flat: dict[str, Any] = {
            "timestamp": asim_event.get("TimeGenerated", ""),
            "event_product": asim_event.get("EventProduct", ""),
            "event_vendor": asim_event.get("EventVendor", ""),
            "event_type": asim_event.get("EventType", ""),
            "event_result": asim_event.get("EventResult", ""),
            "event_severity": asim_event.get("EventSeverity", ""),
            "src_username": asim_event.get("SrcUsername", ""),
            "dst_username": asim_event.get("DstUsername", ""),
            "src_ip": asim_event.get("SrcIpAddr", ""),
            "dst_ip": asim_event.get("DstIpAddr", ""),
            "rule_name": asim_event.get("RuleName", ""),
            "threat_id": asim_event.get("ThreatId", ""),
            "threat_name": asim_event.get("ThreatName", ""),
            "schema": asim_event.get("EventSchema", ""),
        }
        if target_format == "raw":
            additional = asim_event.get("AdditionalFields", {})
            flat.update({k: v for k, v in additional.items() if not k.startswith("purplelab_")})
        return {k: v for k, v in flat.items() if v not in (None, "", [])}


# ── Internal helpers ──────────────────────────────────────────────────────────

_KNOWN_SOURCE_FIELDS = frozenset({
    "TimeGenerated", "timestamp", "@timestamp", "time", "created_at",
    "severity", "alert_severity", "risk_level",
    "result", "outcome", "action", "action_result",
    "src_ip", "source_ip", "src", "local_ip",
    "dst_ip", "dest_ip", "dest", "remote_ip",
    "user", "username", "user_name", "actor",
    "user_domain", "domain",
    "host", "hostname", "computer_name", "device_id",
    "process_name", "process", "image_file_name",
    "pid", "process_id", "parent_pid", "parent_process",
    "command_line", "cmdline", "cmd",
    "sha256", "md5",
    "file_path", "file_name", "target_path",
    "url", "request_url", "url_domain",
    "dns_query", "dns_type", "dns_answers",
    "technique_id", "tactic_id", "technique", "tactic",
    "rule_name", "alert_name", "title", "rule_id", "detection_id",
    "description", "reason", "failure_reason",
    "event_id", "id", "event_type", "event_subtype",
    "os_platform", "platform", "os_type", "os_version",
    "user_id", "user_email", "email",
    "bytes_total", "bytes", "bytes_in", "bytes_out",
    "direction", "network_direction",
    "indicator_ip", "indicator_domain", "indicator_hash",
    "raw_log", "original", "message",
    "scenario_id", "session_id",
    "tags", "app", "service", "protocol",
    "first_seen", "last_seen", "confidence", "threat_confidence",
    "threat_name", "malware_name", "threat_actor",
})


def _product_name(source_id: str) -> str:
    _products = {
        "okta": "Okta Identity Cloud",
        "entra_id": "Microsoft Entra ID",
        "crowdstrike": "CrowdStrike Falcon",
        "defender_endpoint": "Microsoft Defender for Endpoint",
        "carbon_black": "VMware Carbon Black Cloud",
        "splunk": "Splunk",
        "qradar": "IBM QRadar",
        "sentinel": "Microsoft Sentinel",
        "elastic": "Elastic SIEM",
        "guardduty": "Amazon GuardDuty",
        "proofpoint": "Proofpoint TAP",
        "servicenow": "ServiceNow",
    }
    return _products.get(source_id, source_id.replace("_", " ").title())


def _vendor_name(source_id: str) -> str:
    _vendors = {
        "okta": "Okta",
        "entra_id": "Microsoft",
        "crowdstrike": "CrowdStrike",
        "defender_endpoint": "Microsoft",
        "carbon_black": "VMware",
        "splunk": "Splunk",
        "qradar": "IBM",
        "sentinel": "Microsoft",
        "elastic": "Elastic",
        "guardduty": "Amazon",
        "proofpoint": "Proofpoint",
        "servicenow": "ServiceNow",
    }
    return _vendors.get(source_id, "PurpleLab")


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _file_extension(path: str) -> str:
    name = _basename(path)
    if "." in name:
        return name.rsplit(".", 1)[-1].lower()
    return ""
