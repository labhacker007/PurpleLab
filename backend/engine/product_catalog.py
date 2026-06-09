"""Product catalog — maps security product categories to vendor-specific SIEM schemas.

When an environment is configured with specific security products (e.g., CrowdStrike for EDR,
Palo Alto for firewall), the simulation uses the exact field names, index names, and sourcetypes
from each vendor's real log schema — sourced from official vendor documentation.

Products are organized by category:
  edr            — Endpoint Detection & Response
  idp            — Identity Provider / IAM
  firewall       — Network Firewall / NGFW
  proxy          — Secure Web Gateway / Proxy
  cdn_waf        — CDN / Web Application Firewall
  cloud          — Cloud Infrastructure (AWS / Azure / GCP)
  email          — Email Security Gateway
  network_switch — Network Switch
  dhcp_dns       — DHCP / DNS
"""
from __future__ import annotations

from typing import Any


# ── Product registry ───────────────────────────────────────────────────────────
# Each vendor entry: display name, SIEM index, primary sourcetype, log format.
# Multiple sourcetypes (e.g. AWS has cloudtrail + vpc:flowlogs) listed under "sourcetypes".

PRODUCT_CATALOG: dict[str, dict[str, dict[str, Any]]] = {

    # ── Endpoint Detection & Response ────────────────────────────────────────
    "edr": {
        "crowdstrike": {
            "display": "CrowdStrike Falcon",
            "index": "crowdstrike",
            "sourcetype": "crowdstrike:falcon",
            "log_format": "json",
            "log_fields": {
                "host": "ComputerName",
                "user": "UserName",
                "process": "ImageFileName",
                "cmdline": "CommandLine",
                "pid": "TargetProcessId",
                "parent_pid": "ParentProcessId",
                "hash_sha256": "SHA256HashData",
                "src_ip": "LocalAddressIP4",
                "dst_ip": "RemoteAddressIP4",
                "dst_port": "RemotePort",
                "event_type": "event_simpleName",
                "agent_id": "aid",
                "customer_id": "cid",
            },
        },
        "sentinelone": {
            "display": "SentinelOne",
            "index": "sentinelone",
            "sourcetype": "sentinelone:deepvisibility",
            "log_format": "json",
            "log_fields": {
                "host": "endpoint.name",
                "user": "src.process.user",
                "process": "src.process.name",
                "cmdline": "src.process.cmdline",
                "pid": "src.process.pid",
                "hash_sha256": "src.process.image.sha256",
                "src_ip": "src.ip.address",
                "dst_ip": "dst.ip.address",
                "dst_port": "dst.port.number",
                "event_type": "event.type",
            },
        },
        "defender_mde": {
            "display": "Microsoft Defender for Endpoint",
            "index": "defender",
            "sourcetype": "ms:defender:advhunting",
            "log_format": "json",
            "log_fields": {
                "host": "DeviceName",
                "user": "AccountName",
                "process": "FileName",
                "cmdline": "ProcessCommandLine",
                "pid": "ProcessId",
                "hash_sha256": "SHA256",
                "src_ip": "LocalIP",
                "dst_ip": "RemoteIP",
                "dst_port": "RemotePort",
                "event_type": "ActionType",
                "device_id": "DeviceId",
            },
        },
        "carbon_black": {
            "display": "VMware Carbon Black EDR",
            "index": "carbonblack",
            "sourcetype": "carbonblack:edr",
            "log_format": "json",
            "log_fields": {
                "host": "sensor_hostname",
                "user": "username",
                "process": "process_name",
                "cmdline": "cmdline",
                "pid": "process_pid",
                "hash_sha256": "process_sha256",
                "src_ip": "local_ip",
                "dst_ip": "remote_ip",
                "dst_port": "remote_port",
                "event_type": "type",
            },
        },
        "cylance": {
            "display": "Cylance Protect",
            "index": "cylance",
            "sourcetype": "cylance:protect",
            "log_format": "json",
        },
        "sophos": {
            "display": "Sophos Endpoint",
            "index": "sophos",
            "sourcetype": "sophos:es",
            "log_format": "json",
        },
        "trend_micro": {
            "display": "Trend Micro Apex One",
            "index": "trendmicro",
            "sourcetype": "trendmicro:apex",
            "log_format": "json",
        },
        "cybereason": {
            "display": "Cybereason Defense Platform",
            "index": "cybereason",
            "sourcetype": "cybereason:sensor",
            "log_format": "json",
        },
        "eset": {
            "display": "ESET PROTECT",
            "index": "eset",
            "sourcetype": "eset:protect",
            "log_format": "json",
        },
        "symantec_sep": {
            "display": "Symantec Endpoint Protection",
            "index": "symantec",
            "sourcetype": "symantec:ep",
            "log_format": "syslog",
        },
    },

    # ── Identity Provider / IAM ──────────────────────────────────────────────
    "idp": {
        "okta": {
            "display": "Okta",
            "index": "okta",
            "sourcetype": "okta:systemlog",
            "log_format": "json",
            "log_fields": {
                "event_type": "eventType",
                "timestamp": "published",
                "user": "actor.displayName",
                "user_id": "actor.id",
                "email": "actor.alternateId",
                "result": "outcome.result",
                "reason": "outcome.reason",
                "src_ip": "client.ipAddress",
                "os": "client.userAgent.os",
                "browser": "client.userAgent.browser",
                "country": "client.geographicalContext.country",
                "city": "client.geographicalContext.city",
                "auth_provider": "authenticationContext.authenticationProvider",
                "session_id": "uuid",
            },
        },
        "entra_id": {
            "display": "Microsoft Entra ID (Azure AD)",
            "index": "azure",
            "sourcetype": "ms:aad:signin",
            "log_format": "json",
            "log_fields": {
                "user": "UserPrincipalName",
                "user_id": "UserId",
                "timestamp": "CreatedDateTime",
                "src_ip": "IPAddress",
                "app": "AppDisplayName",
                "resource": "ResourceDisplayName",
                "result": "ResultType",
                "error_code": "Status.errorCode",
                "failure_reason": "Status.failureReason",
                "risk_state": "RiskState",
                "risk_level": "RiskLevelAggregated",
                "mfa": "AuthenticationRequirement",
                "device": "DeviceDetail.displayName",
                "os": "DeviceDetail.operatingSystem",
                "ca_status": "ConditionalAccessStatus",
                "correlation_id": "CorrelationId",
            },
        },
        "active_directory": {
            "display": "Active Directory (Windows Security)",
            "index": "windows",
            "sourcetype": "WinEventLog:Security",
            "log_format": "xml",
            "log_fields": {
                "event_id": "EventID",
                "host": "Computer",
                "subject_user": "SubjectUserName",
                "target_user": "TargetUserName",
                "domain": "TargetDomainName",
                "logon_type": "LogonType",
                "auth_package": "AuthenticationPackageName",
                "src_ip": "IpAddress",
                "src_port": "IpPort",
                "logon_id": "TargetLogonId",
                "logon_guid": "LogonGuid",
                "process": "ProcessName",
                "workstation": "WorkstationName",
            },
        },
        "ping_identity": {
            "display": "Ping Identity",
            "index": "pingid",
            "sourcetype": "ping:access",
            "log_format": "json",
        },
        "sailpoint": {
            "display": "SailPoint IdentityIQ",
            "index": "sailpoint",
            "sourcetype": "sailpoint:iiq",
            "log_format": "syslog",
        },
        "cyberark": {
            "display": "CyberArk PAM",
            "index": "cyberark",
            "sourcetype": "cyberark:epm",
            "log_format": "syslog",
        },
        "beyond_trust": {
            "display": "BeyondTrust Privileged Access",
            "index": "beyondtrust",
            "sourcetype": "beyondtrust:pra",
            "log_format": "json",
        },
        "cisco_ise": {
            "display": "Cisco Identity Services Engine",
            "index": "cisco_ise",
            "sourcetype": "cisco:ise:syslog",
            "log_format": "syslog",
        },
        "forgerock": {
            "display": "ForgeRock Access Management",
            "index": "forgerock",
            "sourcetype": "forgerock:am",
            "log_format": "json",
        },
        "saviynt": {
            "display": "Saviynt Enterprise Identity Cloud",
            "index": "saviynt",
            "sourcetype": "saviynt:ecg",
            "log_format": "json",
        },
    },

    # ── Network Firewall / NGFW ──────────────────────────────────────────────
    "firewall": {
        "palo_alto": {
            "display": "Palo Alto Networks NGFW",
            "index": "pan_logs",
            "sourcetype": "pan:traffic",
            "log_format": "csv",
            "log_fields": {
                "timestamp": "receive_time",
                "src_ip": "src",
                "dst_ip": "dst",
                "nat_src": "natsrc",
                "nat_dst": "natdst",
                "src_port": "sport",
                "dst_port": "dport",
                "action": "action",
                "app": "app",
                "rule": "rule",
                "user": "srcuser",
                "bytes": "bytes",
                "bytes_sent": "bytes_sent",
                "bytes_recv": "bytes_received",
                "proto": "proto",
                "direction": "from",
                "zone_from": "from",
                "zone_to": "to",
                "serial": "serial",
                "type": "type",
            },
        },
        "fortinet": {
            "display": "Fortinet FortiGate",
            "index": "fortinet",
            "sourcetype": "fgt_traffic",
            "log_format": "keyvalue",
            "log_fields": {
                "timestamp": "date",
                "src_ip": "srcip",
                "dst_ip": "dstip",
                "src_port": "srcport",
                "dst_port": "dstport",
                "action": "action",
                "service": "service",
                "app": "app",
                "rule": "policyid",
                "user": "user",
                "bytes_sent": "sentbyte",
                "bytes_recv": "rcvdbyte",
                "proto": "proto",
                "device": "devname",
                "type": "type",
                "subtype": "subtype",
            },
        },
        "checkpoint": {
            "display": "Check Point Firewall",
            "index": "checkpoint",
            "sourcetype": "cp:firewall",
            "log_format": "keyvalue",
            "log_fields": {
                "action": "action",
                "src_ip": "src",
                "dst_ip": "dst",
                "src_port": "s_port",
                "service": "service",
                "rule": "rule_name",
                "rule_uid": "rule_uid",
                "if_dir": "ifdir",
                "if_name": "ifname",
                "zone_in": "inzone",
                "zone_out": "outzone",
                "origin": "origin",
                "proto": "proto",
            },
        },
        "cisco_asa": {
            "display": "Cisco ASA / Firepower",
            "index": "cisco_firewall",
            "sourcetype": "cisco:asa",
            "log_format": "syslog",
            "log_fields": {
                "message_id": "msg_id",
                "src_if": "src_interface",
                "src_ip": "src_ip",
                "src_port": "src_port",
                "dst_if": "dst_interface",
                "dst_ip": "dst_ip",
                "dst_port": "dst_port",
                "proto": "protocol",
                "action": "action",
                "conn_id": "connection_id",
            },
        },
        "juniper": {
            "display": "Juniper SRX",
            "index": "juniper",
            "sourcetype": "juniper:junos",
            "log_format": "syslog",
        },
        "cisco_meraki": {
            "display": "Cisco Meraki MX",
            "index": "meraki",
            "sourcetype": "meraki",
            "log_format": "syslog",
        },
        "sonicwall": {
            "display": "SonicWall NGFW",
            "index": "sonicwall",
            "sourcetype": "sonicwall",
            "log_format": "syslog",
        },
        "barracuda_fw": {
            "display": "Barracuda CloudGen Firewall",
            "index": "barracuda",
            "sourcetype": "barracuda:cf",
            "log_format": "syslog",
        },
    },

    # ── Secure Web Gateway / Proxy ──────────────────────────────────────────
    "proxy": {
        "zscaler": {
            "display": "Zscaler Internet Access",
            "index": "zscaler",
            "sourcetype": "zscaler:zia",
            "log_format": "json",
            "log_fields": {
                "timestamp": "datetime",
                "user": "user",
                "src_ip": "srcip",
                "dst_ip": "dstip",
                "hostname": "hostname",
                "url": "url",
                "action": "action",
                "category": "category",
                "threat": "threat",
                "http_status": "respcode",
                "bytes_req": "requestsize",
                "bytes_resp": "responsesize",
                "location": "location",
                "department": "department",
            },
        },
        "symantec_proxy": {
            "display": "Broadcom ProxySG (BlueCoat)",
            "index": "bluecoat",
            "sourcetype": "bluecoat:proxysg",
            "log_format": "w3c",
        },
        "cisco_wsa": {
            "display": "Cisco Secure Web Appliance",
            "index": "cisco_wsa",
            "sourcetype": "cisco:wsa",
            "log_format": "syslog",
        },
        "mcafee_webgateway": {
            "display": "Skyhigh Secure Web Gateway",
            "index": "mcafee",
            "sourcetype": "mcafee:mwg",
            "log_format": "syslog",
        },
        "squid": {
            "display": "Squid Proxy",
            "index": "squid",
            "sourcetype": "squid",
            "log_format": "native",
        },
    },

    # ── CDN / WAF ────────────────────────────────────────────────────────────
    "cdn_waf": {
        "cloudflare": {
            "display": "Cloudflare WAF / CDN",
            "index": "cloudflare",
            "sourcetype": "cloudflare:logpush",
            "log_format": "json",
            "log_fields": {
                "src_ip": "ClientIP",
                "host": "ClientRequestHost",
                "method": "ClientRequestMethod",
                "uri": "ClientRequestURI",
                "http_status": "EdgeResponseStatus",
                "bytes": "EdgeResponseBytes",
                "waf_action": "WAFAction",
                "waf_rule": "WAFRuleID",
                "ray_id": "RayID",
                "timestamp": "Datetime",
                "cache": "CacheCacheStatus",
                "protocol": "HTTPProtocol",
            },
        },
        "akamai": {
            "display": "Akamai Kona Site Defender",
            "index": "akamai",
            "sourcetype": "akamai:siem",
            "log_format": "json",
        },
        "aws_waf": {
            "display": "AWS WAF",
            "index": "aws",
            "sourcetype": "aws:waf",
            "log_format": "json",
        },
        "azure_waf": {
            "display": "Azure Front Door / WAF",
            "index": "azure",
            "sourcetype": "azure:frontdoor",
            "log_format": "json",
        },
        "f5_asm": {
            "display": "F5 BIG-IP ASM",
            "index": "f5",
            "sourcetype": "f5:bigip:asm",
            "log_format": "syslog",
        },
    },

    # ── Cloud Infrastructure ─────────────────────────────────────────────────
    "cloud": {
        "aws": {
            "display": "Amazon Web Services",
            "index": "aws",
            "sourcetype": "aws:cloudtrail",
            "sourcetypes": ["aws:cloudtrail", "aws:vpc:flowlogs", "aws:config", "aws:guardduty"],
            "log_format": "json",
            "log_fields": {
                "timestamp": "eventTime",
                "event": "eventName",
                "service": "eventSource",
                "user": "userIdentity.type",
                "user_arn": "userIdentity.arn",
                "account_id": "userIdentity.accountId",
                "src_ip": "sourceIPAddress",
                "region": "awsRegion",
                "event_id": "eventID",
                "request": "requestParameters",
                "response": "responseElements",
                "error": "errorCode",
            },
        },
        "azure": {
            "display": "Microsoft Azure",
            "index": "azure",
            "sourcetype": "ms:azure:activitylog",
            "sourcetypes": ["ms:azure:activitylog", "ms:aad:signin", "ms:azure:diagnostics"],
            "log_format": "json",
            "log_fields": {
                "timestamp": "time",
                "operation": "operationName",
                "resource_id": "resourceId",
                "resource_type": "resourceType",
                "caller": "caller",
                "caller_ip": "callerIpAddress",
                "result": "resultType",
                "status": "status",
                "category": "category",
                "subscription": "subscriptionId",
                "correlation_id": "correlationId",
            },
        },
        "gcp": {
            "display": "Google Cloud Platform",
            "index": "gcp",
            "sourcetype": "google:gcp:audit",
            "sourcetypes": ["google:gcp:audit", "google:gcp:vpc:flowlogs"],
            "log_format": "json",
            "log_fields": {
                "timestamp": "timestamp",
                "service": "protoPayload.serviceName",
                "method": "protoPayload.methodName",
                "resource": "protoPayload.resourceName",
                "user": "protoPayload.authenticationInfo.principalEmail",
                "src_ip": "protoPayload.requestMetadata.callerIp",
                "severity": "severity",
                "log_name": "logName",
            },
        },
    },

    # ── Email Security ───────────────────────────────────────────────────────
    "email": {
        "m365": {
            "display": "Microsoft 365 / Exchange Online",
            "index": "o365",
            "sourcetype": "ms:o365:management:activity",
            "log_format": "json",
            "log_fields": {
                "timestamp": "CreationTime",
                "operation": "Operation",
                "user": "UserId",
                "workload": "Workload",
                "src_ip": "ClientIP",
                "result": "ResultStatus",
                "record_type": "RecordType",
                "org_id": "OrganizationId",
                "scope": "Scope",
            },
        },
        "proofpoint": {
            "display": "Proofpoint TAP",
            "index": "proofpoint",
            "sourcetype": "proofpoint:tap",
            "log_format": "json",
            "log_fields": {
                "timestamp": "messageTime",
                "message_id": "messageID",
                "from": "fromAddress",
                "to": "toAddresses",
                "sender_ip": "senderIP",
                "subject": "subject",
                "classification": "classification",
                "threat_id": "threatID",
                "event_type": "eventTypeString",
                "campaign_id": "campaignId",
            },
        },
        "google_workspace": {
            "display": "Google Workspace",
            "index": "gworkspace",
            "sourcetype": "google:workspace:admin",
            "log_format": "json",
            "log_fields": {
                "timestamp": "id.time",
                "user": "actor.email",
                "app": "id.applicationName",
                "customer_id": "id.customerId",
                "src_ip": "ipAddress",
                "event_type": "events[0].type",
                "event_name": "events[0].name",
            },
        },
        "mimecast": {
            "display": "Mimecast Email Security",
            "index": "mimecast",
            "sourcetype": "mimecast:audit",
            "log_format": "json",
        },
        "barracuda_email": {
            "display": "Barracuda Email Security Gateway",
            "index": "barracuda",
            "sourcetype": "barracuda:email",
            "log_format": "syslog",
        },
        "cisco_email": {
            "display": "Cisco Secure Email Gateway",
            "index": "cisco_email",
            "sourcetype": "cisco:esa",
            "log_format": "syslog",
        },
    },

    # ── Network Switch ───────────────────────────────────────────────────────
    "network_switch": {
        "cisco_ios": {
            "display": "Cisco IOS Switch",
            "index": "network_infra",
            "sourcetype": "cisco:ios",
            "log_format": "syslog",
        },
        "cisco_nxos": {
            "display": "Cisco NX-OS",
            "index": "network_infra",
            "sourcetype": "cisco:nxos",
            "log_format": "syslog",
        },
        "aruba": {
            "display": "Aruba / HPE Switch",
            "index": "network_infra",
            "sourcetype": "aruba:switch",
            "log_format": "syslog",
        },
        "juniper_ex": {
            "display": "Juniper EX Series Switch",
            "index": "juniper",
            "sourcetype": "juniper:junos",
            "log_format": "syslog",
        },
    },

    # ── DHCP / DNS ───────────────────────────────────────────────────────────
    "dhcp_dns": {
        "windows_dns": {
            "display": "Windows DNS Server",
            "index": "windows",
            "sourcetype": "WinEventLog:DNS Server",
            "log_format": "xml",
        },
        "infoblox": {
            "display": "Infoblox NIOS DNS",
            "index": "infoblox",
            "sourcetype": "infoblox:dns",
            "log_format": "syslog",
        },
        "cisco_umbrella": {
            "display": "Cisco Umbrella DNS",
            "index": "umbrella",
            "sourcetype": "cisco:umbrella:dns",
            "log_format": "json",
        },
        "bind": {
            "display": "ISC BIND DNS",
            "index": "dns",
            "sourcetype": "bind:query",
            "log_format": "syslog",
        },
    },
}


# ── Default vendor per category ────────────────────────────────────────────────
# Used when an environment hasn't specified a vendor for a category.

DEFAULT_VENDORS: dict[str, str] = {
    "edr": "crowdstrike",
    "idp": "active_directory",
    "firewall": "palo_alto",
    "proxy": "zscaler",
    "cdn_waf": "cloudflare",
    "cloud": "aws",
    "email": "m365",
    "network_switch": "cisco_ios",
    "dhcp_dns": "windows_dns",
}


# ── Component → category mapping ───────────────────────────────────────────────
# Maps benign_library component names and ttp_library log_source names to categories.
# Windows endpoint / Sysmon / Linux components are NOT in this map because their
# schemas are fixed (no vendor choice).

COMPONENT_TO_CATEGORY: dict[str, str] = {
    # benign_library component names
    "edr": "edr",
    "email": "email",
    "proxy_firewall": "firewall",
    "cloud": "cloud",
    # ttp_library log_source names
    "edr_endpoint": "edr",
    "email_security": "email",
    "network_traffic": "firewall",
    "proxy": "proxy",
    "firewall": "firewall",
    "cloud_trail": "cloud",
    "auth": "idp",
    "dns": "dhcp_dns",
}


# ── Public API ─────────────────────────────────────────────────────────────────

def get_product_schema(category: str, vendor: str | None = None) -> dict[str, str]:
    """Return the SIEM schema (index + sourcetype) for a product category and optional vendor.

    Falls back to the default vendor for the category, then to a generic fallback.

    Args:
        category: Product category key (e.g., "edr", "firewall", "cloud").
        vendor:   Vendor key within the category (e.g., "crowdstrike", "palo_alto", "aws").

    Returns:
        Dict with keys ``index`` and ``sourcetype``.
    """
    v = vendor or DEFAULT_VENDORS.get(category)
    if v:
        prod = PRODUCT_CATALOG.get(category, {}).get(v)
        if prod:
            return {"index": prod["index"], "sourcetype": prod["sourcetype"]}

    # Generic fallbacks per category
    _fallbacks: dict[str, dict[str, str]] = {
        "edr":           {"index": "endpoint",       "sourcetype": "edr:events"},
        "idp":           {"index": "windows",        "sourcetype": "WinEventLog:Security"},
        "firewall":      {"index": "network",        "sourcetype": "network:firewall"},
        "proxy":         {"index": "proxy",          "sourcetype": "proxy:web"},
        "cdn_waf":       {"index": "waf",            "sourcetype": "waf:http"},
        "cloud":         {"index": "cloud",          "sourcetype": "cloud:audit"},
        "email":         {"index": "email",          "sourcetype": "email:security"},
        "network_switch": {"index": "network_infra", "sourcetype": "network:switch"},
        "dhcp_dns":      {"index": "dns",            "sourcetype": "dns:query"},
    }
    return _fallbacks.get(category, {"index": "main", "sourcetype": "generic"})


def resolve_schema_for_component(
    component: str,
    products: dict[str, str],
) -> dict[str, str]:
    """Resolve the SIEM schema for a simulation component using environment product config.

    Windows/Sysmon/Linux components always return their fixed schemas.
    For EDR/firewall/cloud/email/etc., the vendor is looked up from the products dict.

    Args:
        component: Component name from benign_library or ttp_library.
        products:  Product selection dict from environment settings (e.g., {"edr": "crowdstrike"}).

    Returns:
        Dict with keys ``index`` and ``sourcetype``.
    """
    # Fixed-schema components — no vendor selection
    _fixed: dict[str, dict[str, str]] = {
        "windows_endpoint": {"index": "windows",    "sourcetype": "WinEventLog:Security"},
        "windows_server":   {"index": "windows",    "sourcetype": "WinEventLog:Security"},
        "sysmon":           {"index": "sysmon",     "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"},
        "linux":            {"index": "linux_log",  "sourcetype": "linux:syslog"},
        "linux_auditd":     {"index": "linux_log",  "sourcetype": "linux:syslog"},
        "windows_eventlog": {"index": "windows",    "sourcetype": "WinEventLog:Security"},
    }
    if component in _fixed:
        return _fixed[component]

    # Look up vendor-configurable category
    category = COMPONENT_TO_CATEGORY.get(component)
    if category is None:
        return {"index": "main", "sourcetype": component}

    vendor = products.get(category)
    return get_product_schema(category, vendor)


def list_products(category: str) -> list[dict[str, str]]:
    """Return all available products for a given category.

    Returns list of {"vendor": ..., "display": ..., "index": ..., "sourcetype": ...}.
    """
    result = []
    for vendor_key, info in PRODUCT_CATALOG.get(category, {}).items():
        result.append({
            "vendor": vendor_key,
            "display": info.get("display", vendor_key),
            "index": info.get("index", ""),
            "sourcetype": info.get("sourcetype", ""),
        })
    return result


def list_all_categories() -> list[str]:
    """Return all product category keys."""
    return list(PRODUCT_CATALOG.keys())
