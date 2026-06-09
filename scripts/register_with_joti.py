#!/usr/bin/env python3
"""Register PurpleLab as an MCP server in Joti's MCP Hub.

Run once after both platforms are running:
  python scripts/register_with_joti.py

Environment overrides (all optional):
  JOTI_ADMIN_EMAIL      default: admin@joti.local
  JOTI_ADMIN_PASSWORD   default: Admin@1234
  JOTI_BASE_URL         default: http://localhost:8000
  PURPLELAB_MCP_URL     default: http://purplelab-backend:8000/api/v2/mcp
  PURPLELAB_MCP_API_KEY default: purplelab-dev-key  (read from ../.env if present)

Creates:
  1. MCPServerConfig — PurpleLab registered as MCP server in Joti
  2. Four enrichment policies (IOC Hunt, EDR Detections, Endpoint Status, Active Blocks)
"""
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────────

JOTI_BASE     = os.getenv("JOTI_BASE_URL", "http://localhost:8000") + "/api"
JOTI_EMAIL    = os.getenv("JOTI_ADMIN_EMAIL", "admin@joti.local")
JOTI_PASSWORD = os.getenv("JOTI_ADMIN_PASSWORD", "Admin@1234")

# PurpleLab URL as seen from inside Joti's Docker network.
# If Joti and PurpleLab share the 'purplelab' Docker network, use the service hostname.
# If calling from the host (outside Docker), use http://localhost:8002/api/v2/mcp.
PURPLELAB_MCP_URL = os.getenv(
    "PURPLELAB_MCP_URL",
    "http://purplelab-backend:8000/api/v2/mcp",
)

# Read MCP API key from env, then fall back to reading ../.env file
def _read_mcp_key() -> str:
    key = os.getenv("PURPLELAB_MCP_API_KEY")
    if key:
        return key
    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("PURPLELAB_MCP_API_KEY="):
                return line.split("=", 1)[1].strip()
    return "purplelab-dev-key"

PURPLELAB_MCP_API_KEY = _read_mcp_key()


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def joti_request(method: str, path: str, data: dict | None = None, token: str | None = None) -> dict:
    payload = json.dumps(data).encode() if data is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{JOTI_BASE}{path}", data=payload, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise urllib.error.HTTPError(e.url, e.code, f"{e.reason} — {body[:200]}", e.headers, None)


def joti_post(path: str, data: dict, token: str | None = None) -> dict:
    return joti_request("POST", path, data, token)


def joti_get(path: str, token: str) -> dict:
    return joti_request("GET", path, None, token)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    # 1. Authenticate with Joti
    print("Authenticating with Joti...")
    try:
        auth = joti_post("/auth/login", {"email": JOTI_EMAIL, "password": JOTI_PASSWORD})
    except Exception as e:
        print(f"ERROR: Could not reach Joti at {JOTI_BASE}: {e}")
        sys.exit(1)

    token = auth.get("access_token")
    if not token:
        print("ERROR: Login failed:", auth)
        sys.exit(1)
    print(f"  Logged in as {JOTI_EMAIL}")

    # 2. Check if PurpleLab MCP server already registered
    server_id: int | None = None
    try:
        data = joti_get("/attack-surface/mcp", token)
        servers = data.get("servers", data) if isinstance(data, dict) else data
        if not isinstance(servers, list):
            servers = []
        existing = [
            s for s in servers
            if "purplelab" in s.get("name", "").lower()
            or "purplelab" in s.get("url", "").lower()
        ]
        if existing:
            server_id = existing[0]["id"]
            print(f"  PurpleLab MCP server already registered (id: {server_id})")
    except Exception:
        pass

    # 3. Register PurpleLab MCP server (if not already present)
    if server_id is None:
        print("Registering PurpleLab as MCP server in Joti...")
        try:
            server = joti_post("/attack-surface/mcp", {
                "name": "PurpleLab Security Simulator",
                "description": (
                    "Simulated EDR (CrowdStrike/Defender/SentinelOne), SIEM, "
                    "Identity (Okta/Entra), and Network controls for SOC testing "
                    "and purple team exercises. All containment actions are fully logged."
                ),
                "url": PURPLELAB_MCP_URL,
                "auth_type": "api_key",
                "api_key": PURPLELAB_MCP_API_KEY,
                "domains": ["threat_intel", "hunting", "attack_surface"],
                "is_enabled": True,
            }, token)
            server_id = server.get("id")
            print(f"  Registered with id: {server_id}")
        except urllib.error.HTTPError as e:
            if e.code == 400 and "not permitted" in str(e):
                print(f"  SSRF policy blocked {PURPLELAB_MCP_URL}")
                print("  Trying localhost URL (for host-network registration)...")
                server = joti_post("/attack-surface/mcp", {
                    "name": "PurpleLab Security Simulator",
                    "description": (
                        "Simulated EDR (CrowdStrike/Defender/SentinelOne), SIEM, "
                        "Identity (Okta/Entra), and Network controls for SOC testing "
                        "and purple team exercises."
                    ),
                    "url": "http://localhost:8002/api/v2/mcp",
                    "auth_type": "api_key",
                    "api_key": PURPLELAB_MCP_API_KEY,
                    "domains": ["threat_intel", "hunting", "attack_surface"],
                    "is_enabled": True,
                }, token)
                server_id = server.get("id")
                print(f"  Registered with id: {server_id}")
            else:
                raise

    if not server_id:
        print("ERROR: Could not get server ID after registration")
        sys.exit(1)

    # 4. Create enrichment policies
    policies = [
        {
            "name": "PurpleLab: IOC Hunt (cases)",
            "description": "Hunt for case IOCs across the simulated EDR fleet",
            "entity_types": ["case"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "edr_hunt_ioc",
            "entity_key_template": "{{ entity.title }}",
            "tool_arg_name": "ioc_value",
            "static_args": {"ioc_type": "ip", "time_range_hours": 48},
            "field_mappings": [
                {"result_path": "total_hits", "display_label": "Hunt Hits", "overlay_key": "hunt_hits", "value_type": "number"},
                {"result_path": "scanned_endpoints", "display_label": "Endpoints Scanned", "overlay_key": "endpoints_scanned", "value_type": "number"},
            ],
            "overlay_section": "custom",
            "icon": "Target",
            "priority": 10,
            "cache_ttl_seconds": 1800,
        },
        {
            "name": "PurpleLab: EDR Detections (alerts)",
            "description": "Fetch matching EDR detections for this alert from PurpleLab",
            "entity_types": ["alert"],
            "trigger_mode": "on_create",
            "server_id": server_id,
            "tool_name": "edr_get_detections",
            "entity_key_template": "{{ entity.severity }}",
            "tool_arg_name": "severity",
            "static_args": {"limit": 10},
            "field_mappings": [
                {"result_path": "total", "display_label": "Related Detections", "overlay_key": "detection_count", "value_type": "number"},
            ],
            "overlay_section": "custom",
            "icon": "ShieldAlert",
            "priority": 20,
            "cache_ttl_seconds": 300,
        },
        {
            "name": "PurpleLab: Endpoint Status (cases)",
            "description": "Check simulated endpoint isolation status for hosts mentioned in the case",
            "entity_types": ["case"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "edr_list_devices",
            "entity_key_template": "online",
            "tool_arg_name": "status",
            "static_args": {},
            "field_mappings": [
                {"result_path": "total", "display_label": "Online Endpoints", "overlay_key": "online_endpoints", "value_type": "number"},
            ],
            "overlay_section": "network",
            "icon": "Server",
            "priority": 30,
            "cache_ttl_seconds": 600,
        },
        {
            "name": "PurpleLab: Active Blocks",
            "description": "Show active network blocks (IPs, domains, hashes) from PurpleLab",
            "entity_types": ["case", "alert"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "network_get_blocks",
            "entity_key_template": "ip",
            "tool_arg_name": "block_type",
            "static_args": {"limit": 20},
            "field_mappings": [
                {"result_path": "total",          "display_label": "Active Blocks",   "overlay_key": "active_blocks",   "value_type": "number"},
                {"result_path": "summary.ip",     "display_label": "Blocked IPs",     "overlay_key": "blocked_ips",     "value_type": "number"},
                {"result_path": "summary.domain", "display_label": "Blocked Domains", "overlay_key": "blocked_domains", "value_type": "number"},
            ],
            "overlay_section": "network",
            "icon": "Ban",
            "priority": 40,
            "cache_ttl_seconds": 300,
        },
        {
            "name": "PurpleLab: User Risk Status (cases)",
            "description": "Check identity risk and lockout status for users mentioned in the case",
            "entity_types": ["case"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "identity_list_users",
            "entity_key_template": "high",
            "tool_arg_name": "risk_level",
            "static_args": {"limit": 20},
            "field_mappings": [
                {"result_path": "total", "display_label": "High-Risk Users", "overlay_key": "high_risk_users", "value_type": "number"},
            ],
            "overlay_section": "identity",
            "icon": "UserX",
            "priority": 50,
            "cache_ttl_seconds": 600,
        },
        # ── Enterprise CMDB / Product Registry / VM / CSPM policies ─────────
        {
            "name": "PurpleLab: CMDB Person Lookup (cases)",
            "description": "Look up employee profile, asset ownership, and contact info from the enterprise CMDB when investigating a case",
            "entity_types": ["case"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "cmdb_list_people",
            "entity_key_template": "Security",
            "tool_arg_name": "department",
            "static_args": {"limit": 20},
            "field_mappings": [
                {"result_path": "total", "display_label": "People Found", "overlay_key": "cmdb_people_count", "value_type": "number"},
            ],
            "overlay_section": "identity",
            "icon": "Users",
            "priority": 60,
            "cache_ttl_seconds": 3600,
        },
        {
            "name": "PurpleLab: Product Registry (cases)",
            "description": "Fetch product ownership, data classification, tech stack, and SLA from the enterprise product registry for case context enrichment",
            "entity_types": ["case"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "product_registry_list_products",
            "entity_key_template": "tier1_critical",
            "tool_arg_name": "tier",
            "static_args": {"limit": 20},
            "field_mappings": [
                {"result_path": "total", "display_label": "Critical Products", "overlay_key": "critical_products", "value_type": "number"},
            ],
            "overlay_section": "custom",
            "icon": "Package",
            "priority": 70,
            "cache_ttl_seconds": 3600,
        },
        {
            "name": "PurpleLab: VM Critical Vulns (cases)",
            "description": "Show critical and high CVEs with CISA KEV status affecting enterprise assets and products — for case risk context and patch prioritization",
            "entity_types": ["case"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "vm_get_summary",
            "entity_key_template": "",
            "tool_arg_name": "",
            "static_args": {},
            "field_mappings": [
                {"result_path": "total_open", "display_label": "Open Vulns", "overlay_key": "vm_open_count", "value_type": "number"},
                {"result_path": "cisa_kev_open", "display_label": "CISA KEV Open", "overlay_key": "vm_kev_count", "value_type": "number"},
                {"result_path": "overdue_count", "display_label": "Overdue Findings", "overlay_key": "vm_overdue_count", "value_type": "number"},
            ],
            "overlay_section": "custom",
            "icon": "AlertTriangle",
            "priority": 80,
            "cache_ttl_seconds": 1800,
        },
        {
            "name": "PurpleLab: Cloud Security Posture (cases)",
            "description": "Surface critical cloud misconfigurations (open SSH/RDP, public S3 buckets, disabled MFA) from the CSPM system for case context during cloud-related incidents",
            "entity_types": ["case"],
            "trigger_mode": "manual",
            "server_id": server_id,
            "tool_name": "cspm_get_summary",
            "entity_key_template": "",
            "tool_arg_name": "",
            "static_args": {},
            "field_mappings": [
                {"result_path": "total_open", "display_label": "Open Findings", "overlay_key": "cspm_open_count", "value_type": "number"},
                {"result_path": "by_severity.critical", "display_label": "Critical Misconfigs", "overlay_key": "cspm_critical_count", "value_type": "number"},
            ],
            "overlay_section": "network",
            "icon": "Cloud",
            "priority": 90,
            "cache_ttl_seconds": 1800,
        },
    ]

    print("Creating enrichment policies...")
    for p in policies:
        try:
            result = joti_post("/mcp-hub/policies", p, token)
            print(f"  + Created: {p['name']} (id: {result.get('id')})")
        except urllib.error.HTTPError as e:
            body = str(e)
            if "already exists" in body.lower() or e.code == 409:
                print(f"  ~ Already exists: {p['name']}")
            else:
                print(f"  ! Failed: {p['name']}: HTTP {e.code} — {body[:120]}")

    print()
    print("Done! PurpleLab MCP server registered in Joti.")
    print()
    print("Next steps:")
    print("  1. Joti admin > Attack Surface > MCP Servers > click 'Test' on PurpleLab")
    print("  2. Joti admin > MCP Hub > Policies -- nine policies should be visible")
    print("  3. Open any Case > scroll to MCP enrichment panel > run 'IOC Hunt'")
    print("  4. Joti SOC Agent can now call PurpleLab tools during IR investigations")
    print()
    print(f"  MCP server id : {server_id}")
    print(f"  MCP URL       : {PURPLELAB_MCP_URL}")
    print(f"  Discovery     : GET http://localhost:8002/api/v2/mcp")


if __name__ == "__main__":
    main()
