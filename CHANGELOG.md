# PurpleLab Changelog

---

## 2026-06-04 — Vendor Emulation Layer + SOAR Engine + Tabletop Exercises (Phases A–G)

### Phase A: Product Persona System
- `backend/engine/product_personas.py` — 14 `PersonaDefinition` dataclasses covering CrowdStrike, Splunk, Defender, QRadar, XSIAM, Carbon Black, Okta, Entra ID, Panorama, Sentinel, Elastic, Chronicle, SentinelOne, Cortex XDR
- `backend/api/v2/personas.py` — CRUD + activation endpoints; active persona stored on Environment

### Phase B: Vendor API Emulation Layer
Six FastAPI routers that mirror real vendor REST APIs:
- `backend/api/vendor/crowdstrike.py` — `/api/vendor/crowdstrike/*` (OAuth2, devices, detections, IOC, incidents)
- `backend/api/vendor/defender.py` — `/api/vendor/defender/*` (OAuth2, machines/isolate/unisolate, indicators, alerts)
- `backend/api/vendor/splunk.py` — `/api/vendor/splunk/*` (saved searches, search/jobs, HEC)
- `backend/api/vendor/qradar.py` — `/api/vendor/qradar/*` (offenses, reference sets, searches)
- `backend/api/vendor/xsiam.py` — `/api/vendor/xsiam/*` (incidents, IOC insert, endpoint isolate)
- `backend/api/vendor/carbonblack.py` — `/api/vendor/carbonblack/*` (alerts, devices, banning, device_actions)

### Phase C: SOAR Action Execution Engine
- `backend/engine/action_executor.py` — central dispatcher for 11 action types: `block_ioc`, `unblock_ioc`, `isolate_host`, `release_host`, `disable_account`, `enable_account`, `reset_password`, `kill_process`, `quarantine_file`, `deploy_detection`, `inject_alert`
- Each action updates state machines, stores a confirmation event, writes audit record to `response_actions` table
- `ActionResult` pydantic model with full execution details

### Phase D: Simulated SIEM Detection Testing Ground
- `backend/api/v2/sim_siem.py` — sim-siem router: search (KQL/SPL), deploy detection, validate detection fires, coverage heatmap, SOAR execute endpoint
- Detection deployment → stored in `deployed_detections` table; fire validation checks live events

### Phase E: Tabletop Exercise Engine
- `backend/engine/tabletop.py` — 3 built-in scenarios (`apt_breach`, `ransomware_ir`, `insider_threat`), multi-phase inject/decision flow, scoring, AAR generation
- `backend/api/v2/tabletop.py` — full lifecycle API: create, start, respond, status, report, list exercises
- `tabletop_exercises` DB table; scores stored per exercise

### Phase F: MCP Tools
New tools added to `backend/mcp_server.py`:
- `soar_execute_action` — execute block/isolate/kill/quarantine/disable against simulation
- `siem_search` — search events by KQL/SPL against active session
- `siem_deploy_detection` — deploy Sigma/SPL/KQL rule to simulated SIEM
- `tabletop_create`, `tabletop_start`, `tabletop_respond`, `tabletop_status` — full tabletop via MCP

### Phase G: Joti Connector Templates
In Joti project (`c:/Projects/Joti`):
- `backend/app/response/adapters/simulation/purplelab_vendor.py` — `PurpleLabVendorAdapter` base class + 6 concrete persona subclasses; proxies SOAR actions to PurpleLab vendor API emulation
- `backend/app/response/adapters/__init__.py` — registered all 6 purplelab_* vendors in `VENDOR_CAPABILITIES`, `VENDOR_META`, and `_build_registry()`

### DB Migration
- `alembic/versions/008_product_personas.py` — `response_actions`, `deployed_detections`, `tabletop_exercises` tables; persona columns on `environments`; stamped (tables pre-existed)

---

## Bug Fixes — 2026-06-04

### asyncpg Named-Parameter Cast Syntax
FastAPI/SQLAlchemy with asyncpg dialect translates `:name` to positional `$N`, so `::uuid` and `::jsonb` attached to named params cause `syntax error at or near ":"`. Fixed in:
- `backend/api/v2/tabletop.py` — all `::uuid`/`::jsonb` → `CAST(... AS UUID/JSONB)` + `uuid.UUID()` objects
- `backend/api/v2/sim_siem.py` — same fix throughout
- `backend/engine/action_executor.py` `_persist_action` — same fix

### Pydantic v2 `details: dict` Validation Error
`ActionResult.details: dict` caused pydantic v2 to introspect `dict.__init__` and flag `self` as a required argument whenever a non-empty dict was passed. Fix: changed to `details: Dict[str, Any]` (typing import).

### Defender OAuth2 Token — Form-Encoded Request
`/api/vendor/defender/oauth2/v2.0/token` used `Body(default={})` which expects JSON. Real SDK sends `application/x-www-form-urlencoded`, triggering FastAPI 422. Fix: removed unused body parameter (simulation always grants token regardless of credentials).
