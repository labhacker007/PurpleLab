# PurpleLab Changelog

---

## 2026-07-29 — ThreatForge Integration + Infrastructure Canvas + Push to SIEM

### ThreatForge → PurpleLab Wiring
- `backend/api/v2/threatforge.py` — new proxy module: `GET /api/v2/threatforge/health`, `/models`, `/models/{id}`
  - Forwards to ThreatForge API (default: `http://host.docker.internal:4000`); configurable via `THREATFORGE_URL` env var
  - Extracts ATT&CK technique IDs from `mitre_techniques` array; returns sigma_count, threat_count, risk_score
- `frontend-next/app/sessions/page.tsx` — `NewSessionDialog` two-tab layout:
  - **Attack Chains** tab: existing behavior unchanged
  - **From ThreatForge** tab (violet): fetches live threat models, select one → session created with `technique_ids` from STRIDE analysis; session config records `source: "threatforge"`, `threatforge_model_id/name`
- Registered `threatforge_router` in `backend/api/v2/__init__.py`

### Infrastructure Canvas + Deploy
- `frontend-next/app/environments/[id]/page.tsx` — drag-and-drop palette with 5 infrastructure categories:
  - Endpoints (Windows/Linux/Mac/DC/Server), Cloud (AWS/Azure/GCP), Email (Exchange/GSuite/Proofpoint/Mimecast), EDR (CrowdStrike/Defender/SentinelOne/CarbonBlack/XSIAM), ITSM (ServiceNow/Jira)
  - `InfraNode` custom React Flow node: color-coded by subtype, hostname/IP/users/services fields
  - Canvas infra nodes wired into session creation: `canvas_infrastructure` → `_derive_log_sources_from_infra()` maps node type to log source IDs stored in `merged_config.infra_log_sources`
  - "Deploy" button (enabled when infra nodes present) → `POST /api/v2/environments/{id}/deploy`
- `backend/api/v2/environments.py` — `POST /{id}/deploy` endpoint: generates hostnames/IPs, maps to log sources, saves `deployed_assets` to `environment.settings`

### Push to SIEM
- `frontend-next/app/sessions/[id]/page.tsx` — "Push to SIEM" button with violet styling, loading state, 6s success feedback showing event count + connection name
- `backend/api/v2/sessions.py` — `POST /{session_id}/push-to-siem`: collects `GeneratedEvent` records, auto-creates Splunk sim connection if none exists, calls `ConnectionManager.push_logs()`; `_derive_log_sources_from_infra()` helper maps infra node subtypes to log source IDs
- `backend/api/vendor/splunk.py` — full HEC implementation: `POST /services/collector/event` (newline-delimited JSON), in-memory `_HEC_EVENTS` store, auto-creates notable events from high/critical severity events; `GET /services/collector/health[/1.0]`

### User Guide
- `frontend-next/app/guide/page.tsx` — 4-tab user guide: Vendor APIs (all 16 vendors with endpoints + auth), Seed Data, Connecting from Joti, Workflows
- `frontend-next/components/sidebar.tsx` — "User Guide" sidebar link (HelpCircle icon)

### Bug Fixes
- Canvas template topology guard: template environments store `nodes` as `string[]` — added `typeof nodes[0] === 'object'` check to fall through to auto-layout instead of crashing React Flow
- `backend/api/v2/sessions.py` — added `Body` to FastAPI imports (was causing startup `NameError`)
- Celery worker/beat containers restarted with latest backend image

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
