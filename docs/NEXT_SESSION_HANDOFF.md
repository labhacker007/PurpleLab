# PurpleLab — Next Session Handoff

**Date:** 2026-07-29
**Last commit:** `6d27417 fix(canvas): guard against string-array template topology crashing React Flow`
**Remote:** github.com/labhacker007/PurpleLab
**Branch:** main

---

## Current State

### Services (all healthy)
| Service | Container | Port | Status |
|---------|-----------|------|--------|
| Backend | purplelab-backend | 8002 | healthy |
| Frontend | purplelab-frontend | 3002 | up |
| Celery Worker | purplelab-worker | — | up |
| Celery Beat | purplelab-beat | — | up |
| PostgreSQL | purplelab-db | 5433 | healthy |
| Redis | purplelab-redis | 6380 | healthy |

**Admin credentials:** `admin@purplelab.local` / `Admin@1234`

### Alembic State
- Active heads: `013_sec_intel` (main) + `003ret` (retired orphan)
- Always run: `docker exec purplelab-backend alembic upgrade 013_sec_intel`
- Next migration should be: `014_<description>.py` with `down_revision = '013_sec_intel'`

---

## What Was Built (Jul 2026 Sessions)

### ThreatForge → PurpleLab Integration (2026-07-29)
- `backend/api/v2/threatforge.py` — proxy endpoints at `/api/v2/threatforge/{health,models,models/{id}}`
  - Forwards to ThreatForge API at `http://host.docker.internal:4000` (env: `THREATFORGE_URL`)
  - Extracts ATT&CK technique IDs from `mitre_techniques` array
  - Returns sigma_count, threat_count, risk_score per model
- `frontend-next/app/sessions/page.tsx` — `NewSessionDialog` extended with two-tab layout:
  - **Attack Chains** tab (existing): selects from loaded attack chain list
  - **From ThreatForge** tab (violet accent): fetches live ThreatForge models, select one → session created with its `technique_ids`; session config includes `source: "threatforge"`, `threatforge_model_id/name`
- Canvas fix: template topologies store `nodes` as `string[]` — guard added so React Flow doesn't crash

### Infrastructure Canvas + Deploy (2026-07 Sessions)
- `frontend-next/app/environments/[id]/page.tsx` — drag-and-drop infrastructure palette:
  - 5 categories: Endpoints (Windows/Linux/Mac/DC/Server), Cloud (AWS/Azure/GCP), Email (Exchange/GSuite/Proofpoint/Mimecast), EDR (CrowdStrike/Defender/SentinelOne/CarbonBlack/XSIAM), ITSM (ServiceNow/Jira)
  - `InfraNode` custom React Flow node type — color-coded, shows hostname/IP/users/services
  - Infrastructure nodes wire into session creation: `canvas_infrastructure` → `_derive_log_sources_from_infra()` → `infra_log_sources` in session config
  - "Deploy" button → `POST /api/v2/environments/{id}/deploy` auto-generates hostnames/IPs and asset records
- `backend/api/v2/environments.py` — `POST /{id}/deploy` endpoint: maps infra nodes to CMDB asset records

### Push to SIEM (2026-07 Sessions)
- `frontend-next/app/sessions/[id]/page.tsx` — "Push to SIEM" button: calls `POST /api/v2/sessions/{id}/push-to-siem`, shows loading + success feedback (event count + connection name)
- `backend/api/v2/sessions.py` — `push-to-siem` endpoint: collects `GeneratedEvent` records, auto-creates Splunk sim SIEM connection if none exists, calls `ConnectionManager.push_logs()`
- `backend/api/vendor/splunk.py` — full HEC implementation: `POST /services/collector/event` stores events in `_HEC_EVENTS`, auto-creates notable events from high/critical severity; `GET /services/collector/health` returns healthy status

### User Guide Page (2026-07 Sessions)
- `frontend-next/app/guide/page.tsx` — 4 tabs: Vendor APIs (all 16 vendors), Seed Data, Connecting from Joti, Workflows
- `frontend-next/components/sidebar.tsx` — "User Guide" link added before Settings

---

## Known Issues / Deferred

- **Canvas SIEM nodes** — visual only; Products modal drives actual SIEM connections; not synced yet
- **Template topology format** — fixed: string-array nodes now fall through to auto-layout builder
- **Detection rule nodes** — decorative; not wired to use-cases API yet
- **PurpleLab simulation session in-memory** — re-create via API after container restart

---

## Key Integrations

### ThreatForge (localhost:4000)
- API at `http://localhost:4000/threat-models` — no auth (THREATFORGE_API_KEY empty = disabled)
- PurpleLab proxies via `/api/v2/threatforge/*`
- ThreatForge routes use root-level paths (no `/api` prefix): `/health`, `/threat-models`, `/admin/*`, `/orgs/*`, `/agent/*`

### Joti (localhost:8000)
- Joti webhook endpoint in PurpleLab: `backend/joti/webhook.py`
- SIEM audit forwarder pushes events to Joti alert sources every 60s
- PurpleLab response connector registered in Joti at Admin → Response → Connectors

### Vendor API Emulations (all at `/api/vendor/<name>/...`)
16 vendors: CrowdStrike, Splunk, Defender, QRadar, XSIAM, CarbonBlack, Okta, Entra ID, Elastic, SentinelOne, Panorama, ServiceNow, Jira, Tenable, Wiz, Qualys

---

## Rebuild Commands

```bash
# Backend only (Python changes):
cd c:/Projects/purplelab && docker compose build backend && docker compose up -d --no-deps backend celery_worker celery_beat

# Frontend only (TypeScript/React changes):
cd c:/Projects/purplelab && docker compose build frontend && docker compose up -d --no-deps --force-recreate frontend

# Full rebuild:
cd c:/Projects/purplelab && docker compose build && docker compose up -d
```
