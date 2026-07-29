# PurpleLab — Claude Code Autonomous Operation Guide

**Version:** 1.0 (July 2026) | **Stack:** FastAPI · PostgreSQL 16 · Redis 7 · Next.js 15 · Celery · Docker

This file is the primary reference for autonomous Claude Code operation on PurpleLab. Read this before making any changes.

---

## 0. AUTONOMY OPERATING MODE (ALWAYS ACTIVE)

**Default behavior: FULLY AUTONOMOUS.** Execute all coding, deployment, testing, and configuration tasks without asking for confirmation, EXCEPT for the actions listed as "Always Ask" below.

### Always Ask (require explicit confirmation before proceeding)
- **File/directory deletion** (`rm`, `rmdir`, `git clean`) — irreversible
- **Git force push** (`git push --force`) — overwrites remote history
- **Git hard reset** (`git reset --hard`) — discards uncommitted work
- **Database destructive ops** (`DROP TABLE`, `TRUNCATE`, `DELETE FROM` without WHERE) — data loss
- **Docker removal of stateful services** (`docker rm -f *db*`, `docker rm -f *redis*`) — data loss

### Never Ask (execute immediately)
- Reading any file or directory
- Writing/editing code files, config, docs
- Running tests, linting, type checking
- Building Docker images
- Restarting containers
- Running Alembic migrations
- Git add, commit, push (normal push)
- Flushing Redis cache (FLUSHALL on PurpleLab Redis only — port 6380)
- Creating new files, views, routes, migrations
- Updating Miro board diagrams

### Agentic behavior rules
- Do not ask "Should I proceed?" — just proceed.
- Do not ask "Do you want me to also...?" — read context, decide, do it.
- Multi-step tasks: complete all steps without interruption unless an "Always Ask" action is hit.

---

## 1. PLATFORM OVERVIEW

**What PurpleLab is:** A standalone cybersecurity simulation and detection engineering platform. Teams use it to run realistic attack simulations against emulated SIEM/EDR environments, measure detection coverage, and validate threat intelligence from Joti.

**What it is NOT:** A production SIEM, a real EDR, or a threat intelligence platform. It is a purple team lab — all attack data is simulated.

### Services and Ports
| Service | Container | Host Port | Internal Port | Purpose |
|---------|-----------|-----------|---------------|---------|
| Frontend | purplelab-frontend | 3002 | 3000 | Next.js 15 UI |
| Backend | purplelab-backend | 8002 | 8000 | FastAPI + Celery app |
| Worker | purplelab-worker | — | — | Celery task worker |
| Beat | purplelab-beat | — | — | Celery scheduler |
| PostgreSQL | purplelab-db | 5433 | 5432 | Primary database |
| Redis | purplelab-redis | 6380 | 6379 | Cache + Celery broker |

**Admin credentials:** `admin@purplelab.local` / see `.env` `FIRST_SUPERADMIN_EMAIL`

### Joti Integration
- Joti pushes audit events to PurpleLab every 60 seconds via `SIEMAuditForwarder`
- Endpoint: `POST /api/v2/joti/audit-events` with `X-Joti-Token` header
- `HUNT_TRIGGER` and `EXTRACTION` events auto-create `UseCaseRun` records
- PurpleLab backend reaches Joti at `http://host.docker.internal:8000` (configured in `.env`)

---

## 2. ARCHITECTURE DECISIONS (never reverse without discussion)

### Backend
- **Async SQLAlchemy 2.0** — all DB calls use `async with async_session() as db`. Do NOT use sync `Session`. PurpleLab is async-first throughout.
- **Alembic dual-head** — migration chain has two active heads: `013_sec_intel` (main) and `003ret` (retired orphan). Always run `alembic upgrade 013_sec_intel` not `alembic upgrade head`.
- **Celery workers share the backend image** — `purplelab-worker` and `purplelab-beat` use the same `purplelab-backend` image. Rebuilding backend rebuilds all three.
- **EDR State Machine is a singleton registry** — `get_machine(session_id)` returns a cached `EndpointStateMachine`. Call `drop_machine(session_id)` when a session is deleted.
- **Vendor APIs are pure emulations** — `backend/api/vendor/` contains 16 vendor emulations (Splunk, XSIAM, CrowdStrike, Defender, QRadar, Carbon Black, Okta, Entra ID, Elastic, SentinelOne, Panorama, ServiceNow, Jira, Tenable, Wiz, Qualys). They read from `GeneratedEvent` rows for the given `session_id`. Never add real API credentials here.
- **Splunk HEC emulation** — `POST /api/vendor/splunk/services/collector/event` stores events in `_HEC_EVENTS` in-memory dict; auto-creates notable events from high/critical severity with technique_ids. `GET /services/collector/health[/1.0]` returns `{"text": "HEC is healthy", "code": 17}`.
- **ThreatForge proxy** — `backend/api/v2/threatforge.py` proxies to ThreatForge API at `THREATFORGE_URL` (default: `http://host.docker.internal:4000`). No auth required (ThreatForge dev mode). Exposes: `GET /api/v2/threatforge/{health,models,models/{id}}`.
- **Infrastructure canvas** — environment canvas at `/environments/{id}` supports 5 infra node categories. Canvas nodes flow into session creation via `canvas_infrastructure` field → `_derive_log_sources_from_infra()` → stored in `merged_config.infra_log_sources`. Deploy button creates CMDB asset records via `POST /api/v2/environments/{id}/deploy`.
- **XSIAM dual-field compat** — `/xql/get_query_results` accepts both `query_id` (Joti adapter) and `execution_id` (XSIAM native). `/indicators/insert_jsons` accepts both `json_indicators` and `json_objects`. Maintain both.
- **LLM log generation** — defaults to Ollama (`llama3.2`) at `http://host.docker.internal:11434`. Configured via `.env` `PURPLELAB_LLM_LOG_GENERATION_*`. Falls back gracefully if Ollama is unavailable.

### Frontend
- **Next.js 15 App Router** — pages in `frontend-next/app/`, shared components in `frontend-next/components/`
- **API base URL** — `NEXT_PUBLIC_API_URL=http://localhost:8002` for local dev. Inside Docker the frontend calls backend at `http://backend:8000`.
- **Never use `next dev`** in the production container — the prod image runs `node server.js`.

### Database
- **Alembic migrations** — in `alembic/versions/`. Main chain: `001 → 002 → 003 → ... → 013_sec_intel`.
- **Orphaned revision `003ret`** — exists only as a historical record. Never revise from it.
- **PostgreSQL 16** — port 5433 on host, 5432 inside Docker network.

---

## 3. FEATURE MAP

### Core Simulation Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `api/sessions.py` | `/api/v2/sessions` | `/sessions` | SimulationSession CRUD + start/stop/pause |
| `engine/edr_state_machine.py` | (internal) | — | 6-state EDR lifecycle (ONLINE→ISOLATED) |
| `engine/action_executor.py` | (via sessions) | — | 11 SOAR actions (isolate_host, block_ioc, etc.) |
| `engine/attack_chains/` | `/api/v2/attack-chains` | `/attack-chains` | Multi-step TTP execution chains |

### Detection Engineering Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `detection/sigma_library.py` | `/api/v2/sigma` | `/sigma-library` | Import, tag, deploy Sigma rules to sessions |
| `detection/evaluator.py` | (internal) | — | Sigma/SPL/KQL/ESQL match engine + pass_rate |
| `use_cases/routes.py` | `/api/v2/use-cases` | `/use-cases` | Detection use cases + UseCaseRun lifecycle |
| `scoring/des_scorer.py` | (internal) | — | Detection Effectiveness Score calculation |
| `siem_integration/normalization.py` | `/api/v2/normalization` | `/admin/normalization` | CIM/ASIM/ECS field mapping schemas |

### Vendor Simulation Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `api/vendor/splunk.py` | `/api/vendor/splunk` | — | Splunk HEC + search + saved-searches (full HEC impl) |
| `api/vendor/xsiam.py` | `/api/vendor/xsiam` | — | XSIAM XQL async + incidents + isolation |
| `api/vendor/crowdstrike.py` | `/api/vendor/crowdstrike` | — | CrowdStrike OAuth2 + devices + detections |
| `api/vendor/defender.py` | `/api/vendor/defender` | — | Defender tenant-auth + machines + alerts |
| `api/vendor/qradar.py` | `/api/vendor/qradar` | — | QRadar offenses + reference sets + searches |
| `api/vendor/carbonblack.py` | `/api/vendor/carbonblack` | — | Carbon Black alerts + devices + banning |
| `api/vendor/okta.py` | `/api/vendor/okta` | — | Okta users/groups/factors/events |
| `api/vendor/entra.py` | `/api/vendor/entra` | — | Entra ID (Azure AD) users/signin/conditional-access |
| `api/vendor/elastic.py` | `/api/vendor/elastic` | — | Elastic EQL/KQL search + index management |
| `api/vendor/sentinelone.py` | `/api/vendor/sentinelone` | — | SentinelOne agents + threats + isolate |
| `api/vendor/panorama.py` | `/api/vendor/panorama` | — | Palo Alto Panorama firewall + URL filtering |
| `api/vendor/servicenow.py` | `/api/vendor/servicenow` | — | ServiceNow tickets + CMDB + change requests |
| `api/vendor/jira.py` | `/api/vendor/jira` | — | Jira issues + transitions + comments |
| `api/vendor/tenable.py` | `/api/vendor/tenable` | — | Tenable scans + vulnerabilities + assets |
| `api/vendor/wiz.py` | `/api/vendor/wiz` | — | Wiz cloud issues + configurations |
| `api/vendor/qualys.py` | `/api/vendor/qualys` | — | Qualys VM scans + vulnerabilities |

### Pipeline Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `pipeline/routes.py` | `/api/v2/pipelines` | `/pipelines` | PipelineConfig CRUD + scheduled runs |
| `pipeline/executor.py` | (Celery task) | — | Sequential chain execution + DES delta |

### HITL and Approvals Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `hitl/routes.py` | `/api/v2/hitl` | `/approvals` | L0–L3 approval requests + magic links |

### ITDR Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `api/v2/itdr.py` | `/api/v2/itdr` | `/use-cases?identity=1` | 10 static identity attack simulations |

### Intelligence Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `joti/webhook.py` | `/api/v2/joti` | — | Inbound Joti audit events + auto UseCaseRun |
| `threat_intel/routes.py` | `/api/v2/threat-intel` | `/threat-intel` | IOC/TTP intel management |
| `knowledge/routes.py` | `/api/v2/knowledge` | `/knowledge` | RAG knowledge base |

### Infrastructure Domain
| Backend Module | API Prefix | Frontend Page | Purpose |
|---------------|------------|---------------|---------|
| `environments/routes.py` | `/api/v2/environments` | `/environments` | SimulatedEndpoint + SimulatedUser registry + canvas topology |
| `environments.py` (deploy) | `/api/v2/environments/{id}/deploy` | (canvas "Deploy" button) | Map infra canvas nodes to CMDB asset records |
| `scenarios/routes.py` | `/api/v2/scenarios` | `/scenarios` | Tabletop exercises + phases + injects |
| `integrations/cspm.py` | `/api/v2/cspm` | `/cspm` | CSPMCheck + CSPMFinding (optional) |
| `integrations/vuln_mgmt.py` | `/api/v2/vm` | `/vulnerabilities` | VMVulnerability + CVE/EPSS scoring |
| `api/v2/threatforge.py` | `/api/v2/threatforge` | (session dialog "From ThreatForge" tab) | Proxy to ThreatForge threat models → ATT&CK techniques |

---

## 4. TASK-BY-TASK CLAUDE INSTRUCTIONS

### Task: Add a Backend Route

1. Create or edit the appropriate `backend/api/` module.
2. Register the router in `backend/main.py` with `app.include_router(...)`.
3. Add the Alembic migration if new DB columns are needed (see migration section).
4. Rebuild and restart backend:
   ```bash
   cd c:/Projects/purplelab
   docker compose build backend
   docker compose up -d --no-build backend celery_worker celery_beat
   ```
5. Check logs: `docker logs purplelab-backend --tail 50`
6. Security check: every route must verify the user is authenticated via the `get_current_user` dependency. Multi-tenant routes must filter by `org_id` if the model has one.

### Task: Add a Frontend Page

1. Create the page in `frontend-next/app/(protected)/<path>/page.tsx`.
2. Create the view component in `frontend-next/app/` or `frontend-next/components/`.
3. Add API fetch functions targeting `NEXT_PUBLIC_API_URL`.
4. Rebuild frontend image and restart:
   ```bash
   cd c:/Projects/purplelab
   docker compose build frontend
   docker compose up -d --no-build frontend
   ```
5. Open `http://localhost:3002` to verify.

### Task: Add a Database Migration

1. Create `alembic/versions/<NNN>_<description>.py`. Increment the numeric prefix.
2. Set `down_revision = '013_sec_intel'` (or the latest head in the main chain).
3. Template:
   ```python
   """Description
   Revision ID: 014_description
   Revises: 013_sec_intel
   """
   from alembic import op
   import sqlalchemy as sa

   revision = '014_description'
   down_revision = '013_sec_intel'
   branch_labels = None
   depends_on = None

   def upgrade():
       pass  # your DDL here

   def downgrade():
       pass
   ```
4. Run: `docker exec purplelab-backend alembic upgrade 014_description`
5. Verify: `docker exec purplelab-backend alembic current`

### Task: Sync Code to GitHub

```bash
cd c:/Projects/purplelab
git add <specific files>   # never git add -A blindly
git commit -m "feat: description of change"
git push origin main
```

### Task: Rebuild Both Docker Images After Code Changes

```bash
cd c:/Projects/purplelab
docker compose build backend frontend          # both, with cache
docker compose up -d --no-build backend celery_worker celery_beat frontend
```

For a full cache-busting rebuild:
```bash
docker compose build --no-cache backend frontend
docker compose up -d --no-build backend celery_worker celery_beat frontend
```

### Task: Flush Redis Cache

```bash
docker exec purplelab-redis redis-cli FLUSHALL
```

Only flush PurpleLab Redis (port 6380). Never `FLUSHALL` Joti Redis (port 6379).

### Task: Run Database Migrations

```bash
# Always target the named head, not 'head' (dual-head issue)
docker exec purplelab-backend alembic upgrade 013_sec_intel
# Or to run a specific new migration by name:
docker exec purplelab-backend alembic upgrade <revision_id>
# Verify:
docker exec purplelab-backend alembic current
```

### Task: Check Logs

```bash
docker logs purplelab-backend --tail 50
docker logs purplelab-frontend --tail 20
docker logs purplelab-worker --tail 30
docker logs purplelab-beat --tail 20
```

### Task: Restart a Single Service

```bash
docker compose restart backend           # backend only
docker compose restart frontend          # frontend only
docker compose restart celery_worker     # worker only
```

### Task: Run the Test Suite

```bash
# From host (requires backend container running + test DB):
docker exec purplelab-backend python -m pytest backend/tests/ -v

# Run only the comprehensive suite:
docker exec purplelab-backend python -m pytest backend/tests/test_purplelab_comprehensive.py -v

# Run a specific class:
docker exec purplelab-backend python -m pytest backend/tests/test_purplelab_comprehensive.py::TestEDRStateMachine -v
```

### Task: Verify Health After Deployment

```bash
# All containers up:
docker ps --filter "name=purplelab" --format "table {{.Names}}\t{{.Status}}"

# Backend health:
curl http://localhost:8002/api/health

# Frontend responding:
curl -s -o /dev/null -w "%{http_code}" http://localhost:3002

# Migrations at head:
docker exec purplelab-backend alembic current

# Redis responding:
docker exec purplelab-redis redis-cli ping
```

### Task: Update Miro Board Diagrams

Miro board: https://miro.com/app/board/uXjVH4f6yEA=/

Diagram index: `docs/qa/PURPLELAB_MIRO_BOARD_INDEX.md`

When adding or updating a Miro diagram:
1. Use `diagram_type: "flowchart"` only — `uml_sequence` and `entity_relationship` types are unreliable via MCP.
2. Grid: rows at y=0, 8000, 16000, 24000, 32000. Columns at x=-15000, -7000, 1000, 9000.
3. After creating, record the widget ID in `docs/qa/PURPLELAB_MIRO_BOARD_INDEX.md`.
4. Commit the index update to git and push.

Palette: `palette #c6dcff #adf0c7 #fff6b6 #ffc6c6`
- Blue = infrastructure/platform entry points
- Green = core engine components
- Yellow = vendor API emulations
- Red/Pink = control plane / integrations

### Task: Update Documentation

Documentation lives in `docs/qa/`:
- `PURPLELAB_ARCHITECTURE_DIAGRAMS.md` — Mermaid diagrams
- `PURPLELAB_QA_MASTER_STRATEGY.md` — QA strategy, risk register, CI/CD gates
- `PURPLELAB_WORKFLOW_DOCUMENTATION.md` — step-by-step workflows for all features
- `PURPLELAB_TEST_CASES.md` — 105 test cases across 5 categories
- `PURPLELAB_USER_ADMIN_GUIDE.md` — end-user and admin guide
- `PURPLELAB_MIRO_BOARD_INDEX.md` — Miro diagram index with widget IDs

After updating docs, commit and push:
```bash
cd c:/Projects/purplelab
git add docs/
git commit -m "docs: update <section> documentation"
git push origin main
```

### Task: Add a Vendor API Endpoint

All vendor emulations are in `backend/api/vendor/`. Pattern:
1. Add the endpoint to the appropriate file (`splunk.py`, `xsiam.py`, `crowdstrike.py`, `defender.py`).
2. Read from `GeneratedEvent` filtered by `session_id` — never return hardcoded static data.
3. Where actions are taken (isolation, IOC block), call `execute_action(session_id, action, params)` from `engine/action_executor.py`.
4. Maintain dual-field compatibility where the real vendor SDK uses different field names than the Joti adapter.
5. No authentication is required on vendor endpoints — they are accessed internally by Joti SOAR adapter.

### Task: Add an ITDR Scenario

ITDR scenarios are static dicts in `backend/api/v2/itdr.py`. To add a new one:
1. Add an entry to the `ITDR_SCENARIOS` list with fields: `id`, `name`, `technique_id`, `description`, `attack_steps`, `detection_queries`, `expected_events`.
2. No DB migration needed — scenarios are static.
3. Rebuild backend image.
4. Test via `GET /api/v2/itdr/scenarios` and `POST /api/v2/itdr/scenarios/{id}/run`.

---

## 5. COMPLETE DEPLOYMENT WORKFLOW (run after any significant change)

```bash
cd c:/Projects/purplelab

# 1. Stage and commit changes
git add <files>
git commit -m "feat/fix/docs: description"

# 2. Push to GitHub
git push origin main

# 3. Rebuild changed images (use both if unsure which changed)
docker compose build backend
docker compose build frontend

# 4. Restart all services with new images
docker compose up -d --no-build backend celery_worker celery_beat frontend

# 5. Flush Redis (wipes session cache, rate limits, Celery results)
docker exec purplelab-redis redis-cli FLUSHALL

# 6. Run migrations (always safe — idempotent on already-applied)
docker exec purplelab-backend alembic upgrade 013_sec_intel

# 7. Verify health
docker ps --filter "name=purplelab" --format "table {{.Names}}\t{{.Status}}"
curl http://localhost:8002/api/health
curl -s -o /dev/null -w "%{http_code}" http://localhost:3002
```

---

## 6. DATABASE SCHEMA REFERENCE

### Key Models (backend/db/models.py)

| Model | Table | Key Fields |
|-------|-------|-----------|
| `SimulationSession` | `simulation_sessions` | id, org_id, name, siem_type (splunk/xsiam/crowdstrike/defender), mode (full_simulation/replay/targeted/shadow), status, started_at, stopped_at |
| `GeneratedEvent` | `generated_events` | id, session_id FK, title, severity, payload JSONB, source, created_at |
| `UseCase` | `use_cases` | id, org_id, name, technique_id, platform, detection_type, tags |
| `UseCaseRun` | `use_case_runs` | id, use_case_id FK, session_id FK, status, des_score, coverage_percentage, trigger_source (joti/manual) |
| `HITLApprovalRequest` | `hitl_approval_requests` | id, session_id FK, action_type, approval_level (L0–L3), status, magic_link_token, expires_at |
| `ContainmentAction` | `containment_actions` | id, session_id FK, action_type, target, actor, result JSONB, executed_at |
| `DeployedDetection` | `deployed_detections` | id, session_id FK, use_case_id FK, rule_content, platform, deployed_at, pass_rate |
| `SigmaLibraryRule` | `sigma_library_rules` | id, org_id, title, rule_yaml, technique_ids JSON, source, tags JSON |
| `SessionSigmaRule` | `session_sigma_rules` | id, session_id FK, sigma_rule_id FK, pass_rate, evaluated_at |
| `JotiAuditEvent` | `joti_audit_events` | id, event_type, payload JSONB, source, received_at |
| `PipelineConfig` | `pipeline_configs` | id, org_id, name, steps JSON, schedule, is_active |
| `PipelineRun` | `pipeline_runs` | id, config_id FK, session_id FK, status, des_delta, started_at, completed_at |
| `SimulatedEndpoint` | `simulated_endpoints` | id, session_id FK, hostname, ip, os_type, current_state |
| `SimulatedUser` | `simulated_users` | id, session_id FK, username, domain, role |
| `TabletopExercise` | `tabletop_exercises` | id, org_id, name, phases JSON, current_phase, status, ttr_seconds, ttc_seconds |
| `VMVulnerability` | `vm_vulnerabilities` | id, cve_id, cvss_score, epss_score, title, affected_products JSON |
| `CSPMCheck` | `cspm_checks` | id, check_id, provider (aws/azure/gcp), category, title, severity |
| `NormalizationSchema` | `normalization_schemas` | id, schema_type (CIM/ASIM/ECS), field_mappings JSONB, platform |

---

## 7. EDR STATE MACHINE REFERENCE

```
ONLINE ──anomaly_detected──► AT_RISK ──confirmed_detection──► COMPROMISED
                                                                    │
                                                          isolate_triggered
                                                                    │
                                                                    ▼
OFFLINE ◄──shutdown──── REMEDIATED ◄──remediate──── ISOLATED
```

**Technique triggers** (from `engine/edr_state_machine.py`):
- `anomaly_detected`: T1059 (script exec), T1078 (valid accounts), T1021 (remote services), T1105 (ingress transfer), T1547 (boot autostart)
- `confirmed_detection`: T1003 (credential dump), T1055 (injection), T1041 (exfil), T1486 (ransomware)
- High-fidelity sources (`edr`, `crowdstrike_edr`, `crowdstrike`) always trigger `confirmed_detection`

---

## 8. SECURITY STANDARDS

- All protected endpoints: `current_user = Depends(get_current_user)`
- Vendor API endpoints intentionally have no auth (internal-only, accessed by Joti SOAR adapter)
- JOTI_WEBHOOK_TOKEN in `.env` — always validate `X-Joti-Token` header in `joti/webhook.py`
- Fernet encryption for any stored credentials (e.g. SIEM connection passwords)
- No PII or credentials in `GeneratedEvent.payload` — simulated data only
- Redis FLUSHALL is safe on PurpleLab (all data is ephemeral simulation state); never run on Joti Redis

---

## 9. DEBUGGING PLAYBOOK

### Backend 500 / startup failure
```bash
docker logs purplelab-backend --tail 100
# Common causes:
# - Alembic migration not applied (missing column)
# - JOTI_BASE_URL unreachable (backend tries to connect at startup)
# - Async session used where sync expected (or vice versa)
```

### Migration dual-head error
```bash
# Error: "Multiple head revisions are present"
# Fix: always use the named head:
docker exec purplelab-backend alembic upgrade 013_sec_intel
```

### Worker/Beat Restarting (exit 255)
```bash
docker logs purplelab-worker --tail 50
# Common cause: CELERY_BROKER_URL unreachable or task import error
# Fix: rebuild backend image (worker uses same image) and restart
docker compose build backend
docker compose up -d --no-build celery_worker celery_beat
```

### Frontend not reflecting changes
```bash
# Rebuild frontend image (HMR is not active in prod)
docker compose build frontend
docker compose up -d --no-build frontend
# Verify new image:
docker inspect purplelab-frontend --format '{{.Image}}'
```

### XSIAM query returns empty results
- `session_id` must be passed as a query parameter (`?session_id=<uuid>`)
- Events must exist in `generated_events` for that session within the last 1 hour
- Check: `docker exec purplelab-db psql -U purplelab -c "SELECT COUNT(*) FROM generated_events WHERE session_id='<uuid>'"` (connect via port 5433)

### Joti audit events not arriving
- Check Joti `SIEMAuditForwarder` config at `/api/audit/siem-forwarders` (should be `type=purplelab`, `is_active=true`)
- Check `JOTI_WEBHOOK_TOKEN` matches between Joti and PurpleLab `.env`
- Check PurpleLab is reachable from Joti container: `http://host.docker.internal:8002`

---

## 10. QUICK CONTEXT RECOVERY (New Session)

Read in this order:
1. `CLAUDE.md` (this file) — architecture, patterns, task instructions
2. `CHANGELOG.md` — recent changes
3. `docs/qa/PURPLELAB_WORKFLOW_DOCUMENTATION.md` — detailed workflows
4. `docs/qa/PURPLELAB_MIRO_BOARD_INDEX.md` — Miro diagram index
5. `backend/db/models.py` — current data models

**Miro board:** https://miro.com/app/board/uXjVH4f6yEA=/  
**GitHub:** https://github.com/labhacker007/PurpleLab  
**Migration head:** `013_sec_intel` (next should be `014_`)

---

## 11. SKILL AUTO-SELECTION

At the start of every task, automatically invoke the most relevant skill:

| Skill | Auto-invoke when the task involves... |
|-------|---------------------------------------|
| `/as-backend-dev` | FastAPI routes, SQLAlchemy models, Alembic migrations, Python backend, 500 errors |
| `/as-frontend-dev` | Next.js pages, React components, Tailwind, UI bugs |
| `/as-developer` | Full-stack features touching both frontend and backend |
| `/as-devsecops` | Docker, CI/CD, deployment, container config, auth, token handling, SSRF |
| `/as-threat-hunter` | ITDR scenarios, Sigma rules, MITRE coverage, hunt queries, EDR simulation |
| `/as-sre` | Container health, logs, Redis, monitoring, postmortem |
| `/as-tech-writer` | Architecture docs, workflow docs, API references, Miro diagrams |
