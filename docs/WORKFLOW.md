# PurpleLab + Joti — Master Workflow & Interconnection Map

**Last updated:** 2026-06-04  
**Repo:** https://github.com/labhacker007/PurpleLab.git  
**PurpleLab port:** 8002  **Joti port:** 8000 / 3000

---

## 1. High-Level Data Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│                          JOTI PLATFORM                               │
│                                                                      │
│  [Intel Feeds]──►[IOC/TTP Extraction]──►[Threat Actors/Campaigns]   │
│       │                                         │                    │
│       ▼                                         ▼                    │
│  [Sigma/YARA Rules]◄──[Hunt Builder]◄──[MITRE Coverage Gap]         │
│       │                     │                   │                    │
│       ▼                     ▼                   ▼                    │
│  [Detection Deploy]   [Hunt Execute]    [Purple Team Tab]            │
│       │                     │                   │                    │
│       └──────────┬──────────┘                   │                    │
│                  ▼                               ▼                   │
│            [Cases/SOAR]◄──────────[Intel Validation]                │
│                  │                               │                   │
│                  ▼                               │                   │
│         [Playbook Execution]                     │                   │
│                  │                               │                   │
└──────────────────┼───────────────────────────────┼───────────────────┘
                   │  MCP tool calls               │ Vendor API calls
                   ▼                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        PURPLELAB PLATFORM                            │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │                  SIMULATION ENGINE                          │     │
│  │                                                             │     │
│  │  SimulationContext ──► TopologyGraph ──► EntityCoherence   │     │
│  │         │                                                   │     │
│  │         ▼                                                   │     │
│  │  [Log Generators]   [State Machines]   [Threat Scenarios]  │     │
│  │   WindowsEventLog    EDR (isolation)    APT Breach         │     │
│  │   Sysmon             Identity (disable) Ransomware IR      │     │
│  │   Linux Audit        Firewall (block)   Insider Threat     │     │
│  │   Firewall (NEW)     SIEM (deploy)                         │     │
│  │   DNS (NEW)                                                 │     │
│  │   CloudTrail (NEW)                                          │     │
│  └─────────────────────────────┬───────────────────────────────┘    │
│                                 │                                    │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │               VENDOR API EMULATION LAYER                   │     │
│  │                                                             │     │
│  │  CrowdStrike ✓   Splunk ✓   Defender ✓   QRadar ✓         │     │
│  │  XSIAM ✓         CarbonBlack ✓                             │     │
│  │  Okta (NEW)      Entra ID (NEW)   Elastic (NEW)            │     │
│  │  SentinelOne (NEW)  Panorama (NEW)                         │     │
│  └─────────────────────────────┬───────────────────────────────┘    │
│                                 │                                    │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │                    MCP SERVER                              │     │
│  │                                                             │     │
│  │  simulation_run_scenario    soar_execute_action             │     │
│  │  siem_search_events         siem_deploy_rule               │     │
│  │  tabletop_create/start/     env_get_topology (NEW)         │     │
│  │    respond/status           logs_search_timeline (NEW)     │     │
│  │                             detection_test_rule (NEW)      │     │
│  │                             detection_get_coverage (NEW)   │     │
│  └─────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Detailed Integration Points

### 2a. Hunt Execute → PurpleLab Event Search
```
Joti: ThreatHunt.tsx
  → POST /api/hunts/{id}/execute
  → connectors/purplelab.py _fetch_events()
    → MCP tool: siem_search_events
      → PurpleLab: GET /api/v2/sim-siem/search?session_id=&query=
        → Returns: generated_events rows matching query
  ← Hunt results → Case creation if hits found
```
**Test:** Create hunt in Joti → click Execute → verify events returned from active PurpleLab session

---

### 2b. SOAR Playbook → PurpleLab Vendor API
```
Joti: ResponsePlaybookEditor.tsx
  → POST /api/response/playbooks/{id}/execute
  → response/routes.py _run_step()
  → adapters/simulation/purplelab_vendor.py block_ioc() / isolate_machine()
    → PurpleLab: POST /api/vendor/crowdstrike/iocs/entities/iocs/v1?session_id=
      → action_executor.execute_action("block_ioc", ...)
        → firewall state machine: BLOCKED
        → response_actions table: audit record
  ← ActionResult(success=True) → execution log entry
```
**Test:** Run "Block IOC" playbook step → verify PurpleLab shows IOC blocked + audit record created

---

### 2c. Intel Validation → PurpleLab Simulation → Detection
```
Joti: PurpleTeam.tsx (Intel Validation tab)
  → POST /api/purple-team/intel-validate
  → purple_team/intel_validation.py
    1. Extract TTPs from article
    2. Check coverage: detection_use_cases for those TTPs
    3. If gap: POST /api/v2/sessions/{id}/scenarios → run attack simulation
       → PurpleLab generates attack events
    4. POST /api/v2/sim-siem/detect → check if detection fires
    5. If fires: auto-generate Sigma rule
    6. POST /api/purple-team/detection-library → store DUC
  ← Validation result with coverage status + Sigma YAML
```
**Test:** Submit article with T1078 TTP → verify PurpleLab sim runs → detection check → Sigma generated

---

### 2d. Tabletop Exercise (MCP-accessible)
```
Joti SOC Agent or direct:
  → MCP tool: tabletop_create {scenario_key: "ransomware_ir"}
    → PurpleLab: POST /api/v2/tabletop/exercises
  → MCP tool: tabletop_start {exercise_id: "..."}
    → Returns: inject (Phase 1 narrative + decision options)
  → MCP tool: tabletop_respond {exercise_id, decision_index, rationale}
    → Returns: phase score + next inject OR final AAR
```
**Test:** Create ransomware_ir exercise via MCP → go through all phases → verify AAR generated

---

### 2e. Cross-SIEM Portability (NEW — Phase 8)
```
Joti: PurpleTeam.tsx (Detection Library tab)
  → POST /api/purple-team/detection-library/{id}/check-portability
  → purple_team/portability_checker.py
    for each siem in [splunk, sentinel, qradar, elastic, defender]:
      1. _sigma_to_{siem}() translate
      2. Parse translated query (validate)
      3. Estimate compatibility score
      4. If org has SIEM connected: backtest via connector
  ← PortabilityReport {per_siem_results, field_gaps, recommendation}
```
**Test:** Run portability check on known Sigma rule → verify SPL+KQL success, QRadar warnings shown

---

### 2f. Live Environment Tab (NEW — Phase 5/Phase H)
```
Joti: PurpleTeam.tsx (Live Environment tab — NEW)
  → Stack Selector: picks purplelab_crowdstrike + purplelab_splunk persona
  → POST /api/v2/sessions (PurpleLab) → session_id
  → Scenario Launcher: POST /api/v2/sessions/{id}/scenarios (run attack)
  → Polls: GET /api/v2/sim-siem/deployed-detections?session_id=
  → SOAR Panel: POST /api/v2/sim-siem/soar/execute?session_id=
  → Deploy to Prod: POST /api/purple-team/detection-library/{id}/deploy
```
**Test:** Select CS+Splunk stack → run APT breach → watch detection fire → deploy rule to production

---

## 3. Phase Build Order & Test Gates

```
Phase        Builds On       Test Gate Before Next Phase
─────────────────────────────────────────────────────────────
QW (6 fixes) nothing         ✓ Manual verify each fix
P3 log srcs  nothing         ✓ Unit: generate 100 events, check fields
P2 MCP tools session_mgr     ✓ Call each tool via curl/httpx
P1 vendors   action_executor ✓ Token + IOC block + isolate per vendor
P7 Joti SIEM nothing (Joti)  ✓ Deploy rule → verify siem_rule_id returned
P4 reports   sessions+detections ✓ GET /reports/{id} with format=pdf
P5 Live Env  P1+P2           ✓ E2E: stack→scenario→detection→SOAR
P6 vendor UI P5 pattern      ✓ Create purplelab connector from UI
P8 portability P7            ✓ Portability report on known Sigma rule
P10 a11y     nothing         ✓ No console a11y warnings
Integration  All above       ✓ Full pipeline: article → hunt → case → SOAR
```

---

## 4. File Ownership Map

### PurpleLab — New/Modified Files Per Phase

| Phase | Files |
|-------|-------|
| P3 log sources | `backend/log_sources/sources/firewall.py` (new) |
| | `backend/log_sources/sources/dns.py` (new) |
| | `backend/log_sources/sources/cloud_trail.py` (new) |
| | `backend/log_sources/noise_generator.py` (new) |
| | `backend/engine/session_manager.py` (modify — add to dispatch) |
| | `backend/log_sources/schema_registry.py` (modify — register types) |
| P2 MCP tools | `backend/mcp/server.py` (modify — 4 new tools) |
| P1 vendors | `backend/api/vendor/okta.py` (new) |
| | `backend/api/vendor/entra_id.py` (new) |
| | `backend/api/vendor/elastic.py` (new) |
| | `backend/api/vendor/sentinelone.py` (new) |
| | `backend/api/vendor/panorama.py` (new) |
| | `backend/main.py` (modify — 5 new router includes) |
| P4 reports | `backend/api/v2/reports.py` (modify — HTML/PDF render) |

### Joti — New/Modified Files Per Phase

| Phase | Files |
|-------|-------|
| QW + P7 | `backend/app/purple_team/siem_validator.py` (modify) |
| P1-joti | `backend/app/response/adapters/__init__.py` (modify) |
| | `backend/app/response/adapters/simulation/purplelab_vendor.py` (modify) |
| P5 Live Env | `frontend-nextjs/views/PurpleTeam.tsx` (modify — new tab) |
| | `frontend-nextjs/api/client.ts` (modify — 4 new methods) |
| P6 vendor UI | `backend/app/response/routes.py` (modify) |
| | `frontend-nextjs/views/ResponseConnectors.tsx` (modify) |
| P8 portability | `backend/app/purple_team/portability_checker.py` (new) |
| | `backend/app/purple_team/routes.py` (modify) |
| | `frontend-nextjs/views/PurpleTeam.tsx` (modify — portability modal) |
| P10 a11y | 15-20 files in `frontend-nextjs/views/` (modify) |

---

## 5. Testing Checklist

### Individual Feature Tests (run after each phase)
```bash
# P3: Log sources
docker exec purplelab-backend python3 -c "
from backend.log_sources.sources.firewall import FirewallLogSource
src = FirewallLogSource(None, vendor='panos')
events = src.generate_batch(10, malicious_ratio=0.5)
print(f'Firewall: {len(events)} events, fields: {list(events[0].keys())[:5]}')
"

# P2: MCP tools
curl -X POST http://localhost:8002/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"env_get_topology","arguments":{"session_id":"SESSION_ID"}},"id":1}'

# P1: Vendor APIs
curl -X POST http://localhost:8002/api/vendor/okta/oauth2/v1/token \
  -d 'client_id=test&client_secret=test' -H 'Content-Type: application/x-www-form-urlencoded'

# P7: Joti deploy
curl -X POST http://localhost:8000/api/purple-team/detection-library/1/deploy \
  -H 'Authorization: Bearer TOKEN' -d '{"siem_type":"qradar"}'
```

### Integration Tests (run after all phases)
```bash
# Full pipeline test
docker exec purplelab-backend python3 scripts/integration_test.py

# PurpleLab → Joti hunt flow
docker exec joti-backend-1 python3 -m pytest tests/test_purplelab_integration.py -v
```

---

## 6. GitHub Push Protocol

Push after every phase completion:
```bash
cd c:/Projects/purplelab
git add -A
git commit -m "feat(phase-N): description"
git push origin main
```

For Joti changes:
```bash
cd c:/Projects/Joti
git add -A  
git commit -m "feat/fix: description"
git push origin main
```
