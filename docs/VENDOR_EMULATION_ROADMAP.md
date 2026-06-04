# PurpleLab + Joti — Vendor Emulation & SOAR Integration Roadmap

**Version:** 1.0 | **Date:** June 2026  
**Vision:** Make PurpleLab the only simulation platform that lets you choose which enterprise security product stack it behaves as, then drive your SOAR platform against it as if it were production.

---

## 1. The Problem No Competitor Solves

Every SOC team faces the same gap: **you cannot test your SOAR playbooks, Sigma detections, and response procedures against your actual production stack without risking it.**

| Pain Point | Today's Workaround | Cost |
|------------|-------------------|------|
| Test CrowdStrike isolation playbook | Break-glass lab environment | $$$, 2-day setup |
| Validate Sigma rule fires before deploying to Splunk | Deploy to dev Splunk, hope it works | 3-day cycle |
| Tabletop exercise with realistic system responses | Tabletop whiteboard + role-play | No real telemetry |
| Train new analyst on SOAR without prod access | Skip training | Analyst makes mistakes in prod |
| Migrate SIEM from Splunk → Sentinel | Re-test 400 rules manually | 6-month project |

---

## 2. Competitive Landscape

### BAS Platforms (Breach & Attack Simulation)

| Product | What It Does | Critical Gaps |
|---------|-------------|--------------|
| **AttackIQ** | Runs attack scenarios via agents on live endpoints; checks if security controls blocked them | ① Requires live agent on every endpoint ② No synthetic logs ③ No SOAR integration ④ No vendor API emulation ⑤ No integrated TIP |
| **SafeBreach** | Similar to AttackIQ; "Breach and Attack Simulation" with pre-built attack playbooks | Same as AttackIQ. No simulation without real endpoints. |
| **Cymulate** | BAS + security posture assessment; has some detection testing | ① Still agent-based ② No SOAR playbook testing ③ No vendor-emulated API endpoints ④ No TIP integration |
| **Picus Security** | Detection & response validation; focuses on ATT&CK coverage gaps | Agent-based; no synthetic environment; no SOAR testing |
| **MITRE CALDERA** | Open-source adversary emulation | Requires live agents; no detection deployment; no SOAR |

**Critical gap across ALL BAS platforms:** None can test your SOAR playbooks. None emulate a vendor API so your automation stack can execute against a simulated environment.

### SOAR Platforms

| Product | What It Does | Critical Gaps |
|---------|-------------|--------------|
| **Palo Alto XSOAR** | SOAR + playbook automation; 700+ integrations | No simulation environment; can't test playbooks safely |
| **Palo Alto XSIAM** | SIEM + XDR + SOAR in one; Cortex platform | Locked to Palo Alto ecosystem; no external simulation |
| **Splunk SOAR** | Playbook automation + Splunk SIEM native | No simulation; testing requires live Splunk environment |
| **IBM QRadar SOAR** | SOAR within IBM security ecosystem | No simulation; IBM-only ecosystem |
| **Swimlane** | SOAR + security data lake | No simulation; requires real integrations |
| **Torq** | No-code SOAR | No simulation environment |

**Critical gap across ALL SOAR platforms:** Zero can run playbooks against a simulated environment. You test in production or not at all.

### What Joti + PurpleLab Does That Nobody Else Does

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                   │
│  Joti (TIP + SOAR + Hunt)   ←──MCP──→   PurpleLab               │
│                                                                   │
│  1. Intel article arrives                                         │
│  2. Extract TTPs: T1059, T1078, T1003                            │
│  3. Generate Sigma rule                                           │
│  4. → Deploy to PurpleLab "Splunk" SIEM                          │
│  5. → Run attack scenario in PurpleLab "CrowdStrike" environment │
│  6. ← Detections fired? FP rate? Coverage %?                     │
│  7. SOAR playbook executes isolation in PurpleLab                │
│  8. ← Endpoint isolated; audit trail generated                   │
│  9. If validated → deploy Sigma to production Splunk             │
│                                                                   │
│  NO OTHER PLATFORM DOES STEPS 3-8 IN ONE INTEGRATED FLOW.       │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Market position:** "The cyber range built into your TIP/SOAR. Choose your stack. Simulate your attacks. Validate your defenses. Deploy with confidence."

---

## 3. Product Vision: Vendor Persona System

An operator picks their security stack once and PurpleLab becomes that stack:

```
Environment Config:
  EDR:      crowdstrike_falcon  | carbon_black | defender_mde | sentinelone | elastic_edr
  SIEM:     splunk_es           | qradar        | xsiam         | sentinel    | elastic_siem
  IdP:      okta                | entra_id      | pingidentity  | cyberark
  Firewall: palo_alto_ngfw      | fortinet      | cisco_ftd     | checkpoint
  Network:  darktrace           | vectra_ai     | zeek          | corelight
```

**What changes per persona:**
1. **Log schema** — events look exactly like that vendor's real logs
2. **API endpoints** — emulated vendor REST API (so Joti's connectors point here)
3. **Response actions** — vendor-specific isolation/block/reset commands
4. **Alert format** — detection alerts in that vendor's native structure

---

## 4. Technical Architecture

```
PurpleLab Backend
│
├── /api/vendor/crowdstrike/     ← CrowdStrike Falcon API emulation
│   ├── GET  /devices/v1         ← list endpoints
│   ├── POST /devices/actions/v2 ← isolate (action=contain)
│   ├── POST /iocs/entities/v1   ← block IOC
│   └── GET  /detects/v1         ← list detections
│
├── /api/vendor/splunk/          ← Splunk REST API emulation
│   ├── POST /services/search/jobs       ← create SPL search
│   ├── GET  /services/search/jobs/{sid} ← get results
│   └── POST /services/saved/searches    ← deploy saved search
│
├── /api/vendor/defender/        ← Microsoft Defender for Endpoint API
│   ├── GET  /api/machines        ← list endpoints
│   ├── POST /api/machines/{id}/isolate  ← isolate
│   └── POST /api/indicators      ← block IOC
│
├── /api/vendor/qradar/          ← IBM QRadar REST API
│   ├── GET  /api/siem/offenses
│   ├── POST /api/ariel/searches
│   └── POST /api/reference_data/sets/{name}
│
├── /api/vendor/xsiam/           ← Palo Alto XSIAM/XSOAR
│   └── /xsoar/v2/...
│
├── /api/vendor/carbonblack/     ← Carbon Black Response/EDR
│   └── /api/v3/...
│
├── /api/v2/siem/                ← Vendor-agnostic simulation SIEM
│   ├── POST /search              ← SPL/KQL/AQL/ArcSight search
│   ├── POST /deploy-detection    ← Push Sigma rule, run attack, validate
│   └── GET  /deployed-detections ← list rules in this session
│
├── /api/v2/response-actions/    ← SOAR action execution engine
│   ├── POST /block-ioc
│   ├── POST /isolate-host
│   ├── POST /release-host
│   ├── POST /disable-account
│   ├── POST /reset-password
│   ├── POST /kill-process
│   └── POST /quarantine-file
│
└── /api/v2/tabletop/            ← Tabletop exercise engine
    ├── POST /exercises
    ├── POST /exercises/{id}/start
    ├── GET  /exercises/{id}/status
    ├── POST /exercises/{id}/inject
    ├── POST /exercises/{id}/respond
    └── GET  /exercises/{id}/report
```

### Joti ← → PurpleLab Integration Flow

```
Joti SOC Agent (Claude)
    │
    │  MCP tools
    ▼
PurpleLab MCP Server
    │
    ├── soar_execute_action(session_id, action, params)
    │       → block_ioc / isolate_host / disable_account / kill_process
    │       → fires state machine transition
    │       → generates confirmation events
    │       → returns action receipt
    │
    ├── siem_search(session_id, query, query_language)
    │       → runs SPL/KQL/AQL against stored events
    │       → returns matching events in vendor format
    │
    ├── siem_deploy_detection(session_id, sigma_yaml, run_scenario)
    │       → stores Sigma rule
    │       → optionally triggers attack scenario
    │       → returns {fired, matched_events, fp_count}
    │
    ├── tabletop_create(scenario_name, team_size, environment_id)
    ├── tabletop_inject(exercise_id, injectable_id)
    ├── tabletop_respond(exercise_id, decision, rationale)
    └── tabletop_report(exercise_id)
```

---

## 5. Build Phases

### Phase A — Vendor Product Persona Engine
**What:** Registry of vendor personas; environment gets a product stack configuration.
**Files:** `engine/product_personas.py`, migration `008_product_personas.py`
**Deliverable:** `/api/v2/personas/` CRUD; environment has `edr_persona`, `siem_persona`, etc.

### Phase B — Vendor API Emulation Layer
**What:** Each vendor gets a FastAPI router that mimics its real REST API.  
**Files:** `api/vendor/{crowdstrike,splunk,defender,qradar,xsiam,carbonblack}.py`
**Deliverable:** Joti's CrowdStrike connector can point to `http://purplelab-backend:8000/api/vendor/crowdstrike`

### Phase C — SOAR Action Execution Engine
**What:** When Joti fires a playbook step against PurpleLab, the simulated environment responds.  
**Files:** `engine/action_executor.py`, `api/v2/response_actions.py`, migration `009_response_actions.py`
**Deliverable:** Isolate host → ISOLATED state; block IOC → firewall BLOCKED; logs generated.

### Phase D — SIEM Detection Testing Ground
**What:** Deploy a Sigma rule into the simulated SIEM, run an attack, see if it fires.  
**Files:** `engine/siem_engine.py`, `api/v2/siem.py`, migration `010_deployed_detections.py`
**Deliverable:** Joti can push a Sigma rule, run a `T1059.001` scenario, verify detection fired.

### Phase E — Tabletop Exercise Engine
**What:** Scripted exercise with inject events, human decision gates, timer, scoring.  
**Files:** `engine/tabletop.py`, `api/v2/tabletop.py`, migration `011_tabletop.py`
**Deliverable:** Run a ransomware tabletop; team decisions are recorded; score + AAR generated.

### Phase F — MCP Tools (5 new tools)
**What:** Extend MCP server with SOAR action, SIEM search, detection deploy, tabletop tools.  
**Files:** `mcp/server.py` (additions)
**Deliverable:** Joti's SOC Agent can isolate a host with one tool call.

### Phase G — Joti Connector Templates
**What:** Pre-configured connectors in Joti that point to PurpleLab personas.  
**Files:** Joti `connectors/routes.py` (seed data), `connectors/purplelab_vendor.py`
**Deliverable:** "Add PurpleLab CrowdStrike" button auto-populates the connector.

### Phase H — Joti Frontend Integration
**What:** Purple Team "Live Environment" tab; action panel; detection validation results.  
**Files:** Joti `views/PurpleTeam.tsx` (new tab), `views/admin/MCPHub.tsx` (vendor select)
**Deliverable:** Analyst can select product stack, run scenario, see detections fire, execute SOAR.

---

## 6. Unique Patent Opportunities

| Innovation | Description | Prior Art |
|-----------|-------------|-----------|
| **PLB-P1** | Vendor API emulation layer — simulated endpoint that responds identically to a real vendor API including proper auth, response schemas, and stateful behavior (isolation state persists across calls) | None found |
| **PLB-P2** | Closed-loop detection validation — the same system that generates the attack also hosts the SIEM, deploys the rule, and reports whether it fired | None found |
| **PLB-P3** | SOAR playbook dry-run against virtual environment — run a production playbook against simulated APIs that reflect real product behavior | None found |
| **PLB-P4** | Product persona hot-swap — change a running simulation's "identity" from CrowdStrike to Defender at runtime, preserving existing state | None found |

---

## 7. Market Differentiators Summary

| Capability | AttackIQ | Cymulate | XSIAM | Splunk ES + SOAR | **Joti + PurpleLab** |
|-----------|----------|----------|-------|-----------------|----------------------|
| Agent-free simulation | ❌ | ❌ | ❌ | ❌ | **✅** |
| Choose vendor persona | ❌ | ❌ | ❌ | ❌ | **✅** |
| SOAR playbook dry-run | ❌ | ❌ | ❌ | ❌ | **✅** |
| Sigma deploy + validate | ❌ | Partial | ❌ | Partial | **✅ (automated)** |
| Integrated TIP | ❌ | ❌ | Partial | Partial | **✅** |
| Log fetch in vendor format | ❌ | ❌ | ✅ | ✅ | **✅ (emulated)** |
| Tabletop with real telemetry | ❌ | ❌ | ❌ | ❌ | **✅** |
| SOC Agent (LLM) drives simulation | ❌ | ❌ | ❌ | ❌ | **✅** |
| MITRE coverage closed loop | Partial | Partial | ❌ | ❌ | **✅** |
| No prod environment needed | ❌ | ❌ | ❌ | ❌ | **✅** |

**Bottom line:** Joti + PurpleLab is the only platform where a single SOC analyst can:
1. Read a threat intelligence article
2. Extract the attack TTPs
3. Simulate the attack in a virtual environment that behaves like their real stack
4. Validate their Sigma detections fire
5. Run their SOAR playbook against the simulation
6. Deploy to production with confidence

This is the "DevOps for the SOC" workflow — shift left, test everything, deploy once.
