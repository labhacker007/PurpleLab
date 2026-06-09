# PurpleLab — Full Capability Build Plan 2026
**Last updated:** 2026-06-04 | **Status:** Active execution

---

## Executive Summary

PurpleLab is being built into the industry's only **topology-aware, architecture-driven, vendor-specific security simulation platform** — with full EDR + ASM capabilities, a CMDB-backed entity model, log-schema RAG for authentic normalization, and a complete MCP + REST API surface so Joti SOAR can drive simulations, receive alerts, and trigger containment actions.

No competitor has this combination. SafeBreach/AttackIQ validate controls but don't generate synthetic multi-source logs. SimSpace has real fidelity but requires actual infrastructure at $100K+. PurpleLab delivers SimSpace-class fidelity via intelligent synthesis at API scale.

---

## What Already Exists (Solid Foundation)

| Capability | Status | Location |
|---|---|---|
| 14 vendor-specific generators | ✅ Done | `engine/generators/` |
| Product catalog (9 categories, 40+ vendors) | ✅ Done | `engine/product_catalog.py` |
| Schema library (real vendor field names) | ✅ Done | `engine/schema_library/` |
| Benign event templates (realistic noise) | ✅ Done | `engine/benign_library.py` |
| TTP library (100+ attack templates) | ✅ Done | `engine/ttp_library.py` |
| Agentic log generator (Claude-backed) | ✅ Done | `log_sources/agentic_generator.py` |
| MCP server with 35+ tools | ✅ Done | `mcp/server.py` |
| EDR simulation (detections, isolation, hunt) | ✅ Done | `api/v2/edr.py` |
| Identity simulation (lock, revoke, MFA) | ✅ Done | `api/v2/identity_sim.py` |
| Network controls (IP/domain/hash block) | ✅ Done | `api/v2/network_controls.py` |
| CMDB (people + hardware assets) | ✅ Done | `db/models.py`, `api/v2/cmdb.py` |
| Product registry + cloud accounts | ✅ Done | `api/v2/product_registry.py` |
| Vulnerability management | ✅ Done | `api/v2/vulnerability_mgmt.py` |
| CSPM findings | ✅ Done | `api/v2/cspm.py` |
| Detection parsers (Sigma/SPL/KQL/ESQL/YARA-L) | ✅ Done | `detection/parsers/` |
| ChromaDB knowledge base | ✅ Done | `knowledge/` |
| Normalization schemas (SIEM field mappings) | ✅ Done | `api/v2/normalization.py` |
| 3-agent agentic orchestrator | ✅ Done | `agent/orchestrator.py` |

---

## Full Architecture

```
╔═══════════════════════════════════════════════════════════════════════════╗
║                    PURPLELAB — TARGET ARCHITECTURE                       ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  ┌─────────────────────────────────────────────────────────────────┐    ║
║  │  LAYER 0 — ENVIRONMENT MODEL                                     │    ║
║  │                                                                   │    ║
║  │  Canvas (React Flow)           Environment DB row                │    ║
║  │  ┌──────────────────┐          ┌──────────────────────────────┐  │    ║
║  │  │ 🦅 CrowdStrike   │          │ id, name, siem_platform      │  │    ║
║  │  │ ☁️  AWS           │──────────│ settings.products: {         │  │    ║
║  │  │ 🔐 Okta          │          │   edr: "crowdstrike",        │  │    ║
║  │  │ 🔥 Palo Alto     │          │   cloud: "aws", ...}         │  │    ║
║  │  │ 🔍 Splunk SIEM   │          │ topology_graph: {nodes,edges} │  │    ║
║  │  └──────────────────┘          └──────────────────────────────┘  │    ║
║  │  "Products" button → PUT /environments/{id}/products             │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │                                        ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 1 — SIMULATION CONTEXT (shared entity model)  [Phase 1]  │    ║
║  │                                                                   │    ║
║  │  SimulationContext — created once per session, shared by ALL     │    ║
║  │  generators. Loaded from CMDB when available.                    │    ║
║  │                                                                   │    ║
║  │  attacker_ip:   "185.220.101.42"   ← SAME in all log sources    │    ║
║  │  victim_user:   "jsmith"           ← SAME in EDR+Okta+FW        │    ║
║  │  victim_host:   "WKSTN-FIN-042"   ← SAME in all sources         │    ║
║  │  c2_domain:     "updates.ms-svc.cc"← SAME in DNS+proxy+FW       │    ║
║  │  malware_hash:  "4a5f3c..."        ← SAME in EDR+network        │    ║
║  │  dc_hostname:   "SRV-DC-01"        ← lateral movement target    │    ║
║  │  aws_account_id: "123456789012"    ← cloud events               │    ║
║  │  phase_timings: {t0..t5}           ← coherent chronology        │    ║
║  │                                                                   │    ║
║  │  ContextBuilder.from_cmdb()  → loads real CMDB names/IPs        │    ║
║  │  ContextBuilder.synthetic()  → realistic random fallback         │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │                                        ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 2 — TOPOLOGY GRAPH  [Phase 2]                            │    ║
║  │                                                                   │    ║
║  │  TopologyGraph.get_observers(event_class, node_id)              │    ║
║  │                                                                   │    ║
║  │  OCSF 1007 (process exec) on WKSTN-FIN-042:                    │    ║
║  │    → CrowdStrike EDR fires ✓      (agent installed there)       │    ║
║  │    → Splunk SIEM fires ✓          (receives EDR stream)         │    ║
║  │    → Palo Alto NGFW skips ✗       (perimeter only sees network) │    ║
║  │                                                                   │    ║
║  │  OCSF 4001 (network) crossing perimeter:                        │    ║
║  │    → Palo Alto fires ✓            (traffic rule match)          │    ║
║  │    → Zscaler proxy fires ✓        (URL inspection)              │    ║
║  │    → CrowdStrike fires ✓          (netconn from endpoint)       │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │ OCSF canonical events                 ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 3 — LOG SCHEMA RAG  [Phase 3]                            │    ║
║  │                                                                   │    ║
║  │  OCSF canonical → per-vendor translator                         │    ║
║  │  ChromaDB collections:                                           │    ║
║  │    vendor_schemas/     ← real field names per vendor             │    ║
║  │    normalization/      ← SIEM parsing rules per vendor           │    ║
║  │    ocsf_mappings/      ← OCSF class → vendor field map          │    ║
║  │                                                                   │    ║
║  │  Agentic generator uses RAG to find correct field names          │    ║
║  │  before generating — zero hardcoded schemas                      │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │                                        ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 4 — CMDB-DRIVEN ENTITY INJECTION  [Phase 4]              │    ║
║  │                                                                   │    ║
║  │  Real employee: "Sarah Wilson" <s.wilson@corp.com> → Finance     │    ║
║  │  Real asset: LAPTOP-SW-019, Windows 11, serial CAF234, owned    │    ║
║  │    by Sarah Wilson, patched 2026-05-15                           │    ║
║  │  Real cloud account: AWS prod 123456789012, us-east-1           │    ║
║  │                                                                   │    ║
║  │  All log sources reference these real entities → indist from     │    ║
║  │  production telemetry                                            │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │                                        ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 5 — VENDOR-SPECIFIC GENERATION                           │    ║
║  │                                                                   │    ║
║  │  14 vendor generators + schema_library (real field names):      │    ║
║  │  CrowdStrike | SentinelOne | MDE | Splunk | Sentinel | Elastic  │    ║
║  │  Okta | EntraID | Active Directory | Palo Alto | FortiGate      │    ║
║  │  AWS | Azure | GCP | Proofpoint | M365 | Zscaler | Cloudflare   │    ║
║  │                                                                   │    ║
║  │  Full EDR simulation [Phase 5]:                                  │    ║
║  │    • RTR (Real-Time Response) command execution                  │    ║
║  │    • Process tree + parent/child PID coherence                   │    ║
║  │    • Threat graph (related detections linked by entity)          │    ║
║  │    • Prevention policies (hash/domain/IP/ML blocks)              │    ║
║  │    • Sensor policy management                                    │    ║
║  │                                                                   │    ║
║  │  ASM simulation [Phase 6]:                                       │    ║
║  │    • External surface discovery (ports, certs, services)         │    ║
║  │    • Exposure scoring per asset                                  │    ║
║  │    • Change detection (new exposure vs baseline)                 │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │                                        ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 6 — 3-AGENT LLM SYNTHESIS LOOP  [Phase 7]                │    ║
║  │                                                                   │    ║
║  │  Generator Agent  → initial log batch for TTP+context           │    ║
║  │       ↓                                                          │    ║
║  │  Evaluator Agent  → checks: parent/child PIDs coherent?         │    ║
║  │                             command lines realistic?             │    ║
║  │                             timeline chronological?              │    ║
║  │                             entities match SimulationContext?    │    ║
║  │       ↓ (if score < threshold)                                   │    ║
║  │  Improver Agent   → refines based on evaluator feedback          │    ║
║  │  (max 3 iterations, then accept best)                           │    ║
║  │                                                                   │    ║
║  │  Result: logs that pass detection rules 90%+ of the time        │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │                                        ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 7 — PRODUCT BEHAVIOR STATE MACHINES  [Phase 8]           │    ║
║  │                                                                   │    ║
║  │  Redis-backed state per product instance:                        │    ║
║  │                                                                   │    ║
║  │  EDR:      normal → alerted → isolated → remediated              │    ║
║  │  Identity: active → mfa_challenged → locked → disabled          │    ║
║  │  Firewall: allow → block_rule_added → blocked                    │    ║
║  │  SIEM:     raw_event → corr_rule_fired → alert_created → case   │    ║
║  │                                                                   │    ║
║  │  State transitions → secondary log events automatically          │    ║
║  │  (isolation triggers NetworkContainmentBeginEvent etc.)          │    ║
║  └──────────────────────────────┬──────────────────────────────────┘    ║
║                                  │                                        ║
║  ┌──────────────────────────────▼──────────────────────────────────┐    ║
║  │  LAYER 8 — MCP SERVER + REST API  [Phase 9 + existing]          │    ║
║  │                                                                   ║
║  │  Existing (35+ tools): EDR, Identity, Network, CMDB, CSPM, VM   │    ║
║  │                                                                   │    ║
║  │  New simulation control tools:                                   │    ║
║  │    simulation_run_scenario   ← Joti triggers attack scenario     │    ║
║  │    simulation_inject_alert   ← push alert to Joti SOAR          │    ║
║  │    simulation_get_session    ← poll scenario status              │    ║
║  │    env_get_topology          ← query environment graph           │    ║
║  │    logs_search_timeline      ← unified cross-source timeline     │    ║
║  │    detection_test_rule       ← Sigma/SPL/KQL vs simulated logs   │    ║
║  └─────────────────────────────────────────────────────────────────┘    ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## Phase Build Plan

### Phase 1 — SimulationContext (Critical Foundation)
**Goal:** Fix the #1 realism problem — incoherent entities across log sources.

**Files to create:**
- `backend/engine/simulation_context.py` — SimulationContext dataclass + ContextBuilder
  - Loads real people/assets from CMDB DB tables when available
  - Generates realistic synthetic entities when CMDB is empty
  - Provides `to_substitution_map()` for template rendering
  - Provides `to_prompt_context()` for LLM prompt injection
  - Stores/loads from Redis keyed by session_id

**Files to modify:**
- `backend/engine/generators/base.py` — add `set_context(ctx)` + context-aware `_pick_*` methods
- `backend/log_sources/agentic_generator.py` — inject context into `_render_template()` + `_GENERATION_PROMPT`
- `backend/engine/session_manager.py` — create SimulationContext at session start, pass to all generators
- `backend/engine/ttp_library.py` — use SimulationContext instead of random asset_pool
- `backend/engine/benign_library.py` — use SimulationContext entities

**Test:** Generate CrowdStrike + Okta + Palo Alto logs for T1078 (Valid Accounts) — verify same user/IP appears in all three sources.

---

### Phase 2 — Topology Graph
**Goal:** Products observe only what they can physically see in the network.

**Files to create:**
- `backend/engine/topology.py` — TopologyGraph, TopologyNode, TopologyEdge, observer resolution
- `backend/migrations/versions/001_add_topology_to_environments.py`

**Files to modify:**
- `backend/db/models.py` — add `topology_graph` JSON column to `Environment`
- `backend/engine/session_manager.py` — filter generators by topology before dispatching
- `backend/api/v2/environments.py` — add `GET/PUT /{id}/topology` endpoints

**Test:** Create an environment with CrowdStrike (endpoint) + Palo Alto (perimeter) + Splunk (SIEM). Run T1055 (Process Injection) — verify Palo Alto does NOT fire (no network traffic for this technique); CrowdStrike and Splunk DO fire.

---

### Phase 3 — Log Schema RAG
**Goal:** LLM uses RAG to find correct vendor field names — zero hardcoded schemas.

**Files to create:**
- `backend/engine/ocsf.py` — OCSF event class definitions (1007 Process, 3002 Auth, 4001 Network, 4002 HTTP, 4003 DNS)
- `backend/engine/schema_rag.py` — vendor schema RAG: index + retrieve + translate
- `backend/knowledge/log_schema_indexer.py` — index all 50+ vendor schemas into ChromaDB at startup
- `backend/engine/vendor_translators/__init__.py` — OCSF → vendor translator registry
- `backend/engine/vendor_translators/crowdstrike.py` — OCSF → CrowdStrike FDR JSON
- `backend/engine/vendor_translators/palo_alto.py` — OCSF → PAN-OS syslog CSV
- (one file per major vendor)

**Files to modify:**
- `backend/log_sources/agentic_generator.py` — replace hardcoded schema text with RAG lookup
- `backend/main.py` — add `log_schema_indexer.index_all()` to startup

**Test:** Query `schema_rag.get_fields("edr", "crowdstrike", "process_creation")` — should return `["event_simpleName", "aid", "cid", "ComputerName", "ImageFileName", "CommandLine", "SHA256HashData"]`.

---

### Phase 4 — CMDB-Driven Entity Injection
**Goal:** Simulation entities come from real CMDB inventory data.

**Files to modify:**
- `backend/engine/simulation_context.py` — `ContextBuilder.from_cmdb()` queries `cmdb_people` + `cmdb_hardware_assets` + `product_registry_cloud_accounts`
- `backend/engine/session_manager.py` — load CMDB context when environment has CMDB data

**New CMDB capabilities:**
- `CMDBPerson.department` → simulate realistic job-role-based behavior (Finance users open Excel more; IT users run PowerShell more)
- `CMDBHardwareAsset.serial_number`, `.asset_tag`, `.os_version` → realistic asset metadata in EDR logs
- `ProductCloudAccount.account_id`, `.cloud_provider` → real cloud account IDs in CloudTrail/Activity Log events

**Test:** Import 10 CMDB employees + 20 hardware assets → run a simulation → verify employee names + laptop serials appear verbatim in generated logs.

---

### Phase 5 — Full EDR Simulation
**Goal:** Complete EDR product API surfaces — not just alerts but all EDR capabilities.

**New capabilities per vendor:**

**CrowdStrike Falcon (complete API surface):**
- RTR (Real-Time Response): `edr_rtr_get_session`, `edr_rtr_run_cmd`, `edr_rtr_get_file`, `edr_rtr_put_file`, `edr_rtr_list_processes`, `edr_rtr_kill_process`
- Threat Graph: `edr_get_threat_graph` — entities linked by shared IOCs across detections
- Prevention policies: `edr_get_prevention_policy`, `edr_update_prevention_policy`
- Sensor policy: `edr_get_sensor_policy`, `edr_list_sensor_groups`
- Process timeline: `edr_get_process_timeline` — full process tree for a detection

**SentinelOne (complete API surface):**
- Deep Visibility: `edr_s1_deep_visibility_query` — PowerQuery for process/network/file events
- Threats: `edr_s1_get_threat`, `edr_s1_resolve_threat`, `edr_s1_mitigate_threat`
- Remote shell: `edr_s1_remote_shell`
- Agent: `edr_s1_get_agent`, `edr_s1_update_agent_policy`

**MDE (Microsoft Defender for Endpoint):**
- Advanced Hunting: `edr_mde_advanced_hunting` — KQL queries against DeviceProcessEvents, DeviceNetworkEvents, etc.
- Live Response: `edr_mde_run_live_response`
- Machine actions: `edr_mde_get_machine_actions`

**Files to create:**
- `backend/api/v2/edr_extended.py` — all new EDR endpoints
- `backend/engine/edr_state_machine.py` — EDR product state machine (normal→alerted→isolated→remediated)
- `backend/mcp/tools/edr_tools_extended.py` — new MCP tools for extended EDR

---

### Phase 6 — ASM Simulation
**Goal:** Realistic Attack Surface Management data showing external exposure.

**Capabilities:**
- External scan results per asset (open ports, running services, TLS certificate details)
- Exposure scoring (CVSS-based + public exploit weighting)
- Change detection (new exposure vs. last scan baseline)
- Technology fingerprinting (what web framework, server version, etc.)
- Certificate expiry tracking

**Files to create:**
- `backend/engine/asm_simulator.py` — ASM scan result generation
- `backend/api/v2/asm.py` — ASM API endpoints
- MCP tools: `asm_get_surface`, `asm_get_exposures`, `asm_get_changes`

---

### Phase 7 — 3-Agent LLM Synthesis Loop
**Goal:** Generator → Evaluator → Improver quality cycle for high-fidelity logs.

**Architecture:**
```
generate_logs(ttp, context, n)
  → GeneratorAgent.generate(ttp, context, n)      # initial batch
  → EvaluatorAgent.evaluate(logs, context)         # quality score + feedback
  → if score < 0.8:
      ImproverAgent.improve(logs, feedback, context) # refined batch
      → EvaluatorAgent.evaluate(improved, context)
  → if score < 0.8 (max 3 iterations):
      accept best batch
```

**Evaluator checks:**
- Parent/child PID relationships are consistent
- Timestamps are chronologically ordered within attack phase
- All entity fields (user, host, IP) match SimulationContext
- Command lines are syntactically valid
- Log fields match vendor schema

**Files to modify:**
- `backend/log_sources/agentic_generator.py` — add `EvaluatorAgent` + `ImproverAgent` classes
- `backend/llm/config.py` — add `LOG_EVALUATION`, `LOG_IMPROVEMENT` LLM functions

---

### Phase 8 — Product State Machines
**Goal:** Products react to containment actions with authentic secondary log events.

**State machines (Redis-backed):**

```
EDR State:      normal → detection_fired → isolated → quarantine_active → remediated
Identity State: active → mfa_challenged → locked → session_cleared → disabled
Firewall State: allow → block_rule_pending → blocked → unblocked
SIEM State:     ingesting → correlation_fired → notable_event → case_created → closed
```

**Secondary log events on state transitions:**
- EDR isolation → `NetworkContainmentBeginEvent` (CrowdStrike) or `agent.activity.isolation` (SentinelOne)
- Identity lock → EventID 4740 (Windows), `user.account.lock` (Okta)
- Firewall block → `threat log` entry with `action=block` (Palo Alto), `block` type+subtype (FortiGate)
- SIEM alert → Notable Event (Splunk ES), Incident (Sentinel), Alert (Elastic)

**Files to create:**
- `backend/engine/product_states.py` — Redis-backed state machines per product
- `backend/engine/secondary_events.py` — log events generated by state transitions

**Files to modify:**
- `backend/mcp/server.py` — wire containment tools to state machine transitions
- `backend/api/v2/edr.py` — state machine integration

---

### Phase 9 — Simulation Control MCP Tools
**Goal:** Joti can trigger attack scenarios and receive correlated alerts.

**New MCP tools:**

| Tool | Description |
|---|---|
| `simulation_run_scenario` | Launch named attack scenario → returns session_id |
| `simulation_inject_alert` | Push specific alert type to Joti SOAR via webhook |
| `simulation_get_session` | Poll session status + phase progress |
| `simulation_list_scenarios` | Available scenario types |
| `env_get_topology` | Query environment topology graph |
| `env_list_products` | List configured vendor products |
| `logs_search_timeline` | Unified cross-source event timeline by entity |
| `logs_get_raw` | Raw vendor-format logs for a session + product |
| `detection_test_rule` | Sigma/SPL/KQL rule vs. generated logs → match result |
| `detection_get_coverage` | Which TTPs are covered by deployed rules |

**Files to modify:**
- `backend/mcp/server.py` — add all 10 new tools

---

## Documentation Structure

```
docs/
├── ARCHITECTURE.md          ← Component map + data flow diagrams
├── BUILD_PLAN_2026.md       ← This file
├── BUILD_LOG.md             ← What was built, when, what changed
├── VENDOR_SCHEMAS.md        ← All vendor field name reference
├── MCP_REFERENCE.md         ← All 45+ MCP tools documented
├── SIMULATION_GUIDE.md      ← How to run simulations end-to-end
├── CMDB_INTEGRATION.md      ← CMDB data model + import guide
├── EDR_CAPABILITIES.md      ← Full EDR simulation reference
├── ASM_SIMULATION.md        ← ASM simulation reference
└── API_REFERENCE.md         ← REST API complete reference
```

---

## Competitive Differentiation

| Capability | SafeBreach | AttackIQ | Cymulate | SimSpace | **PurpleLab** |
|---|---|---|---|---|---|
| Vendor-specific log schemas | ✗ | ✗ | ✗ | ✅ real tools | ✅ synthetic |
| Cross-source entity coherence | ✗ | ✗ | ✗ | ✅ real tools | ✅ Phase 1 |
| Topology-aware generation | ✗ | ✗ | ✗ | ✅ real net | ✅ Phase 2 |
| LLM-driven log synthesis | ✗ | ✗ | ✗ | ✗ | ✅ Phase 7 |
| CMDB-backed realism | ✗ | ✗ | ✗ | ✅ real | ✅ Phase 4 |
| Full EDR API simulation | ✗ | ✗ | ✗ | ✅ real | ✅ Phase 5 |
| ASM simulation | ✗ | ✗ | ✗ | ✅ real | ✅ Phase 6 |
| MCP-native SOAR integration | ✗ | ✗ | ✗ | ✗ | ✅ Phase 9 |
| No infrastructure needed | ✅ | ✅ | ✅ | ✗ | ✅ |
| Cost | $50K/yr | $40K/yr | $40K/yr | $100K+ | Open/SaaS |
