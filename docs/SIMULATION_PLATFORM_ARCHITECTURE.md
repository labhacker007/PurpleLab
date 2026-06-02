# PurpleLab — Simulation Platform Architecture
## Detection Engineering, Red Team, Purple Team, Live Fire & Tabletop Exercises

**Version:** 1.0 (June 2026) | **Status:** Implementation Roadmap

---

## 1. WHAT IS PURPLELAB?

PurpleLab is a **cyber simulation platform** — the environment where defensive detection is built, tested, validated, and continuously improved against real adversary techniques.

It sits between:
- **Threat Intelligence** (Joti TIP) — who is attacking, with what TTPs
- **SIEM/EDR Stack** — where logs land and alerts fire
- **SOC Operations** (Joti SOAR) — how analysts respond

PurpleLab answers: *"If that adversary used that TTP against our environment, would we detect it?"*

---

## 2. FOUR OPERATIONAL MODES

### Mode 1 — Detection Engineering
**Who:** Detection engineers, security engineers  
**Goal:** Write a detection rule, simulate the attack, verify the rule fires  
**Workflow:**
```
TTP / CVE input → Environment selection → Log normalization schema → 
Simulate attack logs → Test Sigma/YARA/KQL/SPL → Validate → Deploy
```

### Mode 2 — Red Team Exercise
**Who:** Red teamers, adversary simulation team  
**Goal:** Simulate a full campaign (kill chain) in a controlled environment  
**Workflow:**
```
Threat Actor profile → TTP chain → Environment topology → 
Execute atomics → Observe logs → Report TTPs executed vs detected
```

### Mode 3 — Purple Team Exercise  
**Who:** Red + Blue team together  
**Goal:** Run attacks and detections collaboratively, improve coverage  
**Workflow:**
```
Session created → Red runs TTPs → Blue watches in real-time →
Detection gaps identified → Rules written live → Coverage score updated
```

### Mode 4 — Live Fire Exercise & Tabletop
**Who:** SOC team, IR team, executives  
**Goal:** Test incident response procedures under realistic conditions  
**Workflow:**
```
Scenario selected → Inject alerts into SOAR → Team responds →
Timeline tracked → Lessons learned → KPIs measured (MTTD, MTTR)
```

---

## 3. CURRENT PLATFORM CAPABILITIES (Implemented)

| Capability | Status | Location |
|-----------|--------|----------|
| Environment topology builder | ✅ Live | `/environments/{id}` |
| Simulation sessions | ✅ Live | `/sessions` |
| Log source management | ✅ Live | `/log-sources` |
| Use case testing | ✅ Live | `/use-cases` |
| Pipeline automation | ✅ Live | `/pipeline` |
| AI-powered chat | ✅ Live | `/chat` |
| MITRE ATT&CK coverage | ✅ Live | `/mitre` |
| Detection scoring | ✅ Live | `/scoring` |
| Rules library (imported) | ✅ Live | `/rules` |
| CMDB / HR / VM / CSPM data | ✅ Live | Enterprise data seeded |
| Data import (CSV/JSON) | ✅ Live | `/admin/import` |
| Environment templates | ✅ Live | `/environments/templates` |
| Threat profile injection | ✅ Live | `/threat-profiles` |
| Sigma rule library (10 repos) | ✅ Live | `/sigma-library` |
| Normalization schema manager | ✅ Live | `/normalization` |

---

## 4. CAPABILITY GAPS (What Cybersecurity Operations Needs)

### 4.1 Missing: Atomic Test Executor
**Gap:** Currently logs are simulated abstractly. Need to map TTPs to specific **Atomic Red Team** tests with exact commands and expected log output.

**Why it matters:** Detection engineers need to know EXACTLY what log entry to write their rule against — not a simulation, but `EventID 4688 + CommandLine contains "mimikatz"`.

**Implementation path:**
- `AtomicTest` model: `technique_id`, `test_num`, `name`, `executor_type` (cmd/powershell/bash), `command`, `expected_log_events` (JSON array of expected log lines/fields)
- Sync from `atomic-red-team` GitHub repo on demand
- Per-test: "Show expected logs" → user can write detection rule against those exact fields
- Integration with normalization schemas — show field names as per the org's SIEM schema

### 4.2 Missing: Detection Validation Pipeline (End-to-End)
**Gap:** We simulate logs and write rules but don't close the loop — "did the rule fire?"

**Why it matters:** A detection that isn't tested against real-format logs is untested.

**Implementation path:**
```
Phase 1: Generate synthetic log events (per normalization schema field names)
Phase 2: Pass to rule tester (Sigma rule compiled to SPL/KQL/EQL)
Phase 3: Record: fired / not fired / partial match
Phase 4: Update use-case coverage score
```
- Backend: `detection_validation_runs` table  
- `POST /api/v2/use-cases/{id}/validate` — runs the simulation + rule evaluation
- Use `sigmatools` Python library for Sigma→SIEM compilation
- Store pass/fail evidence per run for audit

### 4.3 Missing: Live SIEM Feedback Loop  
**Gap:** After deploying a Sigma rule to a SIEM, there's no feedback whether it fired in production.

**Why it matters:** Rules that fire too much (noise) or too little (miss) need to be caught.

**Implementation path:**
- SIEM connector polls for rule hit counts hourly
- Shows in use-case detail: "Alert fired 47 times last 7 days" or "0 fires — dead rule"
- Threshold alerting: "Rule not fired in 30 days → mark for review"

### 4.4 Missing: Scenario Library
**Gap:** No pre-built scenarios (kill chains) that can be instantiated end-to-end.

**Why it matters:** Running a purple team exercise requires a full scenario — not just individual TTPs.

**Implementation path:**
- `Scenario` model: name, threat_actor, phases (ordered list of TTPs), expected_duration, difficulty, tags
- Pre-built scenarios: Ransomware (8-step), APT29 Initial Access, Cloud Account Takeover, Insider Threat
- Scenario runner: advances through phases, each phase generates log events, tracks coverage
- Live dashboard during exercise: phase progress, detection events, coverage gauge

### 4.5 Missing: Real-Time Exercise Dashboard
**Gap:** During a live fire exercise, there's no shared dashboard for red and blue teams.

**Why it matters:** Purple team exercises require real-time coordination — "I just ran T1059, did you see the alert?"

**Implementation path:**
- WebSocket-based live session board
- Left rail: Red team timeline (TTPs executed with timestamps)
- Right rail: Blue team detections (alerts fired, rules matched)
- Center: Coverage heatmap updating live
- Chat per session for team communication
- After session: auto-generate exercise report (timeline + gaps)

### 4.6 Missing: Tabletop Exercise Mode
**Gap:** Tabletop exercises need a different interface — no actual simulation, just scenario cards presented to participants for discussion.

**Why it matters:** Tabletops are required for compliance (SOC 2, NIS2) and don't require live systems.

**Implementation path:**
- `TabletopExercise` model: scenario_id, participants (JSON), moderator, format (inject-based/discussion)
- Inject cards: timed scenario events shown to participants ("You receive an email alert...")
- Decision tracking: what did the team decide to do at each inject?
- Timer and facilitator controls
- Post-tabletop: lessons learned capture, gap analysis vs detection coverage

### 4.7 Missing: Log Generation Fidelity
**Gap:** Generated logs use made-up field names. Real detection rules reference fields from specific SIEM CIM/ECS schemas.

**Why it matters:** A rule that matches `src_ip` won't fire if the field is `source.address`.

**Solution:** Normalization schema manager (✅ just built) feeds into the log generator.

**Remaining work:**
- Log generator reads the active normalization schema for the environment
- All generated fields use schema-defined names (e.g., if schema maps to Splunk CIM, use `src`, `dest`, `user`, `process_name`)
- Per-environment: "active schema" setting
- Template variables in atomic test expected-log definitions reference schema fields

### 4.8 Missing: Detection Content Deployment Tracking
**Gap:** We know what rules were written, but not which ones are actually deployed and active in production SIEM.

**Why it matters:** A detection gap means either "no rule exists" or "rule exists but isn't deployed."

**Implementation path:**
- `DetectionDeployment` model: sigma_rule_id, environment_id, siem_platform, status, deployed_at, deployed_by
- "Deploy to SIEM" flow: compiles Sigma → target SIEM query, shows diff, requires approval
- Dashboard: "Total rules: 340 / Deployed: 280 / Draft: 45 / Deprecated: 15"

### 4.9 Missing: Threat Intelligence Feed into Simulations
**Gap:** Threat profiles exist but don't drive scenario generation automatically.

**Why it matters:** "We just got intel that APT29 is targeting our sector — simulate their latest TTPs against our environment right now."

**Implementation path:**
- "Simulate from Intel" button on threat actor profiles (in Joti TIP)
- Sends actor TTPs to PurpleLab via webhook/API
- Auto-generates session with those TTPs as the exercise
- Maps TTPs to existing atomic tests where available

### 4.10 Missing: Container/Kubernetes Simulation
**Gap:** K8s template exists but log events don't reflect real K8s audit log structure.

**Why it matters:** Container attacks (escape, lateral movement, privilege escalation) need K8s-specific log formats.

**Implementation path:**
- K8s normalization schema (audit.log format)
- K8s-specific atomic tests: `kubectl exec`, privileged pod creation, service account token theft
- Falco rule testing (Falco rule syntax, not just Sigma)

---

## 5. RECOMMENDED IMPLEMENTATION ROADMAP

### Sprint 1 (Now → +2 weeks): Foundation Complete ✅
- ✅ Environment templates (7 built-in)
- ✅ Threat profile injection (CVE/TTP/Actor/IOC)
- ✅ Sigma rule library (10 repos)
- ✅ Normalization schema manager with versioning
- ✅ Drag-drop environment topology (bug fixed)
- ✅ API auth headers fixed (all pages now work)

### Sprint 2 (+2 weeks): Atomic Tests & Detection Validation
- `AtomicTest` model + GitHub sync (atomic-red-team repo)
- "Expected log events" per atomic → normalization schema mapping
- Detection validation pipeline: run simulation → check if rule fires
- Use case coverage score update after validation run

### Sprint 3 (+4 weeks): Scenario Engine
- Scenario model + pre-built scenarios (Ransomware, APT29, Cloud Takeover)
- Scenario runner with phase progression
- Simple live session dashboard (polling-based, not WebSocket yet)
- Post-exercise report generation

### Sprint 4 (+6 weeks): Live Fire & Tabletop
- WebSocket live session board
- Tabletop exercise mode (inject cards, decision capture)
- SIEM feedback loop (rule hit count polling)
- Detection deployment tracking

### Sprint 5 (+8 weeks): Intelligence Integration
- "Simulate from Intel" (Joti TIP → PurpleLab webhook)
- K8s/Falco rule testing
- Full audit trail for compliance (SOC 2 evidence collection)

---

## 6. WHAT'S MISSING FROM CYBERSECURITY OPS PERSPECTIVE

Beyond detection, a complete security operations simulation needs:

| Gap | Priority | Complexity |
|-----|----------|------------|
| Atomic test execution (synthetic) | P0 | Medium |
| Sigma → SIEM compilation + validation | P0 | High |
| Exercise reporting (PDF) | P0 | Low |
| Scenario library (pre-built kill chains) | P1 | Medium |
| Live fire dashboard (real-time) | P1 | High |
| Tabletop exercise mode | P1 | Medium |
| SIEM feedback (did rule fire?) | P1 | Medium |
| Compliance evidence collection | P2 | Low |
| Container/K8s attack simulation | P2 | High |
| Deception environment simulation | P3 | High |
| Insider threat behavioral simulation | P3 | High |
| Hunt query validation against logs | P2 | Medium |
| SOAR playbook testing (dry-run) | P2 | Medium |
| BAS (Breach and Attack Simulation) agent | P3 | Very High |

---

## 7. ARCHITECTURE DIAGRAM (Text)

```
┌─────────────────────────────────────────────────────────────────┐
│                      PURPLELAB PLATFORM                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Environment  │    │  Threat      │    │ Normalization    │  │
│  │ Templates    │    │  Profiles    │    │ Schemas          │  │
│  │ (7 built-in) │    │ CVE/TTP/IOC  │    │ SIEM Field Maps  │  │
│  └──────┬───────┘    └──────┬───────┘    └────────┬─────────┘  │
│         │                   │                      │            │
│  ┌──────▼───────────────────▼──────────────────────▼─────────┐  │
│  │              SIMULATION ENGINE                            │  │
│  │  Environments → Sessions → Log Generation → Detection     │  │
│  └──────────────────────┬────────────────────────────────────┘  │
│                         │                                       │
│  ┌──────────────────────▼────────────────────────────────────┐  │
│  │              DETECTION VALIDATION                         │  │
│  │  Sigma Library → Compile → Test → Score → Deploy Track   │  │
│  └──────────────────────┬────────────────────────────────────┘  │
│                         │                                       │
│  ┌──────────────────────▼────────────────────────────────────┐  │
│  │              EXERCISE MANAGEMENT                          │  │
│  │  Scenarios → Purple Team → Live Fire → Tabletop → Report  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  INTEGRATIONS:                                                  │
│  ← Joti TIP (threat intel)   ← Joti SOAR (playbook testing)    │
│  ← Atomic Red Team (tests)   → SIEM (rule deployment)          │
│  ← CMDB/HR/VM/CSPM (context) → SOC Team (alerts/exercises)     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. KEY DESIGN PRINCIPLES

1. **Schema-driven fidelity** — all simulated logs use real SIEM field names from normalization schemas
2. **Evidence by default** — every exercise produces an immutable artifact (for compliance/audit)
3. **Coverage is the north star** — every feature feeds back into MITRE ATT&CK coverage score
4. **Fail-safe isolation** — exercises never touch production systems (all simulation is synthetic)
5. **Intel-driven** — threat actor profiles and current TTPs drive what gets tested (not random)
6. **Team-aware** — red/blue/purple modes have different views of the same exercise data
