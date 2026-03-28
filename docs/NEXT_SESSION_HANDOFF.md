# PurpleLab — Next Session Handoff

**Date:** 2026-03-28
**Last commit:** `b8c69ed rebrand: rename from "Joti Sim" to "PurpleLab"`
**Remote:** github.com/labhacker007/PurpleLab
**Branch:** main

---

## What Was Built This Session

### Infrastructure & Tooling
- **purplelab.sh** — single autonomous master script (Docker install, build, launch, heal, reset-password, backup/restore, test, migrate, seed, frontend)
- **Dockerfile** — Python 3.12-slim with system deps, healthcheck, data dirs
- **docker-compose.yml** — 3 services (purplelab-api, purplelab-db, purplelab-redis) with health checks, restart policies, env passthrough
- **.env.example** — all config vars with auto-generated passwords

### Backend (147 Python files, ~15,000 lines)

**Phase 1 — Foundation (DONE)**
- Modular architecture: 8 backend modules
- `backend/config.py` — pydantic-settings
- `backend/db/models.py` — 12 SQLAlchemy ORM models (Conversation, Message, Environment, SIEMConnection, ImportedRule, ThreatActor, MITRETechnique, TestRun, RuleTestResult, SimulationSession, GeneratedEvent, LogSourceSchema)
- `backend/db/session.py` — async SQLAlchemy session factory
- `backend/core/` — security (Fernet), exceptions (PurpleLabError hierarchy), constants, schemas
- `backend/api/legacy.py` — all v1 endpoints preserved at /api/
- `backend/api/v2/` — 8 route modules (chat, sessions, rules, threat_intel, siem, environments, log_sources, knowledge)
- `alembic/` — initial migration with all 12 tables
- `backend/engine/` — refactored simulation engine with all 12 generators moved here
- 12 vendor generators: Splunk, CrowdStrike, Okta, Sentinel, QRadar, Elastic, Carbon Black, Defender, Entra ID, Proofpoint, ServiceNow, GuardDuty

**Phase 2 — Knowledge Base + Threat Intelligence (DONE)**
- `backend/knowledge/vector_store.py` — ChromaDB wrapper with async + in-memory fallback (282 lines)
- `backend/knowledge/embeddings.py` — OpenAI → sentence-transformers → hash fallback chain (210 lines)
- `backend/knowledge/store.py` — unified KnowledgeStore interface (154 lines)
- `backend/threat_intel/mitre_service.py` — MITRE ATT&CK STIX parser, technique/group indexing, coverage matrix (301 lines)
- `backend/threat_intel/actor_service.py` — threat actor CRUD, research, TTP enrichment (278 lines)
- `backend/threat_intel/research.py` — multi-source research orchestrator (305 lines)
- `backend/threat_intel/sources/mitre_attack.py` — STIX bundle loader (370 lines)
- `backend/threat_intel/sources/web_search.py` — SerpAPI/Brave/DuckDuckGo fallback (207 lines)
- `scripts/seed_mitre.py` — downloads + parses MITRE ATT&CK data (182 lines)
- 9 threat intel API endpoints, 3 knowledge API endpoints wired

**Phase 3 — Detection Rule Engine (DONE) — CORE DIFFERENTIATOR**
- `backend/detection/parsers/base_parser.py` — unified AST: Condition, LogicGroup, Aggregation, ParsedRule, 16 operators (187 lines)
- `backend/detection/parsers/sigma_parser.py` — Sigma YAML with field modifiers, condition expressions (627 lines)
- `backend/detection/parsers/spl_parser.py` — SPL search/where/stats/eval, pipe chains (710 lines)
- `backend/detection/parsers/kql_parser.py` — KQL where/summarize/extend for Sentinel (593 lines)
- `backend/detection/parsers/esql_parser.py` — ES|QL FROM/WHERE/STATS for Elastic (514 lines)
- `backend/detection/evaluator.py` — in-memory rule evaluator: 16 operators, aggregations, dot notation, field mapping (619 lines)
- `backend/detection/coverage.py` — MITRE coverage matrix, gap analysis, efficacy scoring (377 lines)
- `backend/detection/rule_manager.py` — import, auto-detect language, batch evaluate (273 lines)
- 8 rules API endpoints
- **Verified working:** Sigma rule "Suspicious PowerShell Execution" parsed → evaluated against 3 logs → correctly matched 2/3

### Frontend (35 files, ~2,700 lines TypeScript/React)
- Next.js 15 + TypeScript + Tailwind 4 + shadcn-style components
- 8 pages: Dashboard, Chat, Environments, Environment Canvas (React Flow), Rules, Rule Detail (Monaco Editor), MITRE Navigator, Reports, Settings
- 5 Zustand stores: chat, environment, rules, threat-intel, ui
- 3 lib modules: api.ts (fetch wrapper), sse.ts (chat streaming), utils.ts
- 8 UI components: button, card, input, badge, dialog, scroll-area, separator, tabs
- 15+ TypeScript interfaces matching backend models

### Security Fixes Applied
- SSRF protection — target_url validation with IP blocklist (backend/engine.py)
- XSS fix — innerHTML replaced with DOM APIs (frontend/index.html)
- Race condition fix — async lock on update_session (backend/engine.py)
- KeyError fix — safe dict access in _send_event (backend/engine.py)

### Tests (28 files, ~3,100 lines including detection tests)
- Unit tests for all 12 generators
- Engine tests (28 tests)
- Scenario tests (11 tests)
- Legacy API integration tests (25 tests)
- Security tests (SQL injection, XSS, CORS — 22 tests)
- Detection engine tests (45 tests, all passing)

### Research & Documentation
- `docs/research/RESEARCH_NOVEL_TECH.md` — 14 patentable innovations, competitor analysis, tech stack validation, admin AI architecture (721 lines)
- `docs/testing/CURRENT_FINDINGS.md` — 5 bugs, 5 security vulnerabilities documented
- `docs/testing/TEST_STRATEGY.md` — testing philosophy, CI/CD plan
- `docs/ROADMAP.md` — full development roadmap

---

## What Needs to Be Built Next

### Phase 4: Agentic Core — PRIORITY: HIGHEST
This is what makes PurpleLab "agentic." Without this, it's just a simulation tool.

**Files to implement:**

1. **`backend/agent/orchestrator.py`** — The brain
   - Wire Anthropic Claude API (`anthropic` SDK) with native `tool_use`
   - ReAct loop: receive user message → call Claude → execute tool calls → feed results back → stream response
   - Token budget management (~30K input per turn)
   - SSE streaming responses to frontend
   - Error handling and retry logic for API calls
   - Import: `from anthropic import Anthropic`

2. **`backend/agent/tools/threat_intel_tools.py`**
   - `research_threat_actor(name: str)` → calls `ActorService.research_actor()`
   - `search_mitre_technique(query: str)` → calls `MITREService.search_techniques()`
   - `web_search(query: str)` → calls `WebSearchSource.search()`

3. **`backend/agent/tools/rule_tools.py`**
   - `import_detection_rules(rules_text: str, language: str)` → calls `RuleManager.import_rules()`
   - `parse_detection_rule(rule_text: str)` → auto-detect + parse
   - `test_rules_against_logs(rule_ids: list, logs: list)` → calls `RuleEvaluator.evaluate()`
   - `get_coverage_matrix(technique_ids: list)` → calls `CoverageAnalyzer`

4. **`backend/agent/tools/log_tools.py`**
   - `generate_attack_logs(technique: str, source_type: str, count: int)` → calls log source generators
   - `generate_noise_logs(source_type: str, count: int)` → calls noise generator
   - `list_log_source_schemas()` → returns available log types

5. **`backend/agent/tools/siem_tools.py`**
   - `connect_to_siem(type: str, config: dict)` → calls connector
   - `pull_siem_rules(connection_id: str)` → import rules from SIEM
   - `push_logs_to_siem(connection_id: str, logs: list)` → ingest logs

6. **`backend/agent/tools/knowledge_tools.py`**
   - `save_to_knowledge_base(namespace: str, key: str, content: str)`
   - `search_knowledge_base(query: str, namespace: str)`

7. **`backend/agent/conversation.py`** — implement fully
   - Multi-turn history with sliding window
   - Token counting (use `anthropic.count_tokens()` or estimate at 4 chars/token)
   - Context compression for long conversations

8. **`backend/agent/prompts.py`** — enhance
   - Dynamic system prompt assembly: base identity + available tools + environment context + RAG results
   - Currently has a basic stub — needs full implementation

9. **`backend/agent/plan_executor.py`** — implement
   - Decompose complex requests into ordered sub-tasks
   - Example: "Test APT28 against my Splunk rules" → 6-step plan

10. **`backend/api/v2/chat.py`** — implement SSE streaming
    - `POST /api/v2/chat` → SSE stream with events: `text`, `tool_call`, `tool_result`, `done`
    - Store messages in database (Conversation + Message models)
    - Support `conversation_id` for multi-turn

11. **Frontend chat wiring** (`frontend-next/app/chat/page.tsx`)
    - Wire SSE client to message display
    - Render tool call cards (collapsible, show tool name + inputs + outputs)
    - Conversation list sidebar with history
    - Environment selector dropdown

12. **End-to-end integration test**
    - Test: "Research APT28 and test their techniques against these Sigma rules"
    - Should: look up APT28 → find TTPs → parse rules → generate logs → evaluate → report gaps

### Phase 5: Log Source Simulators — PRIORITY: HIGH

**Files to implement (currently stubs with `pass`):**

1. **`backend/log_sources/sources/windows_eventlog.py`**
   - Event IDs: 4624 (logon), 4625 (failed), 4688 (process create), 4720 (user create), 7045 (service)
   - Full Windows XML event format with realistic SIDs, timestamps, hostnames

2. **`backend/log_sources/sources/sysmon.py`**
   - Event IDs: 1 (ProcessCreate), 3 (NetworkConnect), 7 (ImageLoad), 11 (FileCreate), 22 (DNSQuery)
   - Sysmon XML schema with process tree, hashes, command lines

3. **`backend/log_sources/sources/linux_audit.py`**
   - auditd format: execve, connect, open syscalls
   - Realistic uid/gid, paths, command args

4. **`backend/log_sources/sources/firewall.py`**
   - Palo Alto, Fortinet formats
   - Allow/deny, zones, applications, byte counts

5. **`backend/log_sources/sources/dns.py`**
   - Query/response, NXDOMAIN, TXT queries for C2
   - Suspicious domain patterns

6. **`backend/log_sources/sources/cloud_trail.py`**
   - AWS CloudTrail JSON: CreateUser, PutBucketPolicy, StopLogging, etc.

7. **`backend/log_sources/noise_generator.py`**
   - Benign baseline generator
   - Configurable signal-to-noise ratio
   - Time-of-day patterns

8. **Attack fingerprint system** (new concept)
   - Define attack patterns as ordered log sequences per TTP
   - Embed within noise stream
   - Cross-correlate identifiers (same IPs, users, hashes across log sources)

### Phase 6: SIEM Integration — PRIORITY: MEDIUM

**Files to implement (currently stubs):**

1. **`backend/siem_integration/connectors/splunk_connector.py`**
   - REST API (https://{host}:8089/services/)
   - Import saved searches, data models (CIM)
   - Push logs via HEC (HTTP Event Collector, port 8088)

2. **`backend/siem_integration/connectors/sentinel_connector.py`**
   - Azure AD OAuth2 auth
   - Import analytics rules via Azure REST API
   - Push logs via Data Collector API

3. **`backend/siem_integration/connectors/elastic_connector.py`**
   - API key auth
   - Import detection rules via Security API
   - Push logs via _bulk API

4. **`backend/siem_integration/data_models/cim.py`** — Splunk CIM field mappings
5. **`backend/siem_integration/data_models/asim.py`** — Sentinel ASIM mappings
6. **`backend/siem_integration/data_models/ecs.py`** — Elastic ECS mappings
7. **`backend/siem_integration/connection_manager.py`** — encrypted cred storage, test connectivity

### Phase 7: Environment Builder + Reports — PRIORITY: MEDIUM

1. **`backend/environments/environment_service.py`** — full CRUD, templates, simulation binding
2. **`backend/environments/templates.py`** — pre-built configs (SOC starter, cloud-native, hybrid)
3. **React Flow canvas enhancements** — save/load configs, properties panel, node connections
4. **Test run reporting** — gap analysis table, coverage heatmap, recommendations
5. **Export** — PDF/HTML/JSON/CSV report generation

### Phase 8: Hardening — PRIORITY: LOW (for now)

1. Authentication (API key middleware)
2. Rate limiting
3. Admin AI dashboard (token usage, cost tracking, model routing)
4. HITL workflow (propose → approve → execute → review)
5. Configurable automation levels per feature
6. CI/CD pipeline (GitHub Actions)
7. Structured logging + metrics

---

## Patent Implementation Priority

| # | Innovation | Build In Phase | Status |
|---|---|---|---|
| 1 | In-Memory Detection Rule Cross-Compilation | 3 | **DONE** |
| 2 | Agentic Detection Gap Analysis | 4 | **BUILD NEXT** |
| 3 | Hyper-Automation for Purple Teaming | 4+5 | **BUILD NEXT** |
| 4 | Synthetic Log Generation with Attack Fingerprinting | 5 | TODO |
| 5 | Detection Rule Efficacy Scoring | 3 | **PARTIAL** (needs evasion variants) |
| 6 | Cross-SIEM Detection Portability Engine | 6 | TODO |
| 7 | Human-in-the-Loop Agentic Security Testing | 8 | TODO |
| 8 | Attack Chain Simulation Orchestration | 5 | TODO |
| 9 | Adaptive Signal-to-Noise Calibration | 5 | TODO |
| 10 | Dynamic Environment Fingerprinting | 7 | TODO |

---

## Tech Stack Decisions Still Pending

| Decision | Options | Notes |
|---|---|---|
| Redis vs Valkey | Valkey 8.x recommended (FOSS) | Redis SSPL licensing concern |
| ChromaDB vs Qdrant | Qdrant 1.x recommended for production | ChromaDB fine for now |
| Celery vs Taskiq | Taskiq recommended (async-native) | Celery stub exists, easy to swap |
| Cache algorithm | W-TinyLFU recommended | Avoid ARC (IBM patent) |

---

## Quick Start for Next Session

```bash
# Open the project
code c:\Projects\purplelab

# Start services
./purplelab.sh up

# Run tests
./purplelab.sh test

# Check status
./purplelab.sh status
```

**Recommended first task:** Implement Phase 4 (Agentic Core) starting with `backend/agent/orchestrator.py` — this is the highest-impact work that transforms PurpleLab from a tool into a platform.

---

## Key Files Reference

| What | Path |
|---|---|
| Master script | `purplelab.sh` |
| Backend entry | `backend/main.py` |
| Config | `backend/config.py` |
| DB models | `backend/db/models.py` |
| Agent orchestrator | `backend/agent/orchestrator.py` (stub → implement) |
| Agent tools | `backend/agent/tools/` (empty → implement) |
| Detection evaluator | `backend/detection/evaluator.py` (working) |
| Detection parsers | `backend/detection/parsers/` (working) |
| Threat intel | `backend/threat_intel/` (working) |
| Knowledge base | `backend/knowledge/` (working) |
| Log sources | `backend/log_sources/sources/` (stubs → implement) |
| SIEM connectors | `backend/siem_integration/connectors/` (stubs → implement) |
| Frontend pages | `frontend-next/app/` |
| Tests | `tests/` |
| Roadmap | `docs/ROADMAP.md` |
| Research | `docs/research/RESEARCH_NOVEL_TECH.md` |
| Security findings | `docs/testing/CURRENT_FINDINGS.md` |
