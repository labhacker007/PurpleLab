# PurpleLab v2 — Development Roadmap

## What's Built (Phases 1-3)

### Phase 1: Foundation — DONE
- [x] Modular backend architecture (8 modules, 147 Python files)
- [x] PostgreSQL 17 + Alembic migrations (12 tables)
- [x] Redis 7.4 for cache/broker
- [x] SQLAlchemy 2.0 async ORM models
- [x] FastAPI restructured (legacy /api/ + new /api/v2/)
- [x] Config via pydantic-settings (.env)
- [x] Core utilities (encryption, exceptions, constants, schemas)
- [x] Docker Compose with health checks
- [x] Autonomous setup script (purplelab.sh)

### Phase 2: Knowledge Base + Threat Intelligence — DONE
- [x] ChromaDB vector store with async wrappers + in-memory fallback
- [x] Embedding provider (OpenAI → sentence-transformers → hash fallback)
- [x] Unified KnowledgeStore (vector + structured)
- [x] MITRE ATT&CK service (STIX parser, techniques, groups, relationships)
- [x] Threat actor service (CRUD, research, TTP enrichment)
- [x] Web search source (SerpAPI, Brave, DuckDuckGo fallback)
- [x] MITRE ATT&CK data seed script
- [x] 9 threat intel API endpoints, 3 knowledge API endpoints

### Phase 3: Detection Rule Engine — DONE
- [x] Unified AST (Condition, LogicGroup, Aggregation, ParsedRule)
- [x] Sigma YAML parser (modifiers, conditions, value lists)
- [x] SPL parser (search/where/stats/eval, pipe chains)
- [x] KQL parser (where/summarize/extend, Sentinel patterns)
- [x] ES|QL parser (FROM/WHERE/STATS, Elastic patterns)
- [x] In-memory rule evaluator (16 operators, aggregations, dot notation, field mapping)
- [x] Coverage analyzer (MITRE mapping, gap analysis, efficacy scoring)
- [x] Rule manager (import, auto-detect language, batch evaluate)
- [x] 8 rules API endpoints
- [x] 45 passing tests

### Frontend Scaffold — DONE
- [x] Next.js 15 + TypeScript + Tailwind 4 + shadcn-style components
- [x] 8 pages (Dashboard, Chat, Environments, Canvas, Rules, Rule Detail, MITRE Nav, Reports, Settings)
- [x] React Flow canvas with custom node types
- [x] Monaco editor for rules
- [x] 5 Zustand stores, API client, SSE client
- [x] 8 UI components, 15+ TypeScript interfaces

### Security Fixes — DONE
- [x] SSRF protection (target_url validation, IP blocklist)
- [x] XSS fix (innerHTML → DOM APIs)
- [x] Race condition fix (async lock on update_session)
- [x] KeyError fix (safe dict access)

### Testing — DONE
- [x] 28 test files, ~2,500 lines
- [x] Unit tests for all 12 generators
- [x] Integration tests for legacy API
- [x] Security tests (SQL injection, XSS, CORS)
- [x] Detection engine tests (45 passing)

### Research — DONE
- [x] 14 patentable innovations documented
- [x] Competitor gap analysis (AttackIQ, SafeBreach, Cymulate, Picus)
- [x] Tech stack validation with recommendations
- [x] Admin AI Freedom Architecture designed

---

## What Needs to Be Built (Phases 4-8)

### Phase 4: Agentic Core — NOT STARTED
Priority: HIGH — This is what makes the platform "agentic"

- [ ] **AgentOrchestrator implementation** (`backend/agent/orchestrator.py`)
  - Wire Claude API (anthropic SDK) with tool_use
  - ReAct loop: receive message → call tools → stream results
  - Token budget management (~30K per turn)
  - Streaming via SSE to frontend

- [ ] **Register all module functions as agent tools** (`backend/agent/tools/`)
  - `threat_intel_tools.py` — research_threat_actor, search_mitre_technique, web_search
  - `rule_tools.py` — import_detection_rules, parse_detection_rule, test_rules_against_logs
  - `log_tools.py` — generate_attack_logs, generate_noise_logs, list_log_source_schemas
  - `siem_tools.py` — connect_to_siem, pull_siem_rules, push_logs_to_siem
  - `knowledge_tools.py` — save_to_knowledge_base, search_knowledge_base
  - `simulation_tools.py` — run_simulation, get_coverage_matrix

- [ ] **ConversationManager** (`backend/agent/conversation.py`)
  - Multi-turn history with sliding window
  - Token counting and budget enforcement
  - Context compression for long conversations

- [ ] **RAG pipeline**
  - Query ChromaDB for relevant knowledge on each request
  - Inject top-k results into system prompt
  - Dynamic context sizing based on query complexity

- [ ] **System prompt engineering** (`backend/agent/prompts.py`)
  - Base identity prompt
  - Dynamic tool descriptions
  - Environment context injection
  - RAG context injection

- [ ] **PlanExecutor** (`backend/agent/plan_executor.py`)
  - Decompose complex requests into ordered sub-tasks
  - Track execution progress
  - Handle partial failures gracefully

- [ ] **Chat API endpoint** (`backend/api/v2/chat.py`)
  - SSE streaming response
  - Conversation CRUD
  - Environment binding

- [ ] **Chat UI** (frontend-next)
  - Wire SSE streaming to message display
  - Tool call cards (expandable, show inputs/outputs)
  - Conversation list with history
  - Environment selector

- [ ] **End-to-end test**: "Test APT28 against my Sigma rules" flow

### Phase 5: Log Source Simulators — NOT STARTED
Priority: HIGH — Needed for realistic detection testing

- [ ] **Windows Event Log generator** (`backend/log_sources/sources/windows_eventlog.py`)
  - Event IDs: 4624 (logon), 4625 (failed logon), 4688 (process creation), 4720 (user created), 7045 (service installed)
  - Realistic field values, timestamps, SIDs

- [ ] **Sysmon generator** (`backend/log_sources/sources/sysmon.py`)
  - Event IDs: 1 (ProcessCreate), 3 (NetworkConnect), 7 (ImageLoad), 11 (FileCreate), 22 (DNSQuery)
  - Full Sysmon XML schema with realistic process trees

- [ ] **Linux audit generator** (`backend/log_sources/sources/linux_audit.py`)
  - auditd format: execve, connect, open syscalls
  - Realistic uid/gid, command lines, paths

- [ ] **Firewall generator** (`backend/log_sources/sources/firewall.py`)
  - Palo Alto, Fortinet log formats
  - Allow/deny actions, zones, applications

- [ ] **DNS generator** (`backend/log_sources/sources/dns.py`)
  - Query/response pairs, NXDOMAIN, suspicious domains

- [ ] **Cloud Trail generator** (`backend/log_sources/sources/cloud_trail.py`)
  - AWS CloudTrail JSON format
  - API calls: CreateUser, PutBucketPolicy, StopLogging, etc.

- [ ] **Noise generator** (`backend/log_sources/noise_generator.py`)
  - Realistic benign activity baseline
  - Configurable signal-to-noise ratio
  - Time-of-day patterns (business hours vs off-hours)

- [ ] **Attack fingerprint system**
  - Define attack patterns as ordered log sequences
  - Embed within noise at configurable ratios
  - Correlate across log sources (same IPs, users, hashes)

### Phase 6: SIEM Integration — NOT STARTED
Priority: MEDIUM — Needed for production use cases

- [ ] **Splunk connector** (`backend/siem_integration/connectors/splunk_connector.py`)
  - REST API auth (bearer token, basic)
  - Import saved searches (detection rules)
  - Import data models (CIM field mappings)
  - Push logs via HEC (HTTP Event Collector)

- [ ] **Sentinel connector** (`backend/siem_integration/connectors/sentinel_connector.py`)
  - Azure AD OAuth2 authentication
  - Import analytics rules
  - Import ASIM schema mappings
  - Push logs via Data Collector API

- [ ] **Elastic connector** (`backend/siem_integration/connectors/elastic_connector.py`)
  - API key / basic auth
  - Import detection rules
  - Import ECS mappings
  - Push logs via _bulk API

- [ ] **Connection manager** (`backend/siem_integration/connection_manager.py`)
  - Encrypted credential storage (Fernet)
  - Connection testing
  - Sync scheduling

- [ ] **Data model normalizers** (`backend/siem_integration/data_models/`)
  - CIM → unified field names
  - ASIM → unified field names
  - ECS → unified field names
  - Bidirectional mapping for rule evaluation

- [ ] **SIEM connection UI** (frontend-next settings page)
  - Add/edit/delete connections
  - Test connectivity button
  - Sync rules button
  - Field mapping viewer

### Phase 7: Environment Builder + Reports — NOT STARTED
Priority: MEDIUM

- [ ] **Environment service** (`backend/environments/environment_service.py`)
  - Full CRUD with nested configuration
  - Environment templates (SOC starter, cloud-native, hybrid)
  - Simulation orchestration (bind environment to test run)

- [ ] **React Flow canvas enhancements** (frontend-next)
  - Environment-specific node types (log sources, SIEMs, rule sets)
  - Properties panel with per-node configuration
  - Save/load environment configurations
  - Visual connection between nodes

- [ ] **Test run reporting**
  - Gap analysis table (technique → rule → result)
  - Coverage heatmap (MITRE ATT&CK matrix, color-coded)
  - Recommendations engine (suggest rules for gaps)
  - Historical comparison (test run A vs B)

- [ ] **Export reports**
  - PDF generation
  - HTML standalone report
  - JSON/CSV data export

### Phase 8: Hardening + Production — NOT STARTED
Priority: LOW (for now)

- [ ] Authentication (API key middleware, optional OAuth2/OIDC)
- [ ] Rate limiting (SlowAPI or custom middleware)
- [ ] Admin AI dashboard (token usage, cost tracking, model routing)
- [ ] HITL workflow (propose → approve → execute → review)
- [ ] Automation levels (full manual / semi-auto / full auto per feature)
- [ ] CI/CD pipeline (GitHub Actions: lint, test, build, deploy)
- [ ] Structured logging + metrics (OpenTelemetry)
- [ ] Load testing
- [ ] User documentation
- [ ] API documentation (auto-generated from FastAPI + manual guides)

---

## Patentable Innovations to Implement

| # | Innovation | Phase | Status |
|---|---|---|---|
| 1 | In-Memory Detection Rule Cross-Compilation (unified AST + evaluator) | 3 | DONE |
| 2 | Agentic Detection Gap Analysis | 4 | TODO |
| 3 | Synthetic Log Generation with Attack Fingerprinting | 5 | TODO |
| 4 | Hyper-Automation for Purple Teaming (end-to-end pipeline) | 4+5 | TODO |
| 5 | Detection Rule Efficacy Scoring (multi-dimensional) | 3 | PARTIAL (scoring built, needs evasion variants) |
| 6 | Cross-SIEM Detection Portability Engine | 6 | TODO |
| 7 | Adaptive Signal-to-Noise Calibration (ML-based) | 5 | TODO |
| 8 | Human-in-the-Loop Agentic Security Testing | 8 | TODO |
| 9 | Attack Chain Simulation Orchestration (DAG-based) | 5 | TODO |
| 10 | Dynamic Environment Fingerprinting | 7 | TODO |
| 11 | Real-Time Detection Regression Testing (CI/CD for rules) | 8 | TODO |
| 12 | Adversary Emulation Playbook Auto-Generation | 5 | TODO |
| 13 | Persistent Simulation Memory with Token Optimization | 2 | PARTIAL (knowledge base built, needs W-TinyLFU) |
| 14 | Agentic Threat Intelligence with RAG | 2+4 | PARTIAL (TI + knowledge done, needs agent wiring) |

---

## Tech Stack Changes Recommended (from Research)

| Current | Recommended | Why | Status |
|---|---|---|---|
| Redis 7.4 | Valkey 8.x | Redis SSPL relicensing; Valkey is Linux Foundation fork | TODO — evaluate |
| ChromaDB 0.6 | Qdrant 1.x or pgvector | ChromaDB pre-1.0 stability; Qdrant production-grade | TODO — evaluate |
| Celery 5.4 | Taskiq | Native async/FastAPI integration | TODO — evaluate |
| LRU cache | W-TinyLFU | Near-optimal hit rates; avoid ARC (IBM patent) | TODO |

---

## File Reference

| Area | Key Files |
|---|---|
| Master script | `purplelab.sh` |
| Backend entry | `backend/main.py` |
| Config | `backend/config.py`, `.env` |
| DB models | `backend/db/models.py` |
| Agent | `backend/agent/orchestrator.py` (stub) |
| Detection engine | `backend/detection/evaluator.py`, `backend/detection/parsers/` |
| Threat intel | `backend/threat_intel/actor_service.py`, `backend/threat_intel/mitre_service.py` |
| Knowledge base | `backend/knowledge/store.py`, `backend/knowledge/vector_store.py` |
| Log sources | `backend/log_sources/sources/` (stubs) |
| SIEM connectors | `backend/siem_integration/connectors/` (stubs) |
| Frontend | `frontend-next/app/` |
| Tests | `tests/` |
| Research | `docs/research/RESEARCH_NOVEL_TECH.md` |
| Findings | `docs/testing/CURRENT_FINDINGS.md` |
