# PurpleLab v2 — Architecture & Capability Reference

**Last updated:** 2026-03-28
**Purpose:** Single source of truth for what is built, what is stubbed, and how every component connects.
**See also:** [VISION_AND_MASTER_PLAN.md](VISION_AND_MASTER_PLAN.md) — full platform vision with 50+ log sources, scoring models, Joti integration, and HITL workflows.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Tech Stack](#2-tech-stack)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Request Lifecycle Flows](#4-request-lifecycle-flows)
5. [Backend Module Reference](#5-backend-module-reference)
6. [Frontend Module Reference](#6-frontend-module-reference)
7. [Data Models & Database](#7-data-models--database)
8. [API Endpoint Reference](#8-api-endpoint-reference)
9. [Agent System (Phase 4)](#9-agent-system-phase-4)
10. [Detection Engine (Phase 3)](#10-detection-engine-phase-3)
11. [Simulation Engine](#11-simulation-engine)
12. [Threat Intelligence](#12-threat-intelligence)
13. [Knowledge Base](#13-knowledge-base)
14. [Infrastructure & DevOps](#14-infrastructure--devops)
15. [Testing](#15-testing)
16. [Implementation Status Matrix](#16-implementation-status-matrix)
17. [Not Yet Built](#17-not-yet-built)

---

## 1. System Overview

PurpleLab is an **agentic cybersecurity simulation platform** that:

- Simulates 12+ security products (SIEMs, EDRs, ITDR, email gateways, ITSM, cloud security)
- Parses & evaluates detection rules across 5 languages (Sigma, SPL, KQL, ES|QL, YARA-L)
- Provides an AI agent (Claude) that can research threats, test rules, generate logs, and analyze coverage
- Maps everything to MITRE ATT&CK for gap analysis

```
                        User
                         |
            ┌────────────┼────────────┐
            |            |            |
     Next.js Frontend   Legacy UI    API Client
     (port 3000)        (port 4000)  (direct)
            |            |            |
            └────────────┼────────────┘
                         |
                    FastAPI (port 4000)
                    ┌────┴────┐
                /api/ (v1)  /api/v2/
                    |         |
        ┌───────────┼─────────┼───────────┐
        |           |         |           |
  Simulation   Detection   Agent      Threat
   Engine       Engine    Orchestrator  Intel
     |            |         |           |
  12 Vendor    4 Parsers  AsyncAnthropic MITRE
  Generators   Evaluator  21 Tools     ATT&CK
     |           |         |           |
     └───────────┼─────────┼───────────┘
                 |         |
            PostgreSQL  ChromaDB
            (models)    (vectors)
```

---

## 2. Tech Stack

| Layer | Technology | Version | Status |
|-------|-----------|---------|--------|
| **Runtime** | Python | 3.12 | RUNNING |
| **Web framework** | FastAPI | latest | RUNNING |
| **ASGI server** | Uvicorn | latest | RUNNING |
| **Database** | PostgreSQL | 17 (alpine) | CONFIGURED |
| **ORM** | SQLAlchemy 2.0 (async) | latest | MODELS DEFINED |
| **Migrations** | Alembic | latest | INITIAL MIGRATION |
| **Cache/Broker** | Redis | 7.4 (alpine) | CONFIGURED |
| **Vector DB** | ChromaDB | 0.6+ | RUNNING (in-memory fallback) |
| **LLM** | Anthropic Claude | claude-sonnet-4-20250514 | WIRED |
| **HTTP client** | HTTPX (async) | latest | RUNNING |
| **Task queue** | Celery (stub) | 5.4 | NOT WIRED |
| **Frontend** | Next.js 15 + React 19 | latest | SCAFFOLD |
| **State mgmt** | Zustand | 5 | RUNNING |
| **Canvas** | @xyflow/react (React Flow) | 12.4 | RUNNING |
| **Code editor** | Monaco Editor | 4.7 | RUNNING |
| **Styling** | Tailwind CSS 4 | latest | RUNNING |
| **Container** | Docker + Compose | latest | CONFIGURED |

---

## 3. High-Level Architecture

### 3.1 Process Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Docker Compose                                                  │
│                                                                  │
│  ┌──────────────────┐  ┌────────────────┐  ┌────────────────┐  │
│  │  purplelab-api    │  │  purplelab-db  │  │  purplelab-    │  │
│  │  (FastAPI)        │  │  (PostgreSQL)  │  │  redis         │  │
│  │  Port 4000        │  │  Port 5433     │  │  Port 6380     │  │
│  │                   │  │                │  │                │  │
│  │  - API routes     │  │  - 12 tables   │  │  - Cache       │  │
│  │  - Agent loop     │  │  - Alembic     │  │  - Broker      │  │
│  │  - Sim engine     │  │    migrations  │  │  - Sessions    │  │
│  │  - Static files   │  │                │  │                │  │
│  └──────────────────┘  └────────────────┘  └────────────────┘  │
│                                                                  │
│  + ChromaDB (embedded, ./data/chroma)                           │
│  + Next.js dev server (port 3000, development only)             │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Module Dependency Graph

```
backend/
├── main.py                      ← FastAPI app entry point
│   ├── config.py                ← pydantic-settings (env vars)
│   ├── core/                    ← Shared utilities
│   │   ├── exceptions.py        ← PurpleLabError hierarchy
│   │   ├── constants.py         ← Enums & lookup tables
│   │   ├── security.py          ← Fernet encryption
│   │   └── schemas.py           ← Pydantic request/response models
│   ├── db/                      ← Database layer
│   │   ├── models.py            ← 12 SQLAlchemy ORM models
│   │   └── session.py           ← Async session factory
│   ├── dependencies.py          ← FastAPI DI providers
│   │
│   ├── api/                     ← HTTP layer
│   │   ├── legacy.py            ← v1 /api/ routes (simulation)
│   │   └── v2/                  ← v2 /api/v2/ routes
│   │       ├── chat.py          ← POST /chat (SSE streaming)
│   │       ├── rules.py         ← Detection rule CRUD + test
│   │       ├── threat_intel.py  ← Actors, techniques, research
│   │       ├── knowledge.py     ← Semantic search + indexing
│   │       ├── sessions.py      ← Simulation session CRUD
│   │       ├── environments.py  ← Environment CRUD
│   │       ├── siem.py          ← SIEM connection CRUD
│   │       └── log_sources.py   ← Log generation
│   │
│   ├── agent/                   ← Agentic AI system
│   │   ├── orchestrator.py      ← ReAct loop (Claude + tools)
│   │   ├── conversation.py      ← Multi-turn history manager
│   │   ├── prompts.py           ← Dynamic system prompt builder
│   │   ├── tool_registry.py     ← Tool registration + execution
│   │   └── tools/               ← 21 callable tools
│   │       ├── threat_intel_tools.py   (4 tools)
│   │       ├── rule_tools.py          (4 tools)
│   │       ├── log_tools.py           (3 tools)
│   │       ├── siem_tools.py          (3 tools)
│   │       ├── knowledge_tools.py     (3 tools)
│   │       └── simulation_tools.py    (4 tools)
│   │
│   ├── detection/               ← Rule parsing & evaluation
│   │   ├── parsers/
│   │   │   ├── base_parser.py   ← Unified AST (ParsedRule)
│   │   │   ├── sigma_parser.py  ← Sigma YAML → AST
│   │   │   ├── spl_parser.py    ← Splunk SPL → AST
│   │   │   ├── kql_parser.py    ← Kusto KQL → AST
│   │   │   └── esql_parser.py   ← ES|QL → AST
│   │   ├── evaluator.py         ← In-memory rule evaluation
│   │   ├── coverage.py          ← MITRE coverage matrix
│   │   └── rule_manager.py      ← Import, detect, batch test
│   │
│   ├── threat_intel/            ← Threat intelligence
│   │   ├── mitre_service.py     ← MITRE ATT&CK STIX data
│   │   ├── actor_service.py     ← Threat actor profiles
│   │   ├── research.py          ← Multi-source research
│   │   └── sources/
│   │       ├── mitre_attack.py  ← STIX bundle loader
│   │       └── web_search.py    ← Web search (stub)
│   │
│   ├── knowledge/               ← Semantic knowledge base
│   │   ├── store.py             ← Unified interface
│   │   ├── vector_store.py      ← ChromaDB wrapper
│   │   └── embeddings.py        ← Embedding generation
│   │
│   ├── engine/                  ← Simulation engine
│   │   ├── engine.py            ← Session mgmt + dispatch
│   │   ├── scheduler.py         ← APScheduler job runner
│   │   └── generators/          ← 12 vendor generators
│   │       ├── base.py          ← BaseGenerator ABC
│   │       ├── splunk.py
│   │       ├── crowdstrike.py
│   │       ├── sentinel.py
│   │       ├── okta.py
│   │       ├── proofpoint.py
│   │       ├── servicenow.py
│   │       ├── carbon_black.py
│   │       ├── defender.py
│   │       ├── entra_id.py
│   │       ├── qradar.py
│   │       ├── elastic.py
│   │       └── guardduty.py
│   │
│   ├── log_sources/             ← Raw log generators (STUBS)
│   │   ├── base_log_source.py   ← AbstractLogSource ABC
│   │   ├── noise_generator.py   ← Noise generator (stub)
│   │   └── sources/             ← Per-type generators (empty)
│   │
│   ├── siem_integration/        ← SIEM connectors (STUBS)
│   │   ├── connection_manager.py
│   │   ├── connectors/          ← Per-SIEM connectors (empty)
│   │   └── data_models/         ← CIM/ASIM/ECS (empty)
│   │
│   └── environments/            ← Environment mgmt (STUBS)
│       ├── environment_service.py
│       └── templates.py
```

---

## 4. Request Lifecycle Flows

### 4.1 Agentic Chat Flow (Primary Use Case)

This is the core agentic loop — the main interaction pattern for users.

```
User sends message
        │
        ▼
POST /api/v2/chat  { message, conversation_id?, environment_id? }
        │
        ▼
┌─ AgentOrchestrator.run() ─────────────────────────────────────┐
│                                                                │
│  1. ConversationManager.get_or_create(conversation_id)         │
│     → Returns conv_id (UUID)                                   │
│     → yield {"type": "conversation_id", "content": conv_id}   │
│                                                                │
│  2. ConversationManager.add_message(conv_id, "user", message)  │
│                                                                │
│  3. ConversationManager.trim_to_budget(conv_id)                │
│     → Estimates tokens at ~4 chars/token                       │
│     → Trims oldest messages if > 30K token budget              │
│     → Preserves first message, removes tool pairs together     │
│                                                                │
│  4. build_system_prompt(env_context, tools, rag_context)       │
│     → Assembles: base identity + tool descriptions +           │
│       environment context + RAG knowledge results              │
│                                                                │
│  5. ConversationManager.get_anthropic_messages(conv_id)        │
│     → Converts internal format to Anthropic API format         │
│     → Reconstructs tool_use + tool_result block pairs          │
│                                                                │
│  ┌─ AGENTIC LOOP (max 15 rounds) ───────────────────────────┐ │
│  │                                                           │ │
│  │  6. client.messages.create(                               │ │
│  │       model="claude-sonnet-4-20250514",                 │ │
│  │       max_tokens=4096,                                    │ │
│  │       system=system_prompt,                               │ │
│  │       messages=api_messages,                              │ │
│  │       tools=registry.list_tools()  // 21 tools            │ │
│  │     )                                                     │ │
│  │         │                                                 │ │
│  │         ▼                                                 │ │
│  │  7. Process response.content blocks:                      │ │
│  │     ├─ type="text"     → yield {"type":"text",...}        │ │
│  │     └─ type="tool_use" → yield {"type":"tool_call",...}   │ │
│  │                                                           │ │
│  │  8. If stop_reason == "tool_use":                         │ │
│  │     ├─ Execute each tool via ToolRegistry.execute()       │ │
│  │     ├─ yield {"type":"tool_result",...} per tool           │ │
│  │     ├─ Append assistant + tool_result to api_messages     │ │
│  │     ├─ Store in ConversationManager                       │ │
│  │     └─ LOOP BACK to step 6                                │ │
│  │                                                           │ │
│  │  9. If stop_reason == "end_turn":                         │ │
│  │     ├─ Store final assistant message                      │ │
│  │     └─ BREAK loop                                         │ │
│  │                                                           │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                │
│  10. yield {"type": "done"}                                    │
│                                                                │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
SSE Stream to client: data: {"type":"text","content":"..."}\n\n
                      data: {"type":"tool_call","metadata":{...}}\n\n
                      data: {"type":"tool_result","metadata":{...}}\n\n
                      data: {"type":"done"}\n\n
```

### 4.2 Tool Execution Flow (Inside Agentic Loop)

```
Claude returns tool_use block:
  { id: "toolu_xxx", name: "research_threat_actor", input: {"name": "APT28"} }
        │
        ▼
ToolRegistry.execute("research_threat_actor", {"name": "APT28"})
        │
        ▼
┌─ Tool Handler (async) ────────────────────────────────────────┐
│                                                                │
│  threat_intel_tools.py → _research_threat_actor(name="APT28") │
│     │                                                          │
│     ├─ Lazy import: ActorService, MITREService, KnowledgeStore │
│     ├─ actor_service.research_actor("APT28")                   │
│     │   ├─ Check knowledge base for cached profile             │
│     │   ├─ Query MITRE ATT&CK for group "APT28"               │
│     │   ├─ Extract techniques, tactics, platforms              │
│     │   └─ Return structured actor profile                     │
│     └─ Return: {"status":"ok", "actor": {...}}                 │
│                                                                │
│  On error → Return: {"error": "message"}                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
Result JSON-serialized → fed back to Claude as tool_result message
        │
        ▼
Claude processes result → may call more tools or generate final answer
```

### 4.3 Detection Rule Evaluation Flow

```
Input: Rule text (any language) + Log data (list of dicts)
        │
        ▼
┌─ RuleManager ─────────────────────────────────────────────────┐
│                                                                │
│  1. detect_language(rule_text)                                 │
│     → Heuristics: YAML+detection→sigma, search+|→spl,         │
│       where+summarize→kql, FROM+WHERE→esql                    │
│                                                                │
│  2. import_rules(rule_text, language)                           │
│     → Select parser: SigmaParser / SPLParser / KQLParser /     │
│       ESQLParser                                               │
│     → Parse to unified AST: ParsedRule                         │
│                                                                │
│  3. ParsedRule contains:                                       │
│     ├─ name, description, severity                             │
│     ├─ mitre_techniques[] (e.g., ["T1059.001"])                │
│     ├─ filter: LogicGroup (tree of Conditions)                 │
│     ├─ aggregation: Aggregation (count/sum/avg + group_by)     │
│     └─ referenced_fields[], data_sources[], tags[]             │
│                                                                │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ RuleEvaluator.evaluate(rule, logs) ──────────────────────────┐
│                                                                │
│  Phase 1: FILTER                                               │
│  ├─ Walk LogicGroup tree recursively                           │
│  ├─ Each Condition: field + operator + value                   │
│  ├─ 16 operators: eq, neq, contains, startswith, endswith,     │
│  │   regex, gt, gte, lt, lte, in, not_in, exists,             │
│  │   not_exists, wildcard                                      │
│  ├─ Supports: dot notation, case-insensitive, field mapping    │
│  ├─ LogicOp: AND (all match), OR (any match), NOT (invert)    │
│  └─ Result: list of matched log indices                        │
│                                                                │
│  Phase 2: AGGREGATION (if rule has aggregation)                │
│  ├─ Group matched logs by group_by fields                      │
│  ├─ Apply function: count, sum, avg, min, max, distinct_count  │
│  ├─ Evaluate threshold condition                               │
│  └─ Result: fired=True/False, aggregation_result               │
│                                                                │
│  Output: EvalResult                                            │
│  ├─ rule_name, fired, matched_count, total_logs                │
│  ├─ matched_log_indices[], aggregation_result                  │
│  └─ evaluation_time_ms, details                                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ CoverageAnalyzer ────────────────────────────────────────────┐
│                                                                │
│  compute_coverage(rules) → CoverageMatrix                      │
│  ├─ Map each rule's mitre_techniques to tactic columns         │
│  ├─ Count rules per technique                                  │
│  ├─ Calculate per-tactic coverage %                            │
│  └─ Return: total covered, overall %, tactic breakdown         │
│                                                                │
│  identify_gaps(rules, actor_techniques) → GapAnalysis          │
│  ├─ Compare rule coverage to actor TTPs                        │
│  ├─ Identify uncovered techniques                              │
│  └─ Generate recommendations                                   │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 4.4 Simulation Engine Flow (Legacy v1 + Agent Tools)

```
User configures simulation (via UI canvas or agent tool):
  Products: [splunk, crowdstrike, okta]
  Target: http://target:8000/api/alerts/ingest/{token}
  Config: { events_per_minute: 5, severity_weights: {critical:10, high:30, ...} }
        │
        ▼
┌─ SimulationEngine ────────────────────────────────────────────┐
│                                                                │
│  1. create_session(config: SessionConfig)                      │
│     → Store session with products + targets                    │
│     → Validate target URLs (SSRF protection)                   │
│       ├─ Block private IPs: 10.x, 172.16-31.x, 192.168.x     │
│       ├─ Block localhost, 0.0.0.0, 169.254.x                  │
│       └─ Block file://, ftp:// schemes                        │
│                                                                │
│  2. start_session(session_id)                                  │
│     → For each product node:                                   │
│       ├─ Instantiate generator (e.g., SplunkGenerator)         │
│       ├─ Create APScheduler interval job                       │
│       └─ Schedule: call _send_event every (60/epm) seconds     │
│                                                                │
│  3. _send_event(session_id, product) — per interval tick       │
│     ├─ generator.generate_batch(count=1)                       │
│     │   ├─ _pick_severity() → weighted random                  │
│     │   ├─ _pick_ip/domain/hash/host/user/technique()          │
│     │   └─ Build vendor-specific payload (e.g., Splunk JSON)   │
│     ├─ POST payload to target_url via HTTPX                    │
│     ├─ Log: EventLog { timestamp, product, severity, status }  │
│     └─ Handle errors: log, continue running                    │
│                                                                │
│  4. stop_session(session_id)                                   │
│     → Shutdown APScheduler, clean up generators                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 4.5 Threat Intelligence Research Flow

```
Input: "Research APT28"
        │
        ▼
┌─ ThreatResearcher.research_actor("APT28") ────────────────────┐
│                                                                │
│  1. Check knowledge base cache (namespace: research_notes)     │
│                                                                │
│  2. MITREService.search_techniques() / get_all_groups()        │
│     ├─ Load STIX bundle (3 strategies):                        │
│     │   Strategy 1: mitreattack-python library                 │
│     │   Strategy 2: Bundled enterprise-attack.json             │
│     │   Strategy 3: Lightweight techniques_summary.json        │
│     ├─ Build in-memory indices:                                │
│     │   _techniques_by_id, _techniques_by_tactic               │
│     │   _groups_by_name, _groups_by_id                         │
│     └─ Return group data + associated techniques               │
│                                                                │
│  3. ActorService.research_actor("APT28")                       │
│     ├─ Search knowledge base for existing profile              │
│     ├─ Enrich with MITRE group data                            │
│     ├─ Extract TTPs with tactic mapping                        │
│     └─ Store/update in knowledge base                          │
│                                                                │
│  4. WebSearchSource.search() (if available)                    │
│     └─ Query web for recent APT28 activity                     │
│                                                                │
│  5. Assemble structured profile:                               │
│     { name, aliases, techniques[], tactics[],                  │
│       platforms[], description, sources[] }                    │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### 4.6 Knowledge Base Search Flow

```
Input: query="lateral movement detection", namespace="research_notes"
        │
        ▼
┌─ KnowledgeStore.search_knowledge(namespace, query, top_k) ────┐
│                                                                │
│  1. Map namespace → ChromaDB collection name                   │
│                                                                │
│  2. VectorStore.search(collection, query, top_k)               │
│     ├─ If ChromaDB available:                                  │
│     │   collection.query(query_texts=[query], n_results=top_k) │
│     │   → Returns documents + metadatas + distances            │
│     └─ If in-memory fallback:                                  │
│       Basic keyword matching on stored documents               │
│                                                                │
│  3. Return: [{ content, metadata, score }]                     │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## 5. Backend Module Reference

### 5.1 Entry Point & Configuration

| File | Status | Description |
|------|--------|-------------|
| `backend/main.py` | **BUILT** | FastAPI app, CORS, exception handler, router mounting, startup/shutdown |
| `backend/config.py` | **BUILT** | `Settings` class via pydantic-settings, all env vars |
| `backend/dependencies.py` | **PARTIAL** | DI providers — knowledge/MITRE/actors work; DB/Redis raise NotImplementedError |

**Settings available:**
```
DATABASE_URL, REDIS_URL, ANTHROPIC_API_KEY, OPENAI_API_KEY,
DEFAULT_MODEL, APP_NAME, DEBUG, CORS_ORIGINS, ENCRYPTION_KEY,
CELERY_BROKER_URL, CELERY_RESULT_BACKEND, CHROMA_PERSIST_DIR
```

### 5.2 Core Utilities (`backend/core/`)

| File | Status | Contents |
|------|--------|----------|
| `exceptions.py` | **BUILT** | `PurpleLabError` base + 6 subclasses (NotFoundError, ValidationError, SIEMConnectionError, AgentError, RateLimitError, EncryptionError) |
| `constants.py` | **BUILT** | `MITRE_TACTICS` (14), `SEVERITY_LEVELS` (5), `LOG_SOURCE_TYPES` (7+), `RULE_LANGUAGES` (5), `SIEM_PLATFORMS` (5), `DATA_MODELS` (3), `PRODUCT_CATEGORIES` (7) |
| `security.py` | **BUILT** | `encrypt_value()`, `decrypt_value()`, `generate_key()` — Fernet symmetric encryption |
| `schemas.py` | **BUILT** | 14 Pydantic v2 models: ChatRequest, ChatChunk, StatusResponse, EnvironmentCreate/Response, SIEMConnectionCreate/Response, RuleImportRequest/Response, ThreatActorResponse, TestRunCreate/Response, PaginatedResponse, ErrorResponse |

### 5.3 Database (`backend/db/`)

| File | Status | Contents |
|------|--------|----------|
| `models.py` | **BUILT** | 12 SQLAlchemy ORM models (see Section 7) |
| `session.py` | **BUILT** | `engine` (AsyncEngine), `async_session` (factory), `init_db()`, `close_db()` |

### 5.4 Agent System (`backend/agent/`)

See [Section 9](#9-agent-system-phase-4) for full details.

| File | Status | Key Classes/Functions |
|------|--------|----------------------|
| `orchestrator.py` | **BUILT** | `AgentOrchestrator` (ReAct loop, 15 rounds), `get_orchestrator()` singleton |
| `conversation.py` | **BUILT** | `ConversationManager` (in-memory, token budgeting, Anthropic format conversion) |
| `prompts.py` | **BUILT** | `build_system_prompt()`, `SYSTEM_PROMPT`, `TOOL_RESULT_PROMPT`, `CONVERSATION_SUMMARY_PROMPT` |
| `tool_registry.py` | **BUILT** | `ToolRegistry` (register, execute, list), `ToolDefinition` (to_anthropic_format) |
| `tools/__init__.py` | **BUILT** | `register_all_tools(registry)` — loads all 6 tool modules |
| `tools/threat_intel_tools.py` | **BUILT** | 4 tools: research_threat_actor, search_mitre_technique, list_threat_actors, get_threat_actor_ttps |
| `tools/rule_tools.py` | **BUILT** | 4 tools: import_detection_rules, parse_detection_rule, test_rules_against_logs, get_coverage_matrix |
| `tools/log_tools.py` | **BUILT** | 3 tools: generate_attack_logs, generate_sample_logs, list_available_generators |
| `tools/siem_tools.py` | **BUILT** (returns not_yet_implemented) | 3 tools: list_siem_connections, test_siem_connection, push_logs_to_siem |
| `tools/knowledge_tools.py` | **BUILT** | 3 tools: search_knowledge_base, save_to_knowledge_base, list_knowledge_namespaces |
| `tools/simulation_tools.py` | **BUILT** | 4 tools: start_simulation, stop_simulation, list_active_simulations, get_simulation_status |

### 5.5 Detection Engine (`backend/detection/`)

See [Section 10](#10-detection-engine-phase-3) for full details.

| File | Status | Key Classes/Functions |
|------|--------|----------------------|
| `parsers/base_parser.py` | **BUILT** | `Operator` (16 ops), `LogicOp`, `Condition`, `LogicGroup`, `Aggregation`, `ParsedRule`, `AbstractParser` |
| `parsers/sigma_parser.py` | **BUILT** | `SigmaParser` — Sigma YAML with field modifiers, condition expressions (627 lines) |
| `parsers/spl_parser.py` | **BUILT** | `SPLParser` — SPL search/where/stats/eval, pipe chains (710 lines) |
| `parsers/kql_parser.py` | **BUILT** | `KQLParser` — KQL where/summarize/extend (593 lines) |
| `parsers/esql_parser.py` | **BUILT** | `ESQLParser` — ES\|QL FROM/WHERE/STATS (514 lines) |
| `evaluator.py` | **BUILT** | `RuleEvaluator` — 16 operators, aggregations, dot notation, field mapping (619 lines) |
| `coverage.py` | **BUILT** | `CoverageAnalyzer` — `compute_coverage()`, `identify_gaps()`, `TechniqueCoverage`, `CoverageMatrix`, `GapAnalysis` |
| `rule_manager.py` | **BUILT** | `RuleManager` — `import_rules()`, `detect_language()`, `test_rules()`, `batch_evaluate()` |

### 5.6 Threat Intelligence (`backend/threat_intel/`)

| File | Status | Key Classes/Functions |
|------|--------|----------------------|
| `mitre_service.py` | **BUILT** | `MITREService` — load STIX, get techniques/groups, search, coverage matrix |
| `actor_service.py` | **BUILT** | `ActorService` — CRUD, research, enrich, get TTPs |
| `research.py` | **BUILT** | `ThreatResearcher` — multi-source research orchestrator (MITRE + web + knowledge) |
| `sources/mitre_attack.py` | **BUILT** | `MITREAttackSource` — 3-strategy STIX loader (library → bundled JSON → summary) |
| `sources/web_search.py` | **STUB** | `WebSearchSource` — expected to use httpx for real web search |

### 5.7 Knowledge Base (`backend/knowledge/`)

| File | Status | Key Classes/Functions |
|------|--------|----------------------|
| `store.py` | **BUILT** | `KnowledgeStore` — unified interface: store, search, get, delete, index_document, get_stats |
| `vector_store.py` | **BUILT** | `VectorStore` — ChromaDB PersistentClient wrapper with in-memory dict fallback |
| `embeddings.py` | **STUB** | `EmbeddingModel` — expected: OpenAI → sentence-transformers → hash fallback |

### 5.8 Simulation Engine (`backend/engine/`)

| File | Status | Key Classes/Functions |
|------|--------|----------------------|
| `engine.py` | **BUILT** | `SimulationEngine` — session CRUD, start/stop, _send_event, preview, SSRF validation |
| `scheduler.py` | **BUILT** | `EventScheduler` — APScheduler wrapper, per-session interval jobs |
| `generators/base.py` | **BUILT** | `BaseGenerator` (ABC), `GeneratorConfig` (Pydantic), data pools (IPs, domains, hashes, techniques) |
| `generators/*.py` | **BUILT** (12 files) | Splunk, CrowdStrike, Sentinel, Okta, Proofpoint, ServiceNow, CarbonBlack, Defender, EntraID, QRadar, Elastic, GuardDuty |

### 5.9 Log Sources (`backend/log_sources/`) — STUBS

| File | Status | Description |
|------|--------|-------------|
| `base_log_source.py` | **BUILT** | `AbstractLogSource` ABC with generate(), generate_batch(), get_schema() |
| `noise_generator.py` | **STUB** | `NoiseGenerator` — background noise with configurable SNR |
| `sources/windows_eventlog.py` | **NOT BUILT** | Windows Event IDs: 4624, 4625, 4688, 4720, 7045 |
| `sources/sysmon.py` | **NOT BUILT** | Sysmon Event IDs: 1, 3, 7, 11, 22 |
| `sources/linux_audit.py` | **NOT BUILT** | auditd: execve, connect, open |
| `sources/firewall.py` | **NOT BUILT** | Palo Alto, Fortinet formats |
| `sources/dns.py` | **NOT BUILT** | DNS queries, NXDOMAIN, C2 patterns |
| `sources/cloud_trail.py` | **NOT BUILT** | AWS CloudTrail JSON |

### 5.10 SIEM Integration (`backend/siem_integration/`) — STUBS

| File | Status | Description |
|------|--------|-------------|
| `connection_manager.py` | **STUB** | All methods raise NotImplementedError |
| `connectors/splunk_connector.py` | **NOT BUILT** | REST API + HEC |
| `connectors/sentinel_connector.py` | **NOT BUILT** | Azure AD OAuth2 + Data Collector API |
| `connectors/elastic_connector.py` | **NOT BUILT** | API key + _bulk API |
| `data_models/cim.py` | **NOT BUILT** | Splunk CIM field mappings |
| `data_models/asim.py` | **NOT BUILT** | Sentinel ASIM field mappings |
| `data_models/ecs.py` | **NOT BUILT** | Elastic ECS field mappings |

### 5.11 Environments (`backend/environments/`) — STUBS

| File | Status | Description |
|------|--------|-------------|
| `environment_service.py` | **STUB** | All methods raise NotImplementedError |
| `templates.py` | **NOT BUILT** | Pre-built environment configs |

---

## 6. Frontend Module Reference

### 6.1 Next.js Frontend (`frontend-next/`)

**Stack:** Next.js 15, React 19, TypeScript, Tailwind 4, Zustand 5, React Flow 12.4, Monaco Editor 4.7

#### Pages (9 routes)

| Route | File | Status | Description |
|-------|------|--------|-------------|
| `/` | `app/page.tsx` | **SCAFFOLD** | Dashboard with hardcoded stat cards, quick actions |
| `/chat` | `app/chat/page.tsx` | **SCAFFOLD** | Chat UI with conversation sidebar, message bubbles, tool call cards — **NOT wired to SSE backend** (uses setTimeout placeholder) |
| `/environments` | `app/environments/page.tsx` | **BUILT** | Environment list with create dialog, Zustand-only storage |
| `/environments/[id]` | `app/environments/[id]/page.tsx` | **BUILT** | React Flow canvas with 5 node types, drag-and-drop, properties panel — **no persistence** |
| `/rules` | `app/rules/page.tsx` | **BUILT** | Rule list with import (file reader), filters (language/severity), Zustand-only |
| `/rules/[id]` | `app/rules/[id]/page.tsx` | **BUILT** | Monaco editor (read-only) + test button — **placeholder test results** |
| `/reports` | `app/reports/page.tsx` | **BUILT** | Test run cards with coverage % — **no real data** |
| `/threat-intel` | `app/threat-intel/page.tsx` | **SCAFFOLD** | MITRE ATT&CK navigator matrix — **hardcoded 50 techniques** |
| `/settings` | `app/settings/page.tsx` | **BUILT** | SIEM connections, API keys, model routing, automation level — **no persistence** |

#### Components

| Component | File | Status |
|-----------|------|--------|
| `Sidebar` | `components/sidebar.tsx` | **BUILT** — Collapsible nav, 6 menu items, active highlighting |
| `Badge` | `components/ui/badge.tsx` | **BUILT** — 6 variants |
| `Button` | `components/ui/button.tsx` | **BUILT** — 5 variants, 4 sizes |
| `Card` | `components/ui/card.tsx` | **BUILT** — Card, Header, Title, Description, Content, Footer |
| `Dialog` | `components/ui/dialog.tsx` | **BUILT** — Modal overlay, ESC close |
| `Input` | `components/ui/input.tsx` | **BUILT** |
| `ScrollArea` | `components/ui/scroll-area.tsx` | **BUILT** — Simple overflow wrapper |
| `Separator` | `components/ui/separator.tsx` | **BUILT** — Horizontal/vertical |
| `Tabs` | `components/ui/tabs.tsx` | **BUILT** — Context-based tab system |

#### Stores (5 Zustand stores)

| Store | File | State | Actions |
|-------|------|-------|---------|
| `useChatStore` | `stores/chat.ts` | conversations[], activeConversationId, isStreaming | setConversations, addConversation, addMessage, appendToLastMessage, setStreaming |
| `useEnvironmentStore` | `stores/environment.ts` | environments[], activeEnvironmentId, selectedNodeId | CRUD + node operations (add, update, remove) |
| `useRulesStore` | `stores/rules.ts` | rules[], testRuns[], activeRuleId | setRules, addRule, setTestRuns, addTestRun |
| `useThreatIntelStore` | `stores/threat-intel.ts` | actors[], techniques[], selectedActorId, selectedTechniqueId | setActors, setTechniques, setSelectedActor/Technique |
| `useUIStore` | `stores/ui.ts` | sidebarCollapsed | toggleSidebar, setSidebarCollapsed |

#### Libraries

| File | Status | Functions |
|------|--------|-----------|
| `lib/api.ts` | **BUILT** | `ApiError`, `apiGet()`, `apiPost()`, `apiPut()`, `apiDelete()` — fetch wrapper with error handling |
| `lib/sse.ts` | **BUILT** | `createSSEStream()` — POST-based SSE client with abort controller |
| `lib/utils.ts` | **BUILT** | `cn()` — clsx + tailwind-merge |

#### Types (`types/index.ts`)

15+ TypeScript interfaces: Message, ToolCall, Conversation, EnvironmentNode, Environment, ImportedRule, ParsedRule, EvalResult, TestRun, MITRETechnique, ThreatActor, SIEMConnection, ChatRequest, ChatEvent, CatalogProduct

### 6.2 Legacy Frontend (`frontend/`)

| File | Status | Description |
|------|--------|-------------|
| `index.html` | **BUILT** | 403-line vanilla HTML/CSS/JS — drag-and-drop canvas, session management, event polling. **Fully functional** with v1 API. |

---

## 7. Data Models & Database

### 7.1 SQLAlchemy ORM Models (12 tables)

```
┌─────────────┐     ┌──────────┐
│ Conversation │────<│ Message  │
│              │     │          │
│ id (UUID PK) │     │ id       │
│ title        │     │ conv_id  │
│ environment_id│     │ role     │
│ created_at   │     │ content  │
│ updated_at   │     │ tool_calls (JSON) │
└──────────────┘     │ tool_results (JSON)│
                     │ metadata (JSON)    │
                     └──────────┘

┌─────────────┐     ┌────────────────┐
│ Environment  │────<│ SIEMConnection │
│              │     │                │
│ id (UUID PK) │     │ id             │
│ name         │     │ environment_id │
│ description  │     │ name           │
│ siem_platform│     │ siem_type      │
│ log_sources  │     │ base_url       │
│ (JSON)       │     │ encrypted_creds│
│ settings     │     │ is_connected   │
│ (JSON)       │     │ last_sync_at   │
└──────────────┘     └────────────────┘

┌──────────────┐     ┌────────────────┐
│ ImportedRule  │     │ ThreatActor    │
│              │     │                │
│ id (UUID PK) │     │ id (UUID PK)   │
│ environment_id│     │ name           │
│ name         │     │ aliases (JSON) │
│ language     │     │ description    │
│ source_query │     │ mitre_groups   │
│ severity     │     │ techniques     │
│ mitre_techniques│  │ ttps (JSON)    │
│ (JSON)       │     │ source         │
│ enabled      │     └────────────────┘
│ metadata     │
│ (JSON)       │     ┌────────────────┐
└──────────────┘     │ MITRETechnique │
                     │                │
                     │ id (UUID PK)   │
                     │ technique_id   │
                     │ name           │
                     │ tactic         │
                     │ description    │
                     │ platforms (JSON)│
                     │ data_sources   │
                     │ detection_guidance│
                     └────────────────┘

┌───────────────┐    ┌────────────────┐
│ TestRun       │───<│ RuleTestResult │
│               │    │                │
│ id (UUID PK)  │    │ id (UUID PK)   │
│ environment_id│    │ test_run_id    │
│ status        │    │ rule_id        │
│ total_rules   │    │ passed         │
│ rules_passed  │    │ matched_events │
│ rules_failed  │    │ false_positives│
│ coverage_pct  │    │ exec_time_ms   │
│ config (JSON) │    │ details (JSON) │
└───────────────┘    └────────────────┘

┌──────────────────┐  ┌────────────────┐  ┌────────────────┐
│ SimulationSession│─<│ GeneratedEvent │  │ LogSourceSchema│
│                  │  │                │  │                │
│ id (UUID PK)     │  │ id (UUID PK)   │  │ id (UUID PK)   │
│ name             │  │ session_id     │  │ name           │
│ config (JSON)    │  │ product_type   │  │ source_type    │
│ status           │  │ severity       │  │ schema_def     │
│ events_sent      │  │ title          │  │ (JSON)         │
│ errors           │  │ payload (JSON) │  │ sample_event   │
│ last_event_at    │  │ target_url     │  │ (JSON)         │
└──────────────────┘  │ status_code    │  │ description    │
                      │ success        │  └────────────────┘
                      └────────────────┘
```

### 7.2 Database Status

| Aspect | Status |
|--------|--------|
| Models defined | **DONE** — 12 tables |
| Alembic initial migration | **DONE** |
| Async session factory | **DONE** |
| DI wiring (get_db) | **NOT DONE** — raises NotImplementedError |
| Actual DB reads/writes from API | **NOT DONE** — APIs use in-memory storage |

---

## 8. API Endpoint Reference

### 8.1 Legacy v1 API (`/api/`)

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/catalog` | **BUILT** | List 12 product generators |
| GET | `/api/sessions` | **BUILT** | List simulation sessions |
| POST | `/api/sessions` | **BUILT** | Create session |
| GET | `/api/sessions/{id}` | **BUILT** | Get session details |
| PUT | `/api/sessions/{id}` | **BUILT** | Update session config |
| DELETE | `/api/sessions/{id}` | **BUILT** | Delete session |
| POST | `/api/sessions/{id}/start` | **BUILT** | Start event generation |
| POST | `/api/sessions/{id}/stop` | **BUILT** | Stop event generation |
| GET | `/api/sessions/{id}/events` | **BUILT** | Get event log (paginated) |
| GET | `/api/events` | **BUILT** | Get all events |
| GET | `/api/preview/{product_type}` | **BUILT** | Preview sample event |

### 8.2 v2 API (`/api/v2/`)

#### Chat

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| POST | `/api/v2/chat` | **BUILT** | SSE streaming agentic response |
| GET | `/api/v2/chat/conversations` | **BUILT** | List conversations (in-memory) |
| GET | `/api/v2/chat/conversations/{id}` | **BUILT** | Get conversation + messages |
| DELETE | `/api/v2/chat/conversations/{id}` | **BUILT** | Delete conversation |

#### Rules

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/v2/rules` | **BUILT** | List rules (filter: language, severity, technique) |
| POST | `/api/v2/rules/import` | **BUILT** | Import rules from text |
| GET | `/api/v2/rules/{id}` | **BUILT** | Get rule details |
| PUT | `/api/v2/rules/{id}` | **BUILT** | Update rule metadata |
| DELETE | `/api/v2/rules/{id}` | **BUILT** | Delete rule |
| POST | `/api/v2/rules/test` | **BUILT** | Test rules against logs |
| GET | `/api/v2/rules/test/{id}` | **BUILT** | Get test run results |
| POST | `/api/v2/rules/coverage` | **BUILT** | MITRE coverage analysis |
| POST | `/api/v2/rules/detect-language` | **BUILT** | Auto-detect rule language |

#### Threat Intelligence

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/v2/threat-intel/actors` | **BUILT** | List actors |
| GET | `/api/v2/threat-intel/actors/{id}` | **BUILT** | Get actor profile |
| POST | `/api/v2/threat-intel/actors` | **BUILT** | Create actor |
| POST | `/api/v2/threat-intel/actors/research` | **BUILT** | Research actor |
| GET | `/api/v2/threat-intel/actors/{id}/ttps` | **BUILT** | Get actor TTPs |
| GET | `/api/v2/threat-intel/techniques` | **BUILT** | List techniques |
| GET | `/api/v2/threat-intel/techniques/{id}` | **BUILT** | Get technique |
| GET | `/api/v2/threat-intel/groups` | **BUILT** | List MITRE groups |
| GET | `/api/v2/threat-intel/coverage` | **BUILT** | Coverage matrix |
| POST | `/api/v2/threat-intel/research/topic` | **BUILT** | Research topic |
| POST | `/api/v2/threat-intel/research/technique/{id}` | **BUILT** | Research technique |

#### Knowledge

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/v2/knowledge/search` | **BUILT** | Semantic search |
| POST | `/api/v2/knowledge/index` | **BUILT** | Index document |
| GET | `/api/v2/knowledge/stats` | **BUILT** | Collection stats |

#### Sessions (v2)

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/v2/sessions` | **STUB** | List sessions (TODO: DB query) |
| POST | `/api/v2/sessions` | **STUB** | Create session |
| GET | `/api/v2/sessions/{id}` | **STUB** | Get session |
| PUT | `/api/v2/sessions/{id}` | **STUB** | Update session |
| DELETE | `/api/v2/sessions/{id}` | **STUB** | Delete session |
| POST | `/api/v2/sessions/{id}/start` | **STUB** | Start session |
| POST | `/api/v2/sessions/{id}/stop` | **STUB** | Stop session |

#### Environments

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/v2/environments` | **STUB** | List environments |
| POST | `/api/v2/environments` | **STUB** | Create environment |
| GET | `/api/v2/environments/{id}` | **STUB** | Get environment |
| PUT | `/api/v2/environments/{id}` | **STUB** | Update environment |
| DELETE | `/api/v2/environments/{id}` | **STUB** | Delete environment |

#### SIEM

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/v2/siem/connections` | **STUB** | List connections |
| POST | `/api/v2/siem/connections` | **STUB** | Create connection |
| GET | `/api/v2/siem/connections/{id}` | **STUB** | Get connection |
| PUT | `/api/v2/siem/connections/{id}` | **STUB** | Update connection |
| DELETE | `/api/v2/siem/connections/{id}` | **STUB** | Delete connection |
| POST | `/api/v2/siem/connections/{id}/test` | **STUB** | Test connectivity |
| POST | `/api/v2/siem/connections/{id}/sync-rules` | **STUB** | Pull rules from SIEM |

#### Log Sources

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| GET | `/api/v2/log-sources/types` | **BUILT** | List log source types |
| GET | `/api/v2/log-sources/schemas` | **STUB** | List schemas |
| POST | `/api/v2/log-sources/generate` | **STUB** | Generate logs |
| POST | `/api/v2/log-sources/generate-batch` | **STUB** | Batch generation |

---

## 9. Agent System (Phase 4)

### 9.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  AgentOrchestrator (Singleton)                               │
│                                                              │
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ AsyncAnthropic  │  │ ConversationMgr │  │ ToolRegistry │ │
│  │ (Claude API)    │  │ (History)       │  │ (21 Tools)   │ │
│  └───────┬────────┘  └───────┬─────────┘  └──────┬───────┘ │
│          │                   │                    │          │
│          └───────────┬───────┘────────────────────┘          │
│                      │                                       │
│              ReAct Loop (max 15 rounds)                       │
│              ├── Call Claude with tools                       │
│              ├── Execute tool_use blocks                      │
│              ├── Feed tool_results back                       │
│              └── Repeat until end_turn                        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 9.2 Registered Tools (21 total)

| Module | Tool Name | Parameters | What It Does |
|--------|-----------|------------|-------------|
| **Threat Intel** | `research_threat_actor` | name: str | Research actor via MITRE + knowledge base |
| | `search_mitre_technique` | query: str | Search techniques by keyword or ID |
| | `list_threat_actors` | search?: str | List known actors |
| | `get_threat_actor_ttps` | actor_name: str | Get TTPs for actor |
| **Rules** | `import_detection_rules` | rules_text: str, language: str | Parse Sigma/SPL/KQL/ES\|QL rules |
| | `parse_detection_rule` | rule_text: str | Auto-detect language + parse |
| | `test_rules_against_logs` | rule_ids: list, logs: list | Evaluate rules against data |
| | `get_coverage_matrix` | technique_ids: list | MITRE coverage analysis |
| **Logs** | `generate_attack_logs` | technique: str, source_type: str, count: int | Generate malicious events |
| | `generate_sample_logs` | source_type: str, count: int | Generate mixed events |
| | `list_available_generators` | (none) | List all generators |
| **SIEM** | `list_siem_connections` | (none) | List connections (stub) |
| | `test_siem_connection` | connection_id: str | Test connectivity (stub) |
| | `push_logs_to_siem` | connection_id: str, logs: list | Push logs (stub) |
| **Knowledge** | `search_knowledge_base` | query: str, namespace: str | Semantic search |
| | `save_to_knowledge_base` | namespace: str, key: str, content: str | Store knowledge |
| | `list_knowledge_namespaces` | (none) | List collections |
| **Simulation** | `start_simulation` | products: list, target_url?: str, config?: dict | Start event generation |
| | `stop_simulation` | session_id: str | Stop session |
| | `list_active_simulations` | (none) | List running sessions |
| | `get_simulation_status` | session_id: str | Get session details |

### 9.3 Conversation Management

```
ConversationManager
│
├── Storage: In-memory dict { conv_id → {messages[], created_at, title} }
│
├── Message format (internal):
│   { role, content, tool_calls?, tool_results?, timestamp }
│
├── get_anthropic_messages() → Converts to API format:
│   ├── User message:     {"role": "user", "content": "text"}
│   ├── Assistant + tools: {"role": "assistant", "content": [
│   │                        {"type": "text", "text": "..."},
│   │                        {"type": "tool_use", "id": "...", "name": "...", "input": {...}}
│   │                      ]}
│   └── Tool results:     {"role": "user", "content": [
│                            {"type": "tool_result", "tool_use_id": "...", "content": "..."}
│                          ]}
│
├── trim_to_budget(budget=30000):
│   ├── Estimate tokens: len(json(messages)) / 4
│   ├── Keep first message (system context)
│   ├── Remove tool_call + tool_result pairs together
│   └── Trim from oldest until under budget
│
└── NOT YET: Database persistence (Conversation + Message models exist but aren't wired)
```

### 9.4 System Prompt Assembly

```
build_system_prompt(environment_context, available_tools, rag_context)
│
├── Section 1: Base Identity
│   "You are PurpleLab, an expert cybersecurity simulation assistant..."
│   - Simulate attacks, test rules, research threats, build environments, analyze coverage
│
├── Section 2: Available Tools (dynamic)
│   "You have the following tools available:"
│   - Lists all registered tool names + descriptions
│
├── Section 3: Environment Context (if provided)
│   "Current environment: {env_context}"
│
└── Section 4: RAG Context (if provided)
    "Relevant knowledge: {rag_context}"
```

---

## 10. Detection Engine (Phase 3)

### 10.1 Unified AST

```
ParsedRule
├── source_language: str (sigma | spl | kql | esql)
├── raw_text: str
├── name: str
├── description: str
├── severity: str
├── mitre_techniques: list[str]  (e.g., ["T1059.001", "T1547"])
├── filter: LogicGroup           ← The detection logic tree
│   ├── operator: LogicOp (AND | OR | NOT)
│   └── children: list[Condition | LogicGroup]  ← Recursive
│       └── Condition
│           ├── field: str        (e.g., "process.name")
│           ├── operator: Operator (eq, contains, wildcard, etc.)
│           ├── value: Any
│           └── case_insensitive: bool
├── aggregation: Aggregation?
│   ├── function: str (count | sum | avg | min | max | distinct_count)
│   ├── field: str?
│   ├── group_by: list[str]
│   └── condition: Condition (threshold check)
├── referenced_fields: list[str]
├── data_sources: list[str]
└── tags: list[str]
```

### 10.2 Parser Support Matrix

| Feature | Sigma | SPL | KQL | ES\|QL |
|---------|-------|-----|-----|--------|
| Basic conditions | Yes | Yes | Yes | Yes |
| AND/OR/NOT logic | Yes | Yes | Yes | Yes |
| Wildcard matching | Yes | Yes | Yes | Yes |
| Field modifiers | Yes (contains, startswith, endswith, re, all, base64) | N/A | N/A | N/A |
| Pipe chains | N/A | Yes (search\|where\|stats\|eval) | Yes (where\|summarize\|extend) | Yes (FROM\|WHERE\|STATS) |
| Aggregations | Via condition | stats count/sum/avg | summarize count/sum | STATS count/sum |
| MITRE extraction | From tags | From comments | From comments | From comments |
| Multi-doc support | Yes (YAML ---) | Yes (double newline) | No | No |

### 10.3 Evaluator Operators (16)

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Exact match | field == "value" |
| `neq` | Not equal | field != "value" |
| `contains` | Substring match | "cmd" in field |
| `startswith` | Prefix match | field starts with "/tmp" |
| `endswith` | Suffix match | field ends with ".exe" |
| `regex` | Regex match | field matches pattern |
| `gt` / `gte` | Greater than (or equal) | field > 100 |
| `lt` / `lte` | Less than (or equal) | field < 50 |
| `in` / `not_in` | List membership | field in ["a","b","c"] |
| `exists` / `not_exists` | Field presence | field exists |
| `wildcard` | Glob pattern (* ?) | field matches "*.exe" |

---

## 11. Simulation Engine

### 11.1 Product Generators (12)

| Generator | Category | Payload Format | Key Fields |
|-----------|----------|---------------|------------|
| `SplunkGenerator` | SIEM | Webhook alert JSON | search_name, urgency, results |
| `SentinelGenerator` | SIEM | Alert webhook | AlertDisplayName, AlertSeverity |
| `QRadarGenerator` | SIEM | Offense notification | offense_name, magnitude |
| `ElasticGenerator` | SIEM | Alert webhook | rule.name, kibana.alert.severity |
| `CrowdStrikeGenerator` | EDR | Detection API | ProcessRollup2, DNS, Network |
| `CarbonBlackGenerator` | EDR | Alert webhook | WATCHLIST, CB_ANALYTICS |
| `DefenderEndpointGenerator` | EDR | Alert API | Informational → High |
| `OktaGenerator` | ITDR | System Log | auth, MFA, account lock |
| `EntraIDGenerator` | ITDR | Sign-in/audit | risky sign-in, MFA registration |
| `ProofpointGenerator` | Email | TAP clicks/messages | phishing, malware, BEC |
| `ServiceNowGenerator` | ITSM | Incident REST API | create, update, resolve |
| `GuardDutyGenerator` | Cloud | Finding format | recon, trojan, exfil |

### 11.2 SSRF Protection

```
validate_target_url(url) blocks:
├── Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
├── Loopback: 127.0.0.0/8, localhost, [::1]
├── Link-local: 169.254.0.0/16
├── Null: 0.0.0.0
└── Non-HTTP schemes: file://, ftp://, etc.
```

---

## 12. Threat Intelligence

### 12.1 MITRE ATT&CK Data Loading (3 strategies)

```
Priority order:
1. mitreattack-python library (richest data, needs install)
2. Bundled STIX JSON at data/mitre_attack/enterprise-attack.json
3. Lightweight techniques_summary.json (seeded by scripts/seed_mitre.py)
```

### 12.2 Services

| Service | Key Methods | Storage |
|---------|-------------|---------|
| `MITREService` | load_attack_data, get_all_techniques, search_techniques, get_coverage_matrix | In-memory indices |
| `ActorService` | get_actor, list_actors, create_actor, research_actor, get_actor_ttps | Knowledge base (ChromaDB) |
| `ThreatResearcher` | research_topic, research_actor, research_technique | Knowledge base cache |

---

## 13. Knowledge Base

### 13.1 Architecture

```
KnowledgeStore (unified interface)
      │
      ▼
VectorStore (ChromaDB wrapper)
      │
      ├─ ChromaDB PersistentClient (if available)
      │   └─ Collections: threat_actors, detection_rules, log_schemas,
      │                   siem_configs, research_notes
      │
      └─ In-memory dict fallback (if ChromaDB unavailable)
          └─ Basic keyword matching
```

### 13.2 Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Store | `store_knowledge(namespace, key, content, metadata)` | Embed + store in ChromaDB collection |
| Search | `search_knowledge(namespace, query, top_k)` | Semantic similarity search |
| Get | `get_knowledge(namespace, key)` | Direct key lookup |
| Delete | `delete_knowledge(namespace, key)` | Remove from collection |
| Index | `index_document(content, metadata, source)` | General document indexing |
| Stats | `get_stats()` | Collection counts |

---

## 14. Infrastructure & DevOps

### 14.1 Docker

```yaml
# docker-compose.yml — 3 services
purplelab-api:    Python 3.12-slim, port 4000, healthcheck: GET /api/catalog
purplelab-db:     PostgreSQL 17-alpine, port 5433, healthcheck: pg_isready
purplelab-redis:  Redis 7.4-alpine, port 6380, healthcheck: redis-cli ping
```

### 14.2 Master Script (`purplelab.sh`)

Commands: `up`, `down`, `status`, `test`, `migrate`, `seed`, `frontend`, `backup`, `restore`, `reset-password`, `heal`

### 14.3 Database Migrations

```
alembic/
├── env.py          (async SQLAlchemy, target: db.models.Base)
├── versions/
│   └── 001_initial.py  (creates all 12 tables)
└── alembic.ini     (DATABASE_URL from settings)
```

---

## 15. Testing

### 15.1 Test Infrastructure

| File | Description |
|------|-------------|
| `pytest.ini` | testpaths=tests, asyncio_mode=auto, markers: unit/integration/security/slow |
| `tests/conftest.py` | 12 generator fixtures, engine fixture, session config fixture, FastAPI test clients |

### 15.2 Test Coverage

| Category | Files | Tests | Status |
|----------|-------|-------|--------|
| Unit — Generators | 12 files (1 per vendor) | ~36 | **PASSING** |
| Unit — Engine | `test_engine.py` (314 lines) | 28 | **PASSING** |
| Unit — Scenarios | `test_scenarios.py` | 11 | **PASSING** |
| Unit — Detection | `test_detection_engine.py` (579 lines) | 45 | **PASSING** |
| Integration — Legacy API | `test_api_legacy.py` | ~12 | **PASSING** |
| Integration — v2 API | `test_api_v2_stubs.py` | ~10 | **PASSING** |
| Integration — Lifecycle | `test_session_lifecycle.py` | ~5 | **PASSING** |
| Security — Auth | `test_auth.py` | ~3 | **PASSING** |
| Security — CORS | `test_cors.py` | ~3 | **PASSING** |
| Security — Input validation | `test_input_validation.py` | ~22 | **PASSING** |
| **Total** | **28 files** | **~175** | **ALL PASSING** |

---

## 16. Implementation Status Matrix

### By Component

| Component | Built | Stub | Not Built | Notes |
|-----------|-------|------|-----------|-------|
| **Agent Orchestrator** | 100% | 0% | 0% | Full ReAct loop with 21 tools |
| **Detection Engine** | 100% | 0% | 0% | 4 parsers + evaluator + coverage |
| **Simulation Engine** | 90% | 10% | 0% | 12 generators work; sessions in-memory only |
| **Threat Intelligence** | 85% | 15% | 0% | MITRE + actors work; web search is stub |
| **Knowledge Base** | 80% | 20% | 0% | ChromaDB works; embeddings stub |
| **API v1 (Legacy)** | 100% | 0% | 0% | All 11 endpoints functional |
| **API v2 — Chat** | 100% | 0% | 0% | SSE streaming, conversation CRUD |
| **API v2 — Rules** | 100% | 0% | 0% | Import, test, coverage, detect language |
| **API v2 — Threat Intel** | 100% | 0% | 0% | Actors, techniques, research |
| **API v2 — Knowledge** | 100% | 0% | 0% | Search, index, stats |
| **API v2 — Sessions** | 0% | 100% | 0% | All endpoints return placeholder |
| **API v2 — Environments** | 0% | 100% | 0% | All endpoints return placeholder |
| **API v2 — SIEM** | 0% | 100% | 0% | All endpoints return placeholder |
| **API v2 — Log Sources** | 10% | 90% | 0% | Only types listing works |
| **Log Source Generators** | 5% | 5% | 90% | Only base ABC + noise stub exist |
| **SIEM Connectors** | 0% | 5% | 95% | ConnectionManager stub only |
| **Data Model Converters** | 0% | 0% | 100% | CIM/ASIM/ECS not started |
| **Environment Service** | 0% | 100% | 0% | Service stub exists |
| **Database Persistence** | 0% | 0% | 100% | Models defined, not wired to API |
| **Frontend — UI Shell** | 100% | 0% | 0% | All 9 pages, 9 components, 5 stores |
| **Frontend — Backend Wiring** | 5% | 0% | 95% | Only API client + SSE client exist |
| **Tests** | 100% | 0% | 0% | ~175 tests, all passing |
| **Docker/DevOps** | 100% | 0% | 0% | Compose, Dockerfile, purplelab.sh |

### By Phase

| Phase | Description | Status | Completion |
|-------|-------------|--------|------------|
| **Phase 1** | Foundation (FastAPI, DB models, config, Docker) | **DONE** | 100% |
| **Phase 2** | Knowledge Base + Threat Intel | **DONE** | 90% (web search stub) |
| **Phase 3** | Detection Rule Engine | **DONE** | 100% |
| **Phase 4** | Agentic Core | **DONE** | 95% (DB persistence pending) |
| **Phase 5** | Log Source Simulators | **NOT STARTED** | 5% (base ABC only) |
| **Phase 6** | SIEM Integration | **NOT STARTED** | 2% (stub only) |
| **Phase 7** | Environment Builder + Reports | **NOT STARTED** | 5% (UI scaffold only) |
| **Phase 8** | Hardening (auth, rate limit, CI/CD) | **NOT STARTED** | 0% |

---

## 17. Not Yet Built

### Critical Path (blocks real-world usage)

1. **Database Persistence** — API endpoints use in-memory storage; all data lost on restart
   - Wire `get_db()` in `dependencies.py`
   - Update all v2 endpoints to use SQLAlchemy queries
   - Wire conversation persistence for agent chat

2. **Log Source Generators** (Phase 5) — Needed for realistic detection testing
   - Windows EventLog (4624, 4625, 4688, 4720, 7045)
   - Sysmon (ProcessCreate, NetworkConnect, DNSQuery)
   - Linux audit, firewall, DNS, CloudTrail
   - Noise generator with configurable SNR
   - Attack fingerprint system

3. **Frontend ↔ Backend Wiring** — UI is a shell with placeholder data
   - Chat page needs real SSE connection to `/api/v2/chat`
   - All pages need to fetch/persist via API
   - Settings page needs to save to backend

### Important but Not Blocking

4. **SIEM Connectors** (Phase 6) — Splunk, Sentinel, Elastic
5. **Data Model Converters** — CIM, ASIM, ECS field mappings
6. **Environment Service** — CRUD with templates
7. **Web Search Source** — Real web search for threat research
8. **Embedding Model** — Proper embedding chain (OpenAI → sentence-transformers)

### Hardening (Later)

9. Authentication (API key middleware)
10. Rate limiting
11. CI/CD pipeline (GitHub Actions)
12. Structured logging + OpenTelemetry
13. HITL workflow
14. Report export (PDF/HTML/CSV)

---

*This document should be updated whenever significant implementation work is completed.*
