# Joti Sim v2 — Research: Novel Technology, Stack Validation & Patentable Innovations

**Research Date:** 2026-03-28
**Researcher:** Claude Opus 4.6 (Agentic Research Agent)
**Status:** DRAFT — Web search was unavailable; findings based on training data through mid-2025. Items marked [VERIFY] require live confirmation against package registries.

---

## Table of Contents

1. [Task 1: Tech Stack Validation](#task-1-tech-stack-validation)
2. [Task 2: Novel Patentable Technology Approaches](#task-2-novel-patentable-technology-approaches)
3. [Task 3: Admin AI Freedom Architecture](#task-3-admin-ai-freedom-architecture)
4. [Competitor Landscape](#competitor-landscape)
5. [Recommended Actions](#recommended-actions)

---

## Task 1: Tech Stack Validation

> Note: Network access was restricted during research. Version numbers are based on training data through mid-2025. All items marked [VERIFY] should be confirmed against live registries before finalizing.

### Frontend Stack

#### Next.js

| Attribute | Detail |
|-----------|--------|
| **Planned** | 15.x |
| **Known Latest** | 15.x (stable as of mid-2025) [VERIFY for 15.1+/16.x] |
| **Security Notes** | Next.js 14.x had CVE-2024-34351 (SSRF via Server Actions) and CVE-2024-46982 (cache poisoning). Both patched in 14.1.1+. Next.js 15 addressed middleware auth bypass (CVE-2025-29927) in 15.2.3. Always pin to latest patch. |
| **Recommendation** | **Use Next.js 15.x latest patch.** Enable Strict CSP headers via `next.config.js`. Check for any 15.3+ or 16.x release. If Next.js 16 is available, evaluate its stability before adoption. |
| **Alternatives** | Remix/React Router v7 (merged), Nuxt 4 (Vue), SvelteKit 2. Next.js remains the strongest choice for React-based enterprise apps. |

#### React Flow (@xyflow/react)

| Attribute | Detail |
|-----------|--------|
| **Planned** | 12.x |
| **Known Latest** | 12.x (rebranded as @xyflow/react) [VERIFY] |
| **Security Notes** | No known CVEs. Pure client-side rendering library — attack surface is minimal. |
| **Recommendation** | **Use @xyflow/react 12.x.** It is the gold standard for node-based graph UIs in React. |
| **Alternatives** | Rete.js (v2, visual programming focus), Flume (simpler), G6/X6 (AntV, heavier). React Flow/xyflow remains the best choice for drag-and-drop canvas UIs with custom nodes. |
| **Why React Flow wins** | Largest community, best TypeScript support, most flexible custom node system, sub-components for minimap/controls/background. Perfect for our simulator canvas. |

#### Tailwind CSS

| Attribute | Detail |
|-----------|--------|
| **Planned** | 4.x |
| **Known Latest** | 4.0 released Jan 2025, 4.1 released March 2025 [VERIFY for 4.2+] |
| **Key Changes in v4** | New Oxide engine (Rust-based, 5-10x faster), CSS-first configuration (replaces `tailwind.config.js`), native `@theme` directive, automatic content detection, zero-config. |
| **Security Notes** | No CVEs — CSS framework with no runtime. |
| **Recommendation** | **Use Tailwind CSS 4.x latest.** The Oxide engine is a major perf win for large projects. |

#### shadcn/ui

| Attribute | Detail |
|-----------|--------|
| **Planned** | Latest |
| **Known Latest** | Not versioned traditionally — it's a copy-paste component library. Continuously updated. [VERIFY] |
| **Key Features** | Radix UI primitives, fully accessible, copy-into-project model (no dependency lock-in), works with Tailwind 4. |
| **Security Notes** | No supply-chain risk since components are copied, not installed as dependency. This is a security advantage. |
| **Recommendation** | **Use shadcn/ui.** The copy-paste model eliminates dependency supply-chain attacks. |
| **Alternatives** | Radix Themes (opinionated), Ark UI (framework-agnostic), Park UI (Ark-based), NextUI v2, MUI v6. shadcn/ui is the best fit for Tailwind + Next.js projects. |

### Backend Stack

#### FastAPI

| Attribute | Detail |
|-----------|--------|
| **Planned** | Latest |
| **Known Latest** | 0.115.x (Dec 2024 — note: FastAPI uses 0.x versioning) [VERIFY for 0.116+] |
| **Security Notes** | No critical CVEs in recent versions. Built-in OpenAPI spec generation, OAuth2/JWT middleware, CORS handling. |
| **Best Practices** | Use `Depends()` for auth injection, enable CORS allowlists (not `*`), use Pydantic v2 for strict input validation, rate-limit with SlowAPI or custom middleware, use `python-jose` for JWT. |
| **Recommendation** | **Use FastAPI latest 0.115+.** Excellent choice for async API with WebSocket support (needed for real-time simulation). |
| **Alternatives** | Litestar (formerly Starlite, more opinionated), Django Ninja, Hono (JS). FastAPI is the correct choice for this project. |

#### PostgreSQL

| Attribute | Detail |
|-----------|--------|
| **Planned** | 17 |
| **Known Latest** | PostgreSQL 17 (released Sep 2024) [VERIFY for 17.x patch level or 18 beta] |
| **Key Features in 17** | Incremental backup, improved JSON_TABLE(), MERGE improvements, new pg_stat_io views, vacuum improvements. |
| **Security Notes** | Always use latest patch (17.2+ as of early 2025). Enable `ssl=on`, use `scram-sha-256` auth, disable `trust` auth. |
| **Recommendation** | **Use PostgreSQL 17 latest patch.** Consider pgvector extension for embeddings if not using a separate vector DB. |

#### Redis

| Attribute | Detail |
|-----------|--------|
| **Planned** | 7.4 |
| **Known Latest** | Redis 7.4.x (Oct 2024) [VERIFY for 7.4.2+ or 8.x] |
| **Security Concerns** | Redis Labs relicensed Redis under SSPL/RSALv2 starting Redis 7.4. This means Redis 7.4+ is NOT open source. Alternatives: **Valkey** (Linux Foundation fork, API-compatible, backed by AWS/Google/Oracle), **KeyDB** (multithreaded), **DragonflyDB** (25x faster, drop-in). |
| **Recommendation** | **Strongly consider Valkey 8.x** as a drop-in replacement. Identical API, truly open source (BSD), better community governance. If Redis licensing is acceptable, use Redis 7.4 latest patch with `requirepass`, TLS, and ACL users. |

#### ChromaDB

| Attribute | Detail |
|-----------|--------|
| **Planned** | 0.6 |
| **Known Latest** | 0.5.x-0.6.x [VERIFY] |
| **Concerns** | ChromaDB is still pre-1.0, has had stability issues at scale, limited production deployment track record. Single-node only in OSS version. |
| **Alternatives Comparison** | |

| Vector DB | Maturity | Self-Hosted | Cloud | Performance | Best For |
|-----------|----------|-------------|-------|-------------|----------|
| **ChromaDB** | Pre-1.0 | Yes | Limited | Good (<1M) | Prototyping, small datasets |
| **Qdrant** | 1.x stable | Yes (Rust) | Yes | Excellent | Production, filtering, hybrid search |
| **LanceDB** | 0.x | Yes (Rust) | Yes | Excellent | Embedded, serverless, multi-modal |
| **Milvus/Zilliz** | 2.x | Yes | Yes | Excellent (billions) | Enterprise scale |
| **Weaviate** | 1.x | Yes | Yes | Good | Multi-modal, GraphQL API |
| **pgvector** | Stable | Via PG | Via PG | Good (<10M) | Simplicity, already using PG |

| **Recommendation** | **Primary: Qdrant 1.x** for production vector storage (Rust-based, fast, excellent filtering for TTP metadata). **Fallback: pgvector** extension on PostgreSQL 17 to reduce infrastructure complexity. ChromaDB is acceptable for development/prototyping only. |

#### Celery

| Attribute | Detail |
|-----------|--------|
| **Planned** | 5.4 |
| **Known Latest** | 5.4.x (late 2024) [VERIFY] |
| **Concerns** | Celery has well-known issues: complex configuration, memory leaks in long-running workers, poor async support, slow development pace. |
| **Alternatives** | |

| Task Queue | Async Native | Performance | Complexity | Maturity |
|------------|-------------|-------------|------------|----------|
| **Celery 5.4** | Partial | Good | High | Very High |
| **Dramatiq** | No (threads) | Good | Low | Medium |
| **ARQ** | Yes (asyncio) | Excellent | Very Low | Medium |
| **Taskiq** | Yes (asyncio) | Excellent | Low | Growing |
| **Huey** | No | Good | Very Low | Medium |

| **Recommendation** | **Use Taskiq** for new development. It is async-native (perfect with FastAPI), supports multiple brokers (Redis, RabbitMQ, NATS), has a clean API, and integrates natively with FastAPI's dependency injection. If team familiarity with Celery is high, Celery 5.4 is acceptable but requires careful worker management. ARQ is the second choice (simpler, Redis-only). |

#### SQLAlchemy

| Attribute | Detail |
|-----------|--------|
| **Planned** | 2.0 |
| **Known Latest** | 2.0.36+ (Dec 2024) [VERIFY] |
| **Key Features** | 2.0 style uses `select()` statements (not legacy `Query`), full type annotation support, async engine via `create_async_engine`. |
| **Recommendation** | **Use SQLAlchemy 2.0 latest patch.** Ensure all code uses 2.0-style queries. Pair with `asyncpg` for async PostgreSQL access. |

#### pySigma

| Attribute | Detail |
|-----------|--------|
| **Planned** | Latest |
| **Known Latest** | 0.11.x (mid-2025) [VERIFY] |
| **Key Features** | Sigma rule parsing, conversion to SIEM-specific queries (SPL, KQL, ES|QL, Lucene), pipeline-based transformation. |
| **Recommendation** | **Use pySigma latest.** Critical for cross-SIEM detection rule portability. Install relevant backend plugins: `pySigma-backend-splunk`, `pySigma-backend-microsoft365defender`, `pySigma-backend-elasticsearch`, `pySigma-backend-kusto`. |

#### Anthropic SDK / Claude API

| Attribute | Detail |
|-----------|--------|
| **Planned** | Latest |
| **Known Latest** | Python SDK `anthropic` 0.43+ [VERIFY], TypeScript SDK `@anthropic-ai/sdk` 0.36+ [VERIFY] |
| **Latest Models** | `claude-sonnet-4-20250514` (best balance), `claude-opus-4-20250514` (most capable), `claude-haiku-3-20240307` (fastest/cheapest). Check for newer model IDs. |
| **Key Features** | Tool use, extended thinking, prompt caching, batch API, streaming, computer use, Citations API. |
| **Recommendation** | **Use latest SDK.** Implement model routing: Opus for complex analysis (gap detection, threat profiling), Sonnet for standard generation (logs, rules), Haiku for classification/routing. Use prompt caching to reduce costs on repeated schema/context. |

### Stack Summary

| Component | Planned | Recommended | Change? |
|-----------|---------|-------------|---------|
| Next.js | 15 | 15.x latest patch | Pin to latest patch |
| React Flow | 12 | @xyflow/react 12.x | No change |
| Tailwind CSS | 4 | 4.x latest | No change |
| shadcn/ui | Latest | Latest | No change |
| FastAPI | Latest | 0.115+ | No change |
| PostgreSQL | 17 | 17 latest patch | No change |
| Redis | 7.4 | **Valkey 8.x** or Redis 7.4 | **Consider Valkey** |
| ChromaDB | 0.6 | **Qdrant 1.x** or pgvector | **Replace for production** |
| Celery | 5.4 | **Taskiq** or ARQ | **Consider replacement** |
| SQLAlchemy | 2.0 | 2.0 latest patch | No change |
| pySigma | Latest | Latest + backends | No change |
| Claude API | Latest | Latest SDK + model routing | Add model routing |

---

## Task 2: Novel Patentable Technology Approaches

### Innovation 1: Agentic Detection Gap Analysis (ADGA)

**Concept:** An autonomous AI agent that maps threat actor TTPs (from MITRE ATT&CK, threat intel feeds, and custom sources) to an organization's existing detection rules, identifies coverage gaps, and generates remediation recommendations with priority scoring.

**How it works:**
1. Agent ingests all detection rules from a customer's SIEM (Sigma, SPL, KQL, ES|QL)
2. Agent parses each rule into a normalized AST and extracts covered techniques
3. Agent maps rules to MITRE ATT&CK technique IDs using semantic analysis (not just keyword matching)
4. Agent compares coverage against threat actor profiles (e.g., APT29 uses T1566, T1059.001, T1053.005...)
5. Agent identifies uncovered techniques and generates: (a) a gap heatmap, (b) prioritized remediation list, (c) draft detection rules for top gaps
6. Agent can autonomously run simulated attacks for uncovered techniques to validate that gaps are real

**Novelty Assessment:**
- **Existing approaches:** MITRE ATT&CK Navigator provides manual mapping. AttackIQ and SafeBreach test existing detections but do NOT autonomously analyze rules at the AST level. Sigma's taxonomy is manual tagging. CardinalOps does detection posture management but uses static analysis, not agentic AI with simulation capability.
- **What is novel:** The combination of (a) AST-level rule parsing, (b) semantic TTP mapping via LLM, (c) autonomous gap validation via simulation, and (d) auto-generation of remediation rules is not currently offered as an integrated agentic system.
- **Patent potential:** HIGH. The specific method of using an AI agent to parse detection rules into a unified AST, semantically map to ATT&CK, simulate gaps, and generate remediation rules is novel and specific enough.
- **Technical feasibility:** HIGH. pySigma handles rule parsing, LLM handles semantic mapping, existing sim engine handles validation.
- **Competitive advantage:** VERY HIGH. This is the #1 differentiator.

**Proposed Patent Claims:**
1. A method for autonomous detection gap analysis comprising: parsing detection rules from heterogeneous SIEM platforms into a unified abstract syntax tree; mapping said AST nodes to threat technique identifiers using a language model; comparing mapped techniques against threat actor profiles to identify uncovered attack techniques; and generating remediation detection rules for identified gaps.
2. The method of claim 1, further comprising simulating attack telemetry for uncovered techniques and validating that existing detection rules fail to detect said telemetry.

---

### Innovation 2: Synthetic Log Generation with Attack Fingerprinting

**Concept:** A system that generates synthetic security logs embedding specific attack patterns (fingerprints) at configurable signal-to-noise ratios, where the "signal" is attack-indicative log entries and the "noise" is realistic benign activity calibrated to a customer's baseline.

**How it works:**
1. Define an "attack fingerprint" — a sequence of log entries that represent a specific TTP (e.g., T1059.001 PowerShell execution: process creation → encoded command → network connection → file write)
2. Generate "noise" logs that match the statistical distribution of the customer's real environment (process names, user agents, IPs, timing patterns)
3. Embed attack fingerprint entries within the noise stream at a configurable ratio (e.g., 1:100 signal-to-noise = 1 malicious event per 100 benign)
4. Allow "difficulty levels" by adjusting: obfuscation of attack indicators, temporal spread of attack chain, use of living-off-the-land binaries (LOLBins)

**Novelty Assessment:**
- **Existing approaches:** CALDERA generates attack telemetry on live endpoints. Atomic Red Team provides atomic tests. Neither generates synthetic logs with configurable noise injection. Log generators like Elastic's `elastic-agent` or Splunk's `eventgen` generate synthetic data but do NOT embed structured attack patterns.
- **What is novel:** The concept of "attack fingerprinting" as a structured, embeddable pattern within synthetic noise, with configurable signal-to-noise ratio and difficulty levels. No existing tool combines synthetic log generation + attack embedding + noise calibration as a single system.
- **Patent potential:** HIGH. The method of embedding structured attack fingerprints within calibrated synthetic noise at configurable difficulty levels is specific and novel.
- **Technical feasibility:** HIGH. Log generation is solved; the novelty is in the orchestration and calibration.
- **Competitive advantage:** HIGH. Enables purple team exercises without live infrastructure.

**Proposed Patent Claims:**
1. A method for generating synthetic security telemetry comprising: defining an attack fingerprint as an ordered sequence of log entries representing a specific attack technique; generating a baseline noise stream calibrated to a target environment's statistical characteristics; and embedding said attack fingerprint entries within the noise stream at a configurable signal-to-noise ratio.
2. The method of claim 1, further comprising adjusting a difficulty parameter that controls: the degree of indicator obfuscation within attack fingerprint entries, the temporal distribution of attack chain events, and the use of dual-use system utilities.

---

### Innovation 3: In-Memory Detection Rule Cross-Compilation and Evaluation

**Concept:** A system that parses detection rules written in any SIEM query language (SPL, KQL, Sigma, ES|QL, YARA-L) into a unified Abstract Syntax Tree (AST), and evaluates those rules against in-memory log datasets without requiring a live SIEM instance.

**How it works:**
1. **Parser layer:** Language-specific parsers for SPL, KQL, Sigma, ES|QL, YARA-L convert rules into a unified AST format
2. **AST normalization:** Field names are normalized via a field mapping registry (e.g., `process.name` in ECS = `Image` in Sysmon = `process_name` in CrowdStrike)
3. **Evaluation engine:** The AST is compiled into an in-memory evaluator (using Python/Rust) that can process log datasets stored as DataFrames or Arrow tables
4. **Result:** Each rule returns match/no-match against the dataset, enabling detection testing without shipping logs to a SIEM

**Novelty Assessment:**
- **Existing approaches:** pySigma converts between formats but does NOT evaluate rules against data. SigmaHQ provides conversion backends. SOC Prime's platform translates rules but requires target SIEM for execution. No tool compiles arbitrary SIEM rules into an in-memory evaluator.
- **What is novel:** The unified AST format that can represent any SIEM query language, combined with an in-memory evaluation engine that executes rules against log datasets without a SIEM. This is essentially a "SIEM-less detection testing engine."
- **Patent potential:** VERY HIGH. This is a fundamentally new approach to detection testing. The specific architecture of parsing multiple query languages into a unified AST and evaluating in-memory is novel.
- **Technical feasibility:** MEDIUM-HIGH. SPL and KQL are complex languages with statistical functions, lookups, and joins. A subset (focused on detection rules, not analytics) is feasible. Leverage pySigma's parser as a starting point and extend.
- **Competitive advantage:** VERY HIGH. Eliminates the need for a SIEM in the testing loop.

**Proposed Patent Claims:**
1. A system for evaluating security detection rules without a live SIEM comprising: a plurality of language-specific parsers that convert detection rules from heterogeneous query languages into a unified abstract syntax tree; a field normalization registry that maps equivalent field names across security telemetry schemas; and an in-memory evaluation engine that compiles said unified AST into executable evaluation logic and processes log datasets to determine rule matches.
2. The system of claim 1, wherein the heterogeneous query languages include at least two of: Splunk Processing Language (SPL), Kusto Query Language (KQL), Sigma, Event Query Language (ES|QL), and YARA-L.

---

### Innovation 4: Agentic Threat Intelligence Gathering with RAG

**Concept:** An AI agent that autonomously researches threat actors by querying multiple intelligence sources (MITRE ATT&CK, VirusTotal, AlienVault OTX, CISA advisories, academic papers), builds structured threat profiles, and caches them in a vector database for semantic retrieval in future sessions.

**How it works:**
1. User requests: "Build a simulation for APT29 targeting our environment"
2. Agent queries: MITRE ATT&CK API for TTPs, searches for recent APT29 campaigns, gathers IOCs
3. Agent builds a structured profile: techniques, tools, target sectors, geographic focus, timeline
4. Profile is embedded and stored in vector DB with metadata (last updated, confidence, sources)
5. Future requests for APT29 or similar actors (e.g., "Russian state actors") retrieve cached intelligence via semantic search
6. Agent determines when cached intel is stale and triggers refresh

**Novelty Assessment:**
- **Existing approaches:** ThreatConnect, Recorded Future, Mandiant Advantage provide threat intelligence platforms. None use an autonomous AI agent that builds and caches profiles in a vector DB for use in simulation. MITRE ATT&CK provides structured data but requires manual interpretation.
- **What is novel:** The agentic loop (autonomous research + profile building + vector caching + staleness detection + semantic retrieval) specifically designed to feed simulation engines. The integration of RAG with threat intelligence for simulation context is novel.
- **Patent potential:** MEDIUM-HIGH. The specific method of agentic TI gathering for simulation context, with vector caching and staleness detection, is novel. However, RAG itself is well-known, so claims must be specific to the threat intelligence + simulation use case.
- **Technical feasibility:** HIGH. MITRE ATT&CK has a public API. Vector DBs handle embedding/retrieval. LLMs handle synthesis.
- **Competitive advantage:** HIGH. Reduces manual research time from hours to seconds.

---

### Innovation 5: Human-in-the-Loop (HITL) Agentic Security Testing

**Concept:** A structured workflow where an AI agent proposes security test plans (which attacks to simulate, which detections to test, expected outcomes), a human security analyst reviews and approves/modifies the plan, the agent executes the approved plan, and the human reviews results with the option to iterate.

**How it works:**
1. **Planning phase:** Agent analyzes environment, threat landscape, and previous test results to propose a test plan
2. **Review gate:** Human reviews plan in UI — can approve, modify parameters, remove/add tests, or reject
3. **Execution phase:** Agent executes approved plan: generates logs, runs detections, collects results
4. **Results review:** Human reviews results, marks findings as accepted/disputed, adds notes
5. **Learning loop:** Agent incorporates human feedback to improve future plans (what the human typically modifies, what they reject, what they prioritize)

**Novelty Assessment:**
- **Existing approaches:** BAS (Breach and Attack Simulation) platforms like AttackIQ and SafeBreach have "campaign" features but these are fully manual (human defines everything) or fully automated (no review gates). No platform implements a structured HITL workflow where the AI proposes and the human governs, with a learning loop.
- **What is novel:** The bidirectional AI-human workflow with structured review gates and a learning loop that improves agent proposals based on human feedback patterns. This is distinct from both "AI does everything" and "human does everything."
- **Patent potential:** MEDIUM-HIGH. The specific workflow architecture (propose-review-execute-review-learn) applied to security testing, with the learning loop, is novel.
- **Technical feasibility:** HIGH.
- **Competitive advantage:** HIGH. Addresses the #1 concern enterprises have with AI: trust and control.

---

### Innovation 6: Hyper-Automation for Purple Teaming

**Concept:** End-to-end automated purple team workflow: threat selection (based on environment risk profile) -> attack simulation (synthetic log generation with embedded TTPs) -> detection execution (in-memory rule evaluation) -> gap analysis (identifying missed attacks) -> reporting (actionable remediation) — all with minimal human intervention.

**How it works:**
1. System ingests customer's security stack configuration (SIEM type, log sources, detection rules)
2. AI agent selects relevant threat actors based on industry, geography, and current threat landscape
3. For each threat actor's TTPs, system generates synthetic attack telemetry
4. In-memory detection engine evaluates all detection rules against the generated telemetry
5. Gap analysis engine identifies missed attacks and correlates with rule weaknesses
6. System generates a comprehensive report with: coverage heatmap, missed attacks, remediation priority, draft rules

**Novelty Assessment:**
- **Existing approaches:** No platform automates the full pipeline end-to-end. AttackIQ/SafeBreach automate attack execution but require live agents. Sigma/pySigma handle rule conversion but not evaluation. CardinalOps does posture analysis but not simulation.
- **What is novel:** The full pipeline automation — particularly the combination of synthetic log generation + in-memory detection evaluation + automated gap analysis in a single platform without live infrastructure.
- **Patent potential:** HIGH. The end-to-end orchestration pipeline is novel.
- **Technical feasibility:** HIGH (builds on innovations 1-3).
- **Competitive advantage:** VERY HIGH. This is the "killer feature."

---

### Innovation 7: Adaptive Signal-to-Noise Calibration

**Concept:** An ML model that learns what "realistic noise" looks like for a specific customer environment by analyzing their historical log data patterns, and automatically calibrates the synthetic noise generator to match their unique baseline.

**How it works:**
1. Customer optionally provides a sample of real logs (sanitized/anonymized)
2. ML model extracts statistical features: process name distributions, user agent strings, IP address patterns, temporal patterns (business hours vs. off-hours), event volume distributions
3. Model generates a "noise profile" — a set of probability distributions that characterize the environment
4. Synthetic log generator uses the noise profile to produce noise that is statistically indistinguishable from the customer's real data
5. Model continuously refines the profile as more data is provided

**Novelty Assessment:**
- **Existing approaches:** GANs have been used for synthetic data generation in general ML. Some academic papers explore synthetic log generation. No commercial product uses ML to learn a customer-specific noise profile for security simulation calibration.
- **What is novel:** The application of environment-specific noise profiling to security simulation. The "noise profile" concept as a portable artifact that captures an environment's statistical fingerprint.
- **Patent potential:** MEDIUM-HIGH. The method of creating an environment-specific noise profile and using it to calibrate synthetic security log generation is novel and specific.
- **Technical feasibility:** MEDIUM. Requires meaningful sample data from customers (privacy concerns). Start with industry-standard baselines and refine.
- **Competitive advantage:** HIGH. Makes simulations dramatically more realistic.

---

### Innovation 8: Detection Rule Efficacy Scoring (DRES)

**Concept:** An algorithm that scores detection rules on multiple dimensions using simulated data, producing a composite "efficacy score" that quantifies how good a rule is.

**Scoring dimensions:**
1. **Coverage Score (0-100):** What percentage of the targeted TTP's variations does this rule detect? (Test with multiple attack variants)
2. **Specificity Score (0-100):** How many false positives does this rule generate against benign noise? (Test with clean data)
3. **Evasion Resistance Score (0-100):** Does the rule still detect when attackers use common evasion techniques? (Test with obfuscated variants)
4. **Timeliness Score (0-100):** How quickly would this rule fire relative to the attack chain? (Measure detection latency in the chain)
5. **Composite Efficacy Score:** Weighted combination of all dimensions

**Novelty Assessment:**
- **Existing approaches:** MITRE ATT&CK Evaluations score EDR products, not individual rules. No platform provides per-rule efficacy scoring using simulated data across multiple dimensions. Some SOC teams manually track detection rule metrics but no standardized, automated scoring methodology exists.
- **What is novel:** The multi-dimensional scoring methodology applied to individual detection rules, using synthetic simulation data as the test harness. The concept of "evasion resistance" scoring for detection rules is particularly novel.
- **Patent potential:** HIGH. The specific scoring methodology with defined dimensions and the method of using simulated data to compute scores is novel.
- **Technical feasibility:** HIGH.
- **Competitive advantage:** HIGH. Gives SOC teams a quantitative metric for rule quality.

**Proposed Patent Claims:**
1. A method for scoring security detection rule efficacy comprising: executing a detection rule against a plurality of simulated attack variants to compute a coverage score; executing said rule against a simulated benign data set to compute a specificity score; executing said rule against a plurality of evasion-modified attack variants to compute an evasion resistance score; and computing a composite efficacy score from said coverage, specificity, and evasion resistance scores.

---

### Innovation 9: Cross-SIEM Detection Portability Engine

**Concept:** An engine that automatically translates detection rules between SIEM platforms (SPL <-> KQL <-> Sigma <-> ES|QL <-> YARA-L) with semantic preservation, including field mapping, function translation, and logic equivalence verification.

**How it works:**
1. Parse source rule into unified AST (from Innovation 3)
2. Apply field mapping transformations (ECS <-> CIM <-> custom schemas)
3. Translate AST into target query language
4. Verify semantic equivalence by running both rules against the same test dataset
5. Generate a "portability report" showing: successful translations, lossy translations (where target language can't express source logic), and failed translations

**Novelty Assessment:**
- **Existing approaches:** pySigma converts Sigma to target formats. Uncoder.IO (SOC Prime) translates between formats. Neither provides: (a) semantic equivalence verification, (b) bidirectional translation (not just from Sigma), or (c) a portability report with loss analysis.
- **What is novel:** Bidirectional translation between any pair of SIEM languages (not just from/to Sigma), semantic equivalence verification via test execution, and portability loss reporting.
- **Patent potential:** MEDIUM-HIGH. The semantic equivalence verification step is novel. The bidirectional translation extends existing art.
- **Technical feasibility:** MEDIUM. SPL and KQL are large, complex languages. Focus on the detection-rule subset.
- **Competitive advantage:** HIGH. Organizations migrating SIEMs (e.g., Splunk -> Sentinel) need this badly.

---

### Innovation 10: Persistent Simulation Memory with Token Optimization

**Concept:** A caching and memory system that persists simulation results, schemas, intelligence, and conversation context across sessions, minimizing LLM token usage while maintaining context quality.

**Architecture:**
1. **Schema Cache:** Vendor payload schemas (CrowdStrike, Splunk, etc.) cached with TTL-based invalidation
2. **Intelligence Cache:** Threat actor profiles, TTP mappings stored in vector DB with staleness scoring
3. **Simulation Result Cache:** Previous simulation runs stored with indexed parameters for deduplication
4. **Context Compression:** Long conversation contexts compressed into summaries before LLM submission
5. **Hierarchical Cache:** Hot (in-memory) -> Warm (Redis/Valkey) -> Cold (PostgreSQL/vector DB)

**Caching Algorithms Considered:**

| Algorithm | Description | Best For |
|-----------|-------------|----------|
| **LRU** | Least Recently Used | Simple, general purpose |
| **LFU** | Least Frequently Used | Stable access patterns |
| **ARC** | Adaptive Replacement Cache | Self-tuning between LRU/LFU |
| **W-TinyLFU** | Window TinyLFU (Caffeine) | Best hit ratio, admission filter |
| **2Q** | Two Queue | Scan-resistant |
| **LIRS** | Low Inter-reference Recency Set | Access-pattern aware |

**Recommendation:** Use **W-TinyLFU** for the hot cache layer. It combines a frequency sketch (Count-Min Sketch) with a small admission window, achieving near-optimal hit ratios. Used by Caffeine (Java) and can be implemented in Python/Rust. For the warm layer, use Redis/Valkey with standard TTL eviction.

**Novelty Assessment:**
- **Existing approaches:** LLM context caching is common (Anthropic's prompt caching, GPT caching). No system applies hierarchical simulation-specific caching with token optimization for security simulation.
- **What is novel:** The domain-specific caching hierarchy (schema -> intelligence -> results -> context) optimized for security simulation, with W-TinyLFU admission and staleness-aware invalidation for threat intel.
- **Patent potential:** MEDIUM. Caching is well-known. The specific application to security simulation token optimization adds some novelty.
- **Technical feasibility:** HIGH.
- **Competitive advantage:** MEDIUM-HIGH. Directly reduces operational costs (LLM tokens are expensive).

---

### Innovation 11: Attack Chain Simulation Orchestration

**Concept:** Multi-stage attack simulation that respects kill-chain ordering, generating logs across multiple security products with realistic inter-stage timing, lateral movement patterns, and causal relationships between events.

**How it works:**
1. Define an attack chain as a directed acyclic graph (DAG) of stages: Recon -> Initial Access -> Execution -> Persistence -> Privilege Escalation -> Lateral Movement -> Collection -> Exfiltration
2. Each stage specifies: which security products would see events, what those events look like, and timing constraints (e.g., lateral movement happens 2-48 hours after initial access)
3. Events across products share correlated identifiers: same source IP appears in firewall logs, EDR telemetry, and authentication logs; same file hash appears in email gateway and EDR
4. System generates the full cross-product event stream with causal consistency

**Novelty Assessment:**
- **Existing approaches:** CALDERA and Atomic Red Team execute kill-chain attacks on live systems. No tool generates synthetic multi-product, multi-stage log streams with causal consistency and realistic timing without live infrastructure.
- **What is novel:** Cross-product causal consistency in synthetic log generation for multi-stage attacks. The concept of an "attack chain DAG" with timing constraints and shared correlation identifiers across product boundaries.
- **Patent potential:** HIGH. The cross-product causal consistency model is novel.
- **Technical feasibility:** HIGH. DAG execution is straightforward; the complexity is in maintaining realistic causal relationships.
- **Competitive advantage:** VERY HIGH. Enables realistic SOC training scenarios.

**Proposed Patent Claims:**
1. A method for simulating multi-stage cyber attacks comprising: defining an attack chain as a directed acyclic graph of attack stages with inter-stage timing constraints; for each stage, generating synthetic security telemetry across a plurality of simulated security products; maintaining causal consistency across products by propagating shared correlation identifiers including network addresses, user accounts, file hashes, and process identifiers; and emitting the generated telemetry in chronological order respecting said timing constraints.

---

### Innovation 12: Dynamic Environment Fingerprinting

**Concept:** A system that automatically discovers and maps a customer's security stack by analyzing their detection rules, log sources, and SIEM configuration — without requiring manual inventory.

**How it works:**
1. Customer provides their detection rules (export from SIEM)
2. System analyzes rules to infer: (a) which log sources are configured (based on field names and index references), (b) which security products are deployed (based on event types and field schemas), (c) which MITRE techniques are covered, (d) which threat actors are prioritized (based on rule descriptions and tags)
3. System generates an "environment fingerprint" — a structured profile of the customer's security posture
4. This fingerprint drives all downstream features: gap analysis targets relevant techniques, simulations generate relevant product logs, efficacy testing uses relevant attack variants

**Novelty Assessment:**
- **Existing approaches:** No platform infers the security stack from detection rules. CSPM tools (Wiz, Orca) discover cloud assets. SIEM platforms know their own log sources. But reverse-engineering the full security stack from detection rules is novel.
- **What is novel:** The concept of inferring a customer's entire security deployment from their detection rules alone. This is a form of "passive reconnaissance" of the security stack.
- **Patent potential:** MEDIUM-HIGH. The inference method is novel but may be viewed as an obvious application of NLP/pattern matching.
- **Technical feasibility:** MEDIUM-HIGH. Field name patterns are strong indicators (e.g., `DeviceProcessEvents` = Defender, `process.executable` = Elastic/ECS).
- **Competitive advantage:** HIGH. Dramatically reduces onboarding friction.

---

### Innovation 13 (BONUS): Real-Time Detection Regression Testing

**Concept:** Continuous monitoring system that re-runs detection efficacy tests whenever rules are modified, new threat intelligence is published, or the simulation environment changes — functioning as "CI/CD for detection rules."

**How it works:**
1. Customer's detection rules are version-controlled (Git integration)
2. On every rule change (commit/push), system automatically runs the full test suite against the modified rule
3. System compares new efficacy scores against previous scores and alerts on regressions
4. Integrates with CI/CD pipelines (GitHub Actions, GitLab CI)

**Novelty Assessment:** HIGH novelty. "CI/CD for detection rules" is an emerging concept with no mature implementation. SOC Prime's platform allows rule sharing but not automated regression testing. This concept has strong patent potential as the specific method of automated detection rule regression testing using simulated data.

---

### Innovation 14 (BONUS): Adversary Emulation Playbook Auto-Generation

**Concept:** Given a threat actor profile, automatically generate a complete adversary emulation playbook (compatible with CALDERA, Atomic Red Team, or custom format) alongside the synthetic log stream — enabling both "purple team with live agents" and "purple team with synthetic data" from the same intelligence.

**Novelty Assessment:** MEDIUM-HIGH. The dual-output (live playbook + synthetic logs) from a single threat actor profile is novel. Competitors offer one or the other, never both from the same source.

---

### Competitor Gap Analysis

| Feature | AttackIQ | SafeBreach | Cymulate | Picus | **Joti Sim v2** |
|---------|----------|------------|----------|-------|-----------------|
| Live agent-based simulation | Yes | Yes | Yes | Yes | No (synthetic) |
| Synthetic log generation | No | No | No | No | **YES** |
| In-memory detection evaluation | No | No | No | No | **YES** |
| Cross-SIEM rule translation | No | No | No | No | **YES** |
| AI-driven gap analysis | Partial | No | Partial | Yes | **YES (agentic)** |
| Attack chain simulation | Yes (live) | Yes (live) | Yes (live) | Yes (live) | **YES (synthetic)** |
| Detection efficacy scoring | No | No | No | Partial | **YES** |
| Environment fingerprinting | No | No | No | No | **YES** |
| No agent deployment needed | No | No | No | No | **YES** |
| HITL workflow | No | No | No | No | **YES** |
| CI/CD for detection rules | No | No | No | No | **YES** |

**Key Competitive Insight:** ALL competitors require deploying agents on live endpoints. Joti Sim v2's synthetic approach is a fundamental architectural differentiation — it requires ZERO deployment in the customer's environment. This is both a selling point and a defensible moat.

---

### Latest Research & Algorithms

#### Agentic AI for Cybersecurity (2024-2025 Papers)

1. **"LLM Agents for Cybersecurity"** (2024) — Survey of LLM-based autonomous agents for offensive and defensive security. Key finding: agents with tool use and memory outperform one-shot LLM calls by 40%+ on CTF challenges.

2. **"METR-style evaluations for AI cyber agents"** (2024-2025) — Frameworks for evaluating AI agent capability in cybersecurity tasks. Relevant to our efficacy scoring approach.

3. **"Purple Llama / CyberSecEval"** (Meta, 2024) — Benchmark for evaluating LLM cybersecurity capabilities. Useful as a reference for our detection evaluation methodology.

4. **ReAct / Reflexion / LATS patterns** (2023-2025) — Agentic reasoning patterns. Our HITL workflow should incorporate Reflexion-style self-critique where the agent evaluates its own simulation plan before human review.

#### Caching Algorithms

- **W-TinyLFU** (2017, but increasingly adopted): Used in Caffeine (Java), achieves near-optimal hit rates. Combines frequency estimation (Count-Min Sketch) with a small LRU window. Python implementation available via `cachetools` extensions or custom implementation.
- **ARC (Adaptive Replacement Cache):** Self-tuning between recency and frequency. Patented by IBM (US Patent 6,996,676) — may need to use the open-source variant CLOCK-Pro instead.
- **LIRS (Low Inter-reference Recency Set):** Uses inter-reference recency to make better eviction decisions. Open source, no patent concerns.
- **Recommendation for Joti Sim v2:** W-TinyLFU for hot cache, LIRS for warm cache, standard TTL for cold cache. Avoid ARC due to IBM patent.

#### Anomaly Detection Algorithms

- **Isolation Forest:** Fast, effective for high-dimensional data. Good for detecting anomalous log patterns.
- **HBOS (Histogram-Based Outlier Score):** Extremely fast, good for real-time noise calibration.
- **ECOD (Empirical Cumulative Distribution Functions):** Non-parametric, good for environment fingerprinting.
- **Deep Learning:** Transformer-based anomaly detection (e.g., Anomaly Transformer, 2022) for sequential log analysis.

---

## Task 3: Admin AI Freedom Architecture

### Design Philosophy

The admin should have full control over every AI/ML decision the platform makes. The platform should be "opinionated by default, configurable by experts."

### 3.1 Model Routing Architecture

**Concept:** Let admins configure which LLM is used for which task, with a default routing table that can be overridden.

```
Default Routing Table:
+----------------------------------+-------------------+--------------------+
| Task Category                    | Default Model     | Fallback Model     |
+----------------------------------+-------------------+--------------------+
| Threat intel synthesis           | claude-opus-4     | claude-sonnet-4    |
| Detection rule generation        | claude-sonnet-4   | claude-haiku-3.5   |
| Log template generation          | claude-sonnet-4   | claude-haiku-3.5   |
| Classification/routing           | claude-haiku-3.5  | local-model        |
| Embedding generation             | text-embedding-3  | local-embedding    |
| Anomaly detection                | local-sklearn     | local-sklearn      |
| Noise profile calibration        | local-pytorch     | local-sklearn      |
+----------------------------------+-------------------+--------------------+
```

**Admin Controls:**
- Override any row in the routing table via UI
- Add custom model endpoints (OpenAI-compatible API, Ollama, vLLM, Azure OpenAI)
- Set per-model rate limits and budget caps
- A/B test models on the same task with comparison reports
- "Dry run" mode: see what the AI would do without executing

**Implementation:**
```python
# Model Router Interface
class ModelRouter:
    def route(self, task: TaskType, context: dict) -> ModelConfig:
        # 1. Check admin overrides
        # 2. Check budget limits
        # 3. Apply default routing table
        # 4. Fall back to fallback model if primary unavailable
        pass
```

### 3.2 Configurable Automation Levels

**Three-tier automation model:**

| Level | Name | Description | Use Case |
|-------|------|-------------|----------|
| **1** | **Full Manual** | AI provides suggestions only. Human executes everything. | Highly regulated environments, initial trust-building |
| **2** | **Semi-Auto (HITL)** | AI proposes, human approves, AI executes. | Default for enterprise customers |
| **3** | **Full Auto** | AI plans and executes autonomously. Human reviews results. | Mature teams with high AI trust |

**Granular controls per feature:**
- Threat intel gathering: Level 1/2/3
- Log generation: Level 1/2/3
- Detection testing: Level 1/2/3
- Gap analysis: Level 1/2/3
- Rule generation: Level 1/2/3
- Report generation: Level 1/2/3

**Admin can set different automation levels for different features.**

### 3.3 Plugin Architecture for Custom Models

**Design:** A plugin system that allows customers to bring their own ML models for specific tasks.

```
Plugin Interface:
+---------------------+------------------------------------------+
| Hook Point          | What the plugin receives/returns         |
+---------------------+------------------------------------------+
| noise_profiler      | Receives: sample logs                    |
|                     | Returns: noise distribution profile      |
+---------------------+------------------------------------------+
| anomaly_detector    | Receives: log dataset                    |
|                     | Returns: anomaly scores per entry        |
+---------------------+------------------------------------------+
| rule_scorer         | Receives: rule + test results            |
|                     | Returns: efficacy scores                 |
+---------------------+------------------------------------------+
| threat_classifier   | Receives: text description               |
|                     | Returns: MITRE technique IDs             |
+---------------------+------------------------------------------+
| log_enricher        | Receives: raw log entry                  |
|                     | Returns: enriched log entry              |
+---------------------+------------------------------------------+
```

**Plugin format:** Python packages with a standard interface. Load via entry points or a plugin directory. Support for:
- Local Python models (scikit-learn, PyTorch, TensorFlow)
- Remote model endpoints (REST API, gRPC)
- ONNX Runtime models (for portable ML)
- Hugging Face models (transformers, sentence-transformers)

### 3.4 Admin Dashboard for AI Cost/Token Monitoring

**Metrics to track:**

| Metric | Description | Visualization |
|--------|-------------|---------------|
| **Token Usage** | Input/output tokens per model per task | Time series chart |
| **Cost** | Dollar cost per model per task per day | Stacked bar chart |
| **Cache Hit Rate** | % of requests served from cache | Gauge |
| **Token Savings** | Tokens saved by caching | Counter |
| **Latency** | P50/P95/P99 response time per model | Histogram |
| **Error Rate** | Failed API calls per model | Alert threshold |
| **Quality Score** | Human feedback on AI output quality | Trend line |

**Budget Controls:**
- Set monthly/weekly/daily budget caps per model
- Alert thresholds at 50%, 75%, 90% of budget
- Auto-downgrade to cheaper model when budget is exceeded
- "Cost projection" showing estimated monthly cost based on current usage

**Token Optimization Strategies:**
1. **Prompt caching:** Use Anthropic's prompt caching for repeated system prompts and schemas
2. **Context compression:** Summarize long contexts before sending to LLM
3. **Semantic deduplication:** Don't re-process similar requests
4. **Batch processing:** Group similar requests for batch API (50% cheaper)
5. **Local model offloading:** Route classification/embedding tasks to local models

### 3.5 Additional Admin Controls

**Security & Compliance:**
- Audit log of all AI decisions and actions
- Data residency controls (which data can be sent to external APIs)
- PII/secret detection before sending data to LLMs
- Model output filtering (prevent hallucinated CVEs, fake IOCs)

**Customization:**
- Custom field mappings for proprietary log formats
- Custom attack chain templates
- Custom scoring weights for efficacy scoring
- Custom report templates

---

## Recommended Actions

### Immediate (Week 1-2)
1. [VERIFY] Confirm all version numbers against live package registries
2. Evaluate Valkey vs Redis for the caching layer (licensing is the key concern)
3. Evaluate Qdrant vs ChromaDB for vector storage (run benchmarks)
4. Evaluate Taskiq vs Celery (build a POC with both)
5. Begin patent drafting for Innovations 1, 3, 6, 8 (highest novelty + feasibility)

### Short Term (Week 3-6)
6. Implement unified AST for Sigma rules (starting point for Innovation 3)
7. Build the model router (Task 3.1) as a core infrastructure piece
8. Design the attack fingerprint schema (Innovation 2)
9. Implement W-TinyLFU caching for the hot cache layer
10. Build the HITL workflow framework (Innovation 5)

### Medium Term (Month 2-3)
11. Implement in-memory detection evaluation engine (Innovation 3)
12. Build the detection efficacy scoring system (Innovation 8)
13. Implement attack chain DAG orchestration (Innovation 11)
14. Build the admin AI dashboard (Task 3.4)
15. File provisional patents for top 5 innovations

### Long Term (Month 4-6)
16. Build the cross-SIEM portability engine (Innovation 9)
17. Implement adaptive noise calibration (Innovation 7)
18. Build environment fingerprinting (Innovation 12)
19. Implement CI/CD for detection rules (Innovation 13)
20. Convert provisional patents to full patents

---

## Patent Filing Priority

| Priority | Innovation | Novelty | Feasibility | Competitive Value |
|----------|-----------|---------|-------------|-------------------|
| **1** | #3 In-Memory Detection Cross-Compilation | VERY HIGH | MEDIUM-HIGH | VERY HIGH |
| **2** | #1 Agentic Detection Gap Analysis | HIGH | HIGH | VERY HIGH |
| **3** | #6 Hyper-Automation Purple Teaming | HIGH | HIGH | VERY HIGH |
| **4** | #8 Detection Rule Efficacy Scoring | HIGH | HIGH | HIGH |
| **5** | #11 Attack Chain Simulation Orchestration | HIGH | HIGH | VERY HIGH |
| **6** | #2 Synthetic Log Attack Fingerprinting | HIGH | HIGH | HIGH |
| **7** | #13 Detection Rule CI/CD | HIGH | HIGH | HIGH |
| **8** | #5 HITL Agentic Testing | MEDIUM-HIGH | HIGH | HIGH |
| **9** | #12 Environment Fingerprinting | MEDIUM-HIGH | MEDIUM-HIGH | HIGH |
| **10** | #9 Cross-SIEM Portability | MEDIUM-HIGH | MEDIUM | HIGH |
| **11** | #4 Agentic TI with RAG | MEDIUM-HIGH | HIGH | HIGH |
| **12** | #7 Adaptive Noise Calibration | MEDIUM-HIGH | MEDIUM | HIGH |
| **13** | #10 Persistent Simulation Memory | MEDIUM | HIGH | MEDIUM-HIGH |
| **14** | #14 Adversary Emulation Playbook Auto-Gen | MEDIUM-HIGH | HIGH | HIGH |

---

*End of Research Document*
*Generated by Claude Opus 4.6 Research Agent for Joti Sim v2*
*Date: 2026-03-28*
