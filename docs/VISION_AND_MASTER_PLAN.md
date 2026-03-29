# PurpleLab — Vision & Master Plan

**Date:** 2026-03-28
**Status:** Living document — update as implementation progresses

---

## Executive Summary

PurpleLab is an **agentic purple team simulation platform** that generates production-realistic security logs from 50+ sources, tests detection rules against those logs, scores detection coverage using Bayesian math, and integrates with Joti for a complete **intel-to-hunt-to-detection feedback loop** — all orchestrated by an AI agent with configurable human-in-the-loop controls.

---

## Table of Contents

1. [The Vision](#1-the-vision)
2. [Log Source Coverage (50+ Sources)](#2-log-source-coverage)
3. [Schema Tracking & Freshness System](#3-schema-tracking--freshness-system)
4. [Attack Chain Orchestration](#4-attack-chain-orchestration)
5. [Scoring Models](#5-scoring-models)
6. [Joti Integration — Intel-to-Hunt-to-Detection Pipeline](#6-joti-integration)
7. [HITL & Approval Workflows](#7-hitl--approval-workflows)
8. [AI & Model Strategy](#8-ai--model-strategy)
9. [Detection-as-Code Pipeline](#9-detection-as-code-pipeline)
10. [Implementation Roadmap](#10-implementation-roadmap)
11. [Research References](#11-research-references)

---

## 1. The Vision

```
┌───────────────────────────────────────────────────────────────────────┐
│                        PURPLELAB PLATFORM                             │
│                                                                       │
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────┐              │
│  │ 50+ Log     │   │ Attack Chain │   │ Detection    │              │
│  │ Source       │──>│ Orchestrator │──>│ Engine       │              │
│  │ Generators   │   │ (TTP-based)  │   │ (5 languages)│              │
│  └─────────────┘   └──────────────┘   └──────┬───────┘              │
│                                               │                       │
│  ┌─────────────┐   ┌──────────────┐   ┌──────▼───────┐              │
│  │ Schema      │   │ Scoring      │   │ Coverage     │              │
│  │ Registry    │──>│ Engine       │──>│ Matrix       │              │
│  │ (auto-update)│   │ (Bayesian)   │   │ (MITRE)      │              │
│  └─────────────┘   └──────────────┘   └──────┬───────┘              │
│                                               │                       │
│  ┌─────────────┐   ┌──────────────┐   ┌──────▼───────┐              │
│  │ Joti        │<──│ Intel→Hunt→  │<──│ Gap Analysis │              │
│  │ Platform    │──>│ Detection    │──>│ & Risk Map   │──> CISO      │
│  │ Integration │   │ Pipeline     │   │              │   Dashboard  │
│  └─────────────┘   └──────────────┘   └──────────────┘              │
│                                                                       │
│  ┌─────────────────────────────────────────────────────┐             │
│  │  Agentic AI (Claude) + HITL Approval Workflows      │             │
│  │  Magic Link | Slack | PagerDuty | Email              │             │
│  └─────────────────────────────────────────────────────┘             │
└───────────────────────────────────────────────────────────────────────┘
```

### Core Workflow

1. **Select threat** — Pick a threat actor (APT28), TTP set, or custom scenario
2. **Generate logs** — Produce realistic attack logs embedded in noise across 50+ sources
3. **Test detections** — Run all detection rules against generated logs
4. **Score coverage** — Bayesian scoring per technique, per tactic, overall
5. **Show gaps** — MITRE heatmap showing what's covered, what's missing, what's stale
6. **Close gaps** — AI suggests detection rules, human reviews, deploys to test, re-runs
7. **Track over time** — Trend scores, compare runs, report to leadership

---

## 2. Log Source Coverage

### Target: 50+ Log Sources Across 12 Categories

#### 2.1 Endpoint / OS Logs

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 1 | **Windows Security Event Log** | EVTX/XML→JSON | 4624 (logon), 4625 (failed), 4648 (explicit cred), 4672 (special priv), 4688 (process create), 4720 (user create), 4732 (group add), 7045 (service install), 1102 (log cleared) | Very stable (core unchanged since Vista) | P0 |
| 2 | **Windows Sysmon** | XML→JSON | 1 (ProcessCreate), 3 (NetworkConnect), 7 (ImageLoad), 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (FileCreate), 12-14 (Registry), 22 (DNSQuery), 23 (FileDelete), 25 (ProcessTampering) | Stable, new events added ~yearly | P0 |
| 3 | **Windows PowerShell** | EVTX | 4103 (Module), 4104 (ScriptBlock), 4105/4106 (Start/Stop) | Stable | P0 |
| 4 | **Windows Defender / MDE** | JSON (Alert API) | Alerts, detections, device events, advanced hunting | Changes frequently (~quarterly) | P1 |
| 5 | **macOS Unified Logging** | JSON (os_log) | process exec, file access, network, auth, endpoint security framework events | Evolves with macOS releases | P1 |
| 6 | **Linux auditd** | Key=value text | execve, connect, open, chmod, chown syscalls | Very stable | P0 |
| 7 | **Linux syslog** | RFC 5424/3164 | auth.log (SSH, sudo), kern.log, daemon.log | Very stable | P0 |
| 8 | **Linux systemd journal** | Binary→JSON | Unit start/stop, service failures, login events | Stable | P2 |

#### 2.2 Container & Orchestration

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 9 | **Docker** | JSON (log-driver) | Container start/stop/die, image pull, exec, daemon audit | Stable | P1 |
| 10 | **Kubernetes Audit Log** | JSON | API calls: create/delete pods, secrets access, RBAC changes, exec into pods | Stable (follows K8s API versions) | P1 |
| 11 | **Kubernetes Events** | JSON (Event objects) | Pod scheduling, failures, scaling, node conditions | Stable | P2 |
| 12 | **containerd / CRI-O** | JSON | Container lifecycle, image operations | Stable | P3 |

#### 2.3 Cloud — AWS

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 13 | **AWS CloudTrail** | JSON | CreateUser, PutBucketPolicy, StopLogging, AssumeRole, RunInstances, CreateAccessKey | Stable (new events with new services) | P0 |
| 14 | **AWS GuardDuty** | JSON (Finding) | Recon, trojan, exfil, credential compromise, crypto mining | Stable | P0 (already have generator) |
| 15 | **AWS VPC Flow Logs** | Space-delimited/JSON (v2-v5) | Accept/reject, src/dst IP:port, protocol, bytes | Stable | P1 |
| 16 | **AWS Security Hub** | ASFF JSON | Aggregated findings from GuardDuty, Inspector, Macie, etc. | Stable | P2 |
| 17 | **AWS WAF Logs** | JSON | Allow/block/count, rule matches, request details | Stable | P2 |

#### 2.4 Cloud — GCP

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 18 | **GCP Cloud Audit Logs** | JSON (LogEntry) | Admin Activity, Data Access, System Event, Policy Denied | Stable | P1 |
| 19 | **GCP Security Command Center** | JSON (Finding) | Vulnerabilities, misconfigs, threats | Evolves with SCC features | P1 |
| 20 | **GCP VPC Flow Logs** | JSON | Connection records with src/dst, bytes, start/end time | Stable | P2 |

#### 2.5 Cloud — Azure

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 21 | **Azure Activity Log** | JSON | Resource CRUD, RBAC changes, service health | Stable | P1 |
| 22 | **Azure Monitor / Log Analytics** | KQL-queryable JSON | Custom tables, diagnostic logs | Stable | P2 |
| 23 | **Azure Defender for Cloud** | JSON (Alert) | Brute force, anomalous access, resource threats | Changes with Defender updates | P1 |
| 24 | **Azure NSG Flow Logs** | JSON | Allow/deny with tuples, byte counts | Stable | P2 |

#### 2.6 Cloud Security Posture

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 25 | **Wiz** | JSON (Issue/Alert) | Vulnerability findings, misconfigs, network exposures, toxic combos | Evolves (Wiz releases often) | P1 |
| 26 | **Prisma Cloud (Palo Alto)** | JSON | Compliance violations, runtime alerts, network anomalies | Evolves quarterly | P2 |

#### 2.7 Firewall & Network Security

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 27 | **Palo Alto PAN-OS** | Syslog (CSV-like) | TRAFFIC (allow/deny), THREAT (virus/spyware/vuln/URL/wildfire), SYSTEM, CONFIG, GLOBALPROTECT | Stable per PAN-OS version | P0 |
| 28 | **Palo Alto Cortex XDR** | JSON | Alerts, incidents, endpoints, causality chains | Changes with XDR versions | P1 |
| 29 | **Palo Alto AIRO (AI Runtime Security)** | JSON | AI model threats, prompt injection, data leakage | NEW — schema evolving | P2 |
| 30 | **Fortinet FortiGate** | Syslog (key=value) | traffic, utm, event subtypes; allow/deny/drop | Stable per FortiOS version | P1 |
| 31 | **Check Point** | CEF/LEEF/JSON | Accept, Drop, Log, Alert; SmartEvent correlations | Stable | P2 |
| 32 | **Cisco ASA / Firepower** | Syslog (%-msg-ID) | %ASA-4-106023 (deny), %ASA-6-302013 (connection), IPS events | Very stable | P2 |
| 33 | **Zscaler ZIA** | JSON (Nanolog Streaming Service) | Web transactions, DLP, sandbox, firewall | Stable | P2 |

#### 2.8 Secure Web / Browser / AI Security

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 34 | **Palo Alto Prisma Access** | Syslog/JSON | GlobalProtect, tunnel, web access | Stable | P2 |
| 35 | **Netskope** | JSON | Cloud app activity, DLP, threat protection | Evolves | P2 |
| 36 | **AI Security Logs (generic)** | JSON | Prompt injection attempts, model abuse, data exfil via AI | NEW category — emerging | P2 |

#### 2.9 CDN & Edge

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 37 | **Cloudflare** | JSON | HTTP requests, WAF events, Bot Management, DDoS events, Workers logs | Stable, well-documented | P1 |
| 38 | **Akamai** | JSON (SIEM Integration) | WAF events, Bot Manager, DDoS events, API security | Stable | P2 |
| 39 | **AWS CloudFront** | TSV (access) / JSON (real-time) | Request logs with edge location, status, bytes, timing | Stable | P2 |

#### 2.10 Identity & Access

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 40 | **Okta System Log** | JSON | auth, MFA, account lock, impossible travel, admin actions | Stable | P0 (already have generator) |
| 41 | **Microsoft Entra ID** | JSON | Sign-in logs, audit logs, risky users, risky sign-ins, MFA registration | Changes with Entra updates | P0 (already have generator) |
| 42 | **CrowdStrike Identity** | JSON | Identity threats, lateral movement, privilege escalation | Evolves with Falcon releases | P2 |

#### 2.11 Email Security

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 43 | **Proofpoint TAP** | JSON | Clicks permitted/blocked, messages delivered/blocked | Stable | P0 (already have generator) |
| 44 | **Microsoft Defender for O365** | JSON | File detonation, URL detonation, safe attachments | Changes with M365 updates | P1 |
| 45 | **Mimecast** | JSON | URL protection, impersonation, attachment protection | Stable | P2 |

#### 2.12 ITSM, Vuln Management, DNS

| # | Source | Format | Key Events | Schema Stability | Priority |
|---|--------|--------|------------|-----------------|----------|
| 46 | **ServiceNow** | JSON (REST) | Incident CRUD, change requests | Stable | P0 (already have generator) |
| 47 | **Jira** | JSON (Webhook) | Issue CRUD, transitions | Stable | P2 |
| 48 | **Tenable.io** | JSON | Vulnerability export, CVE findings | Stable | P2 |
| 49 | **Qualys** | XML/JSON | Host detection, compliance findings | Stable | P2 |
| 50 | **DNS Logs** | Text/JSON | Query/response, NXDOMAIN, TXT/MX queries (C2, exfil) | Stable | P1 |
| 51 | **Zeek (Bro)** | TSV/JSON | conn.log, dns.log, http.log, files.log, ssl.log | Stable | P2 |

#### 2.13 SIEM Normalized Schemas (For Field Mapping)

| Schema | Purpose | Status |
|--------|---------|--------|
| **Splunk CIM** | Common Information Model — normalized field names across data models | Track updates |
| **Elastic ECS** | Elastic Common Schema — comprehensive field reference | Track updates |
| **Microsoft ASIM** | Advanced Security Information Model — Sentinel normalization | Track updates |
| **QRadar LEEF** | Log Event Extended Format | Track updates |
| **Chronicle UDM** | Google's Unified Data Model | Track updates |
| **OCSF** | Open Cybersecurity Schema Framework (AWS, Splunk, IBM) | Emerging standard — watch closely |
| **OSSEM** | Open Source Security Events Metadata — master reference | Primary schema source |

---

## 3. Schema Tracking & Freshness System

### 3.1 Schema Registry

Every log source gets a tracked schema record:

```python
class LogSourceSchema:
    source_id: str              # "windows_sysmon"
    vendor: str                 # "Microsoft"
    product: str                # "Sysmon"
    version: str                # "15.0"
    format: str                 # "xml_to_json"
    schema_definition: dict     # Full field definitions
    sample_events: list[dict]   # 3-5 realistic sample events per event type
    mitre_data_sources: list    # ATT&CK data source mappings
    event_types: list           # Supported event IDs / categories
    doc_url: str                # Official documentation URL
    doc_last_checked: datetime  # When we last read vendor docs
    schema_last_updated: datetime # When schema was last modified
    update_frequency: str       # "stable" | "quarterly" | "monthly" | "frequent"
    normalization_map: dict     # Maps vendor fields → OSSEM/ECS normalized fields
    index_name: str             # SIEM index/sourcetype (e.g., "wineventlog:sysmon")
    sourcetype: str             # Splunk sourcetype
    data_model: str             # CIM data model mapping
    notes: str                  # Known quirks, version differences
```

### 3.2 Monthly Schema Update Process

```
┌─────────────────────────────────────────────────────────────┐
│  Monthly Schema Update Job (Agentic + HITL)                  │
│                                                              │
│  1. Agent reads vendor documentation URLs                    │
│     ├─ Fetches changelog / release notes pages               │
│     ├─ Uses LLM to parse: "Extract schema changes"           │
│     └─ Flags sources with detected changes                   │
│                                                              │
│  2. For flagged sources:                                     │
│     ├─ Agent generates updated schema_definition             │
│     ├─ Agent generates updated sample_events                 │
│     ├─ Diff against current schema                           │
│     └─ Create PR / approval request                          │
│                                                              │
│  3. Human reviews:                                           │
│     ├─ Approve: schema updated, generators rebuilt            │
│     ├─ Reject: mark as reviewed, no change needed             │
│     └─ Modify: human edits, then applies                     │
│                                                              │
│  4. Update tracking table:                                   │
│     └─ doc_last_checked = now()                              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Schema Sources Priority

| Source | What It Provides | How to Use |
|--------|-----------------|------------|
| **OSSEM** (github.com/OTRF/OSSEM) | Standardized data dictionaries for all major log sources | Primary reference for field names and types |
| **Sigma taxonomies** (github.com/SigmaHQ/sigma) | Log source → field name mappings | Field normalization for detection rules |
| **Elastic ECS** (github.com/elastic/ecs) | Comprehensive field reference with examples | Secondary reference, especially for JSON schemas |
| **OCSF** (github.com/ocsf) | Emerging standard schema (AWS, Splunk, IBM) | Watch for adoption, potential future standard |
| **Vendor docs** | Authoritative field definitions | Source of truth for vendor-specific quirks |

### 3.4 RAG Knowledge Base for Schemas

Store in ChromaDB with rich metadata for retrieval:

```
Namespace: "log_schemas"
  ├── Per source: schema definition, field descriptions, sample events
  ├── Per field: normalized name, vendor-specific names, data type, description
  └── Per event type: event ID, description, ATT&CK mapping, detection relevance

Namespace: "normalization"
  ├── Vendor field → OSSEM/ECS field mappings
  ├── Index/sourcetype assignments per SIEM platform
  └── CIM/ASIM/ECS data model mappings

Namespace: "detection_context"
  ├── Per technique: which log sources provide visibility
  ├── Per log source: which techniques it can detect
  └── Required fields per detection scenario
```

---

## 4. Attack Chain Orchestration

### 4.1 Attack Chain Definition

An attack chain is an **ordered sequence of TTPs** that simulates a real adversary:

```yaml
# Example: APT28 attack chain
name: "APT28 — Credential Theft & Lateral Movement"
threat_actor: APT28
kill_chain:
  - step: 1
    technique: T1566.001  # Spearphishing Attachment
    log_sources: [email_gateway, windows_security]
    events:
      - source: proofpoint
        type: malicious_message_delivered
      - source: windows_security
        event_id: 4688
        detail: "outlook.exe spawns cmd.exe"

  - step: 2
    technique: T1059.001  # PowerShell
    log_sources: [windows_powershell, sysmon]
    events:
      - source: powershell
        event_id: 4104
        detail: "Encoded command with Invoke-WebRequest"
      - source: sysmon
        event_id: 1
        detail: "powershell.exe with -enc parameter"

  - step: 3
    technique: T1003.001  # LSASS Memory Dump
    log_sources: [sysmon, windows_security]
    events:
      - source: sysmon
        event_id: 10
        detail: "Process access to lsass.exe with PROCESS_VM_READ"
      - source: sysmon
        event_id: 1
        detail: "procdump.exe or mimikatz.exe execution"

  - step: 4
    technique: T1021.001  # RDP
    log_sources: [windows_security, firewall]
    events:
      - source: windows_security
        event_id: 4624
        detail: "Type 10 (RemoteInteractive) logon to new host"
      - source: palo_alto
        type: TRAFFIC
        detail: "Allow TCP/3389 to internal host"

  - step: 5
    technique: T1048.003  # Exfiltration Over DNS
    log_sources: [dns, sysmon]
    events:
      - source: dns
        type: query
        detail: "Long TXT queries to suspicious domain"
      - source: sysmon
        event_id: 22
        detail: "DNSQuery to C2 domain"

# Shared context (makes logs correlated)
shared_identifiers:
  source_ip: "10.1.5.42"
  username: "jsmith"
  hostname: "WKS-FINANCE-03"
  domain: "corp.example.com"
  c2_domain: "update-service.xyz"
  timeframe: "2h"  # All events within 2-hour window
```

### 4.2 Generation Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Threat Actor Profile** | Select APT group → auto-generate chain from MITRE TTPs | "Test our defenses against APT29" |
| **Manual TTP Selection** | Pick specific techniques → build custom chain | Red team / detection engineer testing specific gaps |
| **Custom Scenario** | Define full chain YAML with specific events | Reproduce known incidents, compliance testing |
| **Intel-Driven** | Pull active TTPs from Joti intel → auto-generate chain | "Test against current threats targeting us" |

### 4.3 Noise Generator

Real environments are noisy. Generated attack logs must be mixed with benign baseline:

```
Noise Generator
├── Configurable signal-to-noise ratio (default: 1:100)
├── Time-of-day patterns (business hours = high activity)
├── Day-of-week patterns (weekdays vs weekends)
├── User behavior profiles (normal login/logout, file access, web browsing)
├── Seasonal patterns (end of quarter = more activity)
└── Per-source noise templates (Windows auth, DNS queries, firewall allows)
```

---

## 5. Scoring Models

### 5.1 Detection Efficacy Score (DES)

Measures: **How well do your detections work?**

#### Per-Technique Formula

```
DES(technique) = GeometricMean(
    breadth(t)^3,        # sub-technique coverage fraction
    depth(t)^1,          # defense-in-depth (multiple rules)
    freshness(t)^2,      # time since last test (exponential decay)
    pass_rate(t)^3,      # Bayesian pass rate (skeptical prior)
    signal_quality(t)^1  # false positive rate (if known)
)
```

**Breadth** = (sub-techniques with at least 1 rule) / (total sub-techniques) * 100

**Depth** = min(rule_count / 3, 1) * 100 (target: 3 independent rules per technique)

**Freshness** = e^(-ln(2) * days_since_last_test / 90) * 100 (90-day half-life)

**Pass Rate (Bayesian)** = (1 + passes) / (4 + total_tests) * 100 (skeptical prior: alpha=1, beta=3)
- 0 tests → 25% (untested rules are suspect)
- 1 test, 1 pass → 40%
- 10 tests, 10 passes → 78.6%
- 100 tests, 100 passes → 97.1%

**Signal Quality** = (1 - false_positive_rate) * 100, default 50 if unknown

#### Per-Tactic Score

```
DES(tactic) = WeightedMean(
    DES(technique_i) * threat_weight(technique_i)
) for all techniques in tactic
```

Where `threat_weight` comes from Joti intel (frequency in active threat landscape).

#### Overall Score

```
DES(overall) = GeometricMean(DES(tactic_j)) for all 14 tactics
```

Geometric mean ensures: one tactic at zero pulls the whole score down.

### 5.2 Intel-to-Hunt-to-Detection Score (IHDS)

Measures: **Does your full pipeline work from intel through detection?**

#### Per-TTP Pipeline Score

```
IHDS(ttp) = Intel_Score * Hunt_Score * Detection_Score
```

Each component is 0-1. Multiplication means any broken stage = zero.

**Intel Score:**
```
Intel_Score = has_intel * decay(intel_age, half_life=180 days) * relevance
```
- `has_intel`: 1 if this TTP appears in active threat intel, 0 otherwise
- `relevance`: 0.5 (generic) to 1.0 (targeted at your sector)

**Hunt Score:**
```
Hunt_Score = has_hunted * decay(hunt_age, half_life=60 days) * finding_factor
```
- `finding_factor`: 1.0 (found & addressed), 0.7 (clean hunt), 0.3 (inconclusive)

**Detection Score:**
```
Detection_Score = DES(technique) / 100
```

#### Overall IHDS

```
IHDS(overall) = mean(IHDS(ttp_i)) for all TTPs in active threat intel
```

### 5.3 Unified MITRE Risk Map

**Keep DES and IHDS separate** (different audiences, different update cadences) but display together:

| Condition | Color | Meaning |
|-----------|-------|---------|
| DES >= 75 AND IHDS >= 60 | Green | Well covered, pipeline works |
| DES >= 50 OR IHDS >= 40 | Yellow | Partial coverage, needs attention |
| DES < 50 AND IHDS < 40 | Orange | Significant gaps |
| DES < 25 OR (high_threat AND DES < 50) | Red | Critical gap — immediate action |
| No data | Gray | Unknown — potentially worst |

### 5.4 Executive Visualization

**Risk Quadrant** — 2D scatter plot for leadership:
- X-axis: Threat Relevance (from intel — how likely this technique targets us)
- Y-axis: Detection Efficacy Score
- Upper-right: High threat, well detected (maintain)
- Lower-right: High threat, poorly detected (**urgent**)
- Upper-left: Low threat, well detected (possible over-investment)
- Lower-left: Low threat, poorly detected (accept risk or backlog)

**Trend-Over-Time** — Weekly tracking:
- Overall DES and IHDS
- Technique-level score changes
- "Score decay" alerts (scores dropping due to stale tests, not real degradation)
- "Coverage velocity" (new techniques gaining detection per sprint)

---

## 6. Joti Integration

### 6.1 What Joti Provides (Data to Pull)

| Joti API | What We Get | How PurpleLab Uses It |
|----------|-------------|----------------------|
| `GET /api/hunt-coverage/score` | HCCS (Hunt Coverage Completeness Score) | Feed into IHDS Hunt_Score |
| `GET /api/hunt-coverage/gaps` | Techniques with high prevalence but no hunts | Priority targets for simulation |
| `GET /api/analytics/threat-exposure-score` | TES (Threat Exposure Score) with components | Compare with PurpleLab's DES |
| `GET /api/analytics/mitre-coverage` | Per-technique heatmap (articles + sigma + hunts) | Overlay with PurpleLab detection test results |
| `GET /api/articles/{id}/intelligence` | Extracted IOCs, TTPs, actors | Drive intel-based attack chain generation |
| `GET /api/hunts` with executions | Hunt results, findings, analyst verdicts | Feed Hunt_Score (recency, finding_factor) |
| `GET /api/sigma/rules` | Detection rules with MITRE tags, last_hunted_at | Compare with PurpleLab test results |
| `GET /api/threat-actors/{id}/intelligence` | Actor TTPs, tools, campaigns | Drive threat-actor-based simulations |
| `GET /api/campaigns/{id}/mitre-coverage` | Campaign technique coverage | Prioritize which campaigns to test against |
| `POST /api/attack-chain/predict` | Predicted next techniques (Bayesian) | Proactive gap analysis |

### 6.2 What PurpleLab Sends to Joti

| PurpleLab Data | Joti Endpoint | Purpose |
|----------------|---------------|---------|
| Simulated alerts | `POST /api/alerts/ingest/{token}` | Test Joti's ingestion pipeline |
| Detection test results | Custom API (new) | Show test pass/fail in Joti's coverage view |
| DES scores per technique | Custom API (new) | Enrich Joti's MITRE heatmap |
| New detection rules | Sigma YAML via API | Push AI-generated rules for review |

### 6.3 Intel-to-Hunt-to-Detection Loop

```
Joti Intel Feed                    PurpleLab                        Joti Hunt/Detection
     │                                │                                    │
     │  1. New threat intel            │                                    │
     │     (article with TTPs)         │                                    │
     │─────────────────────────────────>│                                    │
     │                                │  2. Auto-generate attack chain     │
     │                                │     for TTPs in the intel          │
     │                                │                                    │
     │                                │  3. Generate realistic logs        │
     │                                │     (attack + noise)               │
     │                                │                                    │
     │                                │  4. Test all detection rules       │
     │                                │     against generated logs         │
     │                                │                                    │
     │                                │  5. Score: DES per technique       │
     │                                │                                    │
     │                                │  6. For gaps: AI suggests          │
     │                                │     new detection rules            │
     │                                │                                    │
     │                                │  7. Human reviews (HITL)           │
     │                                │     ├─ Approve → deploy to test    │
     │                                │     ├─ Modify → re-test            │
     │                                │     └─ Reject → log decision       │
     │                                │                                    │
     │                                │  8. Re-run tests with new rules    │
     │                                │                                    │
     │                                │  9. Push results to Joti           │
     │                                │─────────────────────────────────────>│
     │                                │                                    │
     │                                │  10. Query Joti for hunt status    │
     │                                │<─────────────────────────────────────│
     │                                │                                    │
     │                                │  11. Compute IHDS                  │
     │                                │      (Intel * Hunt * Detection)    │
     │                                │                                    │
     │                                │  12. Update MITRE Risk Map         │
     │                                │      and CISO dashboard            │
     │                                │                                    │
```

---

## 7. HITL & Approval Workflows

### 7.1 Automation Levels (Admin Configurable)

| Level | Name | Description | What's Auto | What Needs Approval |
|-------|------|-------------|-------------|---------------------|
| L0 | **Manual** | AI provides info, human does all | Nothing | Everything |
| L1 | **Assisted** | AI suggests, human approves each step | IOC enrichment, log parsing | Rule generation, test execution, deployment |
| L2 | **Supervised** | AI auto-runs low-risk, escalates high-risk | Log generation, rule testing, scoring | New rule deployment, SIEM changes, notifications |
| L3 | **Autonomous** | AI handles most, human reviews outcomes | Everything except production deployment | Deploy to prod SIEM, external sharing |

**Admin configures per-action, not globally.** Example:
- Log generation: L3 (fully auto)
- Rule testing: L2 (auto-run, notify on failure)
- New rule creation: L1 (suggest, wait for approval)
- Deploy to SIEM: L0 (always manual)

### 7.2 Approval Channels

| Channel | How It Works | Best For |
|---------|-------------|----------|
| **In-Platform** | Banner/modal in PurpleLab UI with approve/reject/modify | Primary — when user is active |
| **Magic Link Email** | Time-limited approve/reject links (UUID token, 60min expiry, single-use) | Async — when user is away |
| **Slack** | Block Kit interactive message with context + buttons | Teams using Slack for SOC |
| **PagerDuty** | Incident requiring acknowledgment | Critical/urgent approvals |

### 7.3 Approval Request Format

Every approval request includes:
```
┌─────────────────────────────────────────────────┐
│  APPROVAL REQUEST: Deploy New Detection Rule     │
│                                                  │
│  Action: Deploy Sigma rule to test environment   │
│  Rule: "Suspicious PowerShell Download Cradle"   │
│  Technique: T1059.001                           │
│  Generated by: AI (confidence: 87%)              │
│                                                  │
│  Context:                                        │
│  - Gap identified for T1059.001 in last test run │
│  - Rule tested against 500 sample logs           │
│  - Result: 12/12 attack logs detected            │
│  - False positives: 0/488 benign logs            │
│                                                  │
│  [Approve] [Reject] [Modify] [View Details]      │
└─────────────────────────────────────────────────┘
```

### 7.4 Actions That ALWAYS Require Human Approval

1. Deploying detection rules to production SIEM
2. Modifying firewall/WAF rules
3. Blocking hosts/users/IPs
4. Sharing threat intel externally
5. Sending notifications to executives
6. Deleting or modifying log data
7. Changing RBAC permissions

---

## 8. AI & Model Strategy

### 8.1 Model Selection

| Task | Model | Reason | Cost |
|------|-------|--------|------|
| **Agent orchestration** | Claude Sonnet | Best balance of capability and cost for tool-use | $3/$15 per 1M tokens |
| **Complex analysis** (gap analysis, threat research) | Claude Opus | Highest reasoning quality for strategic decisions | $15/$75 per 1M tokens |
| **Rule generation** | Claude Sonnet | Good structured output, schema-constrained | $3/$15 per 1M tokens |
| **Rule critique / review** | Claude Sonnet | Strong reasoning for finding logic errors | $3/$15 per 1M tokens |
| **Log parsing / triage** | Claude Haiku OR local SLM | High volume, low complexity | $0.25/$1.25 per 1M tokens |
| **Embeddings** | nomic-embed-text (local) | Free, good quality, runs on CPU | Free |
| **Schema change detection** | Claude Haiku | Parse changelogs, structured extraction | $0.25/$1.25 per 1M tokens |

### 8.2 Local SLM Strategy (Cost Optimization)

For high-volume, lower-complexity tasks, run models locally:

| Model | Size | Hardware | Best For |
|-------|------|----------|----------|
| **Phi-3.5-mini** | 3.8B | CPU (quantized) | Log field extraction, schema validation |
| **Mistral 7B** | 7B | Single GPU | Rule syntax checking, log classification |
| **Llama 3.1 8B** | 8B | Single GPU | General security log analysis |
| **nomic-embed-text** | 137M | CPU | All embedding tasks |

### 8.3 Caching Strategy

| Cache Type | TTL | What |
|-----------|-----|------|
| **Prompt cache** | Session | System prompts, few-shot examples (Anthropic native) |
| **Semantic cache** | 24h | Similar queries → same response (cosine > 0.95) |
| **Schema cache** | 7d | Parsed log schemas (invalidate on vendor update) |
| **MITRE cache** | 30d | ATT&CK technique data (invalidate on ATT&CK release) |
| **Enrichment cache** | 1h-24h | IOC lookups, threat intel queries |

### 8.4 AI for Detection Rule Generation

Best prompt pattern (from research):
1. Provide exact log schema + 2-3 example rules as few-shot
2. Decompose technique into sub-behaviors first
3. Ground generation in actual sample logs (benign + malicious)
4. Iterate with FP context: "Common false positives for this include X, Y, Z"
5. Always validate generated rules against sample logs before presenting

---

## 9. Detection-as-Code Pipeline

### 9.1 Lifecycle

```
  Author          Validate        Test            Review         Deploy
  (AI + Human)    (Automated)     (PurpleLab)     (HITL)         (Staged)
      │               │               │               │              │
      ▼               ▼               ▼               ▼              ▼
┌──────────┐   ┌───────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐
│ Generate  │──>│ Syntax    │──>│ Run vs    │──>│ PR /     │──>│ Stage →  │
│ Sigma     │   │ check +   │   │ attack +  │   │ Approval │   │ Prod     │
│ rule      │   │ field     │   │ noise     │   │ workflow │   │ (SIEM)   │
│           │   │ verify    │   │ logs      │   │          │   │          │
└──────────┘   └───────────┘   └───────────┘   └──────────┘   └──────────┘
                                     │
                                     ▼
                              Score: TP rate,
                              FP rate, coverage
```

### 9.2 GitHub Integration

- **Detection rules repo** — Sigma YAML files in version control
- **Branch protection** — CI must pass + peer review before merge
- **CI pipeline** — PurpleLab generates logs, runs rules, reports pass/fail
- **Auto-PR** — Agent creates PR with new rule, test results, coverage impact
- **CODEOWNERS** — Detection engineers as required reviewers

### 9.3 Sigma as Canonical Format

Write rules in **Sigma** (vendor-agnostic), then auto-translate to target SIEM:
- Sigma → SPL (Splunk)
- Sigma → KQL (Sentinel)
- Sigma → ES|QL (Elastic)
- Sigma → YARA-L (Chronicle)
- Sigma → XQL (Cortex XDR)

This gives one rule that deploys to any SIEM — the "cross-SIEM portability" innovation.

---

## 10. Implementation Roadmap

### Phase 5A: Log Source Generators (P0) — BUILD NEXT

| Task | Files | Priority |
|------|-------|----------|
| Windows Security Event Log generator | `backend/log_sources/sources/windows_eventlog.py` | P0 |
| Windows Sysmon generator | `backend/log_sources/sources/sysmon.py` | P0 |
| Windows PowerShell generator | `backend/log_sources/sources/powershell.py` | P0 |
| Linux auditd generator | `backend/log_sources/sources/linux_audit.py` | P0 |
| Linux syslog generator | `backend/log_sources/sources/linux_syslog.py` | P0 |
| AWS CloudTrail generator | `backend/log_sources/sources/cloud_trail.py` | P0 |
| Palo Alto PAN-OS generator | `backend/log_sources/sources/palo_alto.py` | P0 |
| DNS log generator | `backend/log_sources/sources/dns.py` | P0 |
| Noise generator (benign baseline) | `backend/log_sources/noise_generator.py` | P0 |

### Phase 5B: More Log Sources (P1-P2)

| Task | Files | Priority |
|------|-------|----------|
| GCP Audit Logs | `backend/log_sources/sources/gcp_audit.py` | P1 |
| Azure Activity Log | `backend/log_sources/sources/azure_activity.py` | P1 |
| Kubernetes audit | `backend/log_sources/sources/kubernetes_audit.py` | P1 |
| Docker logs | `backend/log_sources/sources/docker.py` | P1 |
| Fortinet FortiGate | `backend/log_sources/sources/fortinet.py` | P1 |
| Cloudflare | `backend/log_sources/sources/cloudflare.py` | P1 |
| Wiz | `backend/log_sources/sources/wiz.py` | P1 |
| Cortex XDR | `backend/log_sources/sources/cortex_xdr.py` | P1 |
| VPC Flow Logs (AWS) | `backend/log_sources/sources/vpc_flow.py` | P2 |
| macOS Unified Logging | `backend/log_sources/sources/macos.py` | P2 |
| Cisco ASA | `backend/log_sources/sources/cisco_asa.py` | P2 |
| Check Point | `backend/log_sources/sources/checkpoint.py` | P2 |
| Zeek | `backend/log_sources/sources/zeek.py` | P2 |
| Akamai | `backend/log_sources/sources/akamai.py` | P2 |

### Phase 5C: Attack Chain Orchestrator

| Task | Files | Priority |
|------|-------|----------|
| Attack chain YAML schema | `backend/attack_chains/schema.py` | P0 |
| Chain orchestrator | `backend/attack_chains/orchestrator.py` | P0 |
| Shared identifier correlation | `backend/attack_chains/correlator.py` | P0 |
| Threat actor → chain generator | `backend/attack_chains/actor_chains.py` | P0 |
| Noise mixer | `backend/attack_chains/noise_mixer.py` | P0 |
| Agent tools for chains | `backend/agent/tools/attack_chain_tools.py` | P0 |

### Phase 5D: Schema Registry

| Task | Files | Priority |
|------|-------|----------|
| Schema registry model + API | `backend/log_sources/schema_registry.py` | P1 |
| Schema tracking table | `backend/db/models.py` (extend LogSourceSchema) | P1 |
| Monthly update job | `backend/jobs/schema_updater.py` | P2 |
| OSSEM integration | `backend/log_sources/ossem_sync.py` | P2 |

### Phase 6: Scoring Engine

| Task | Files | Priority |
|------|-------|----------|
| DES scoring engine | `backend/scoring/detection_efficacy.py` | P0 |
| IHDS scoring engine | `backend/scoring/intel_hunt_detection.py` | P0 |
| MITRE risk map generator | `backend/scoring/risk_map.py` | P0 |
| Scoring API endpoints | `backend/api/v2/scoring.py` | P0 |
| Executive dashboard data | `backend/api/v2/dashboard.py` | P1 |
| Trend tracking | `backend/scoring/trend_tracker.py` | P1 |

### Phase 7: Joti Integration

| Task | Files | Priority |
|------|-------|----------|
| Joti API client | `backend/integrations/joti_client.py` | P0 |
| Intel pull pipeline | `backend/integrations/joti_intel_sync.py` | P0 |
| Hunt status sync | `backend/integrations/joti_hunt_sync.py` | P1 |
| Score push pipeline | `backend/integrations/joti_score_push.py` | P1 |

### Phase 8: HITL & Approvals

| Task | Files | Priority |
|------|-------|----------|
| Approval engine | `backend/hitl/approval_engine.py` | P1 |
| Magic link generator | `backend/hitl/magic_link.py` | P1 |
| Slack integration | `backend/hitl/slack_notifier.py` | P1 |
| PagerDuty integration | `backend/hitl/pagerduty_notifier.py` | P2 |
| Automation level config | `backend/hitl/automation_config.py` | P1 |
| Email notifications | `backend/hitl/email_notifier.py` | P2 |

### Phase 9: Detection-as-Code

| Task | Files | Priority |
|------|-------|----------|
| GitHub integration | `backend/integrations/github_client.py` | P1 |
| Auto-PR for new rules | `backend/detection/rule_publisher.py` | P1 |
| CI validation hook | `backend/detection/ci_validator.py` | P2 |
| Sigma → SIEM translator | `backend/detection/translators/` | P1 |

---

## 11. Research References

### Scoring & Mathematics
- **Detection Maturity Level (DML)** — Ryan Stillions (2014)
- **Pyramid of Pain** — David Bianco (2013)
- **Bayesian Data Analysis** — Gelman et al. (Beta-Binomial model)
- **VECTR** (SecurityRisk Advisors) — open-source purple team scoring
- **NIST CSF v2.0** — maturity tier model

### AI & Detection Engineering
- **MITRE CALDERA** — Adversary emulation platform
- **Atomic Red Team** — Technique-level test library (~800 tests)
- **OSSEM** (OTRF) — Open Source Security Events Metadata
- **OCSF** — Open Cybersecurity Schema Framework
- **SigmaHQ** — Vendor-agnostic detection rules (~3,000+)
- **Elastic detection-rules** — Detection-as-Code reference
- **Splunk Security Content (ESCU)** — Detection + sample data bundles

### AI Models
- **Claude Opus/Sonnet/Haiku** — Anthropic (agent orchestration, analysis, triage)
- **Phi-3.5-mini** (3.8B) — Microsoft (local log parsing)
- **Mistral 7B** — (local rule validation)
- **nomic-embed-text** — (local embeddings, free)
- **BGE-large-en-v1.5** — (high-quality local embeddings)

### Schema Sources
- **OSSEM**: github.com/OTRF/OSSEM
- **Elastic ECS**: github.com/elastic/ecs
- **Sigma taxonomies**: github.com/SigmaHQ/sigma
- **OCSF**: github.com/ocsf

---

*This document represents the complete vision for PurpleLab. Implementation should follow the phase order in Section 10, with P0 items built first.*
