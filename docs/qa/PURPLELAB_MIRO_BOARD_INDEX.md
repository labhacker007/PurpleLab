# PurpleLab — Miro Board Diagram Index

**Board URL:** https://miro.com/app/board/uXjVH4f6yEA=/  
**Version:** 1.1 | **Date:** 2026-07-26 | **Total Diagrams:** 18

All 18 diagrams are interactive, zoomable, and fully linked on the Miro board.  
Use the widget links below to jump directly to any diagram.

---

## Row 1 — Core Architecture (y=0)

| # | Title | Widget ID | Direct Link |
|---|-------|-----------|-------------|
| 1 | System Architecture — Services, Ports, External Connections | 3458764679164349530 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164349530) |
| 2 | SimulationSession Lifecycle — All Modes and State Transitions | 3458764679164349717 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164349717) |
| 3 | EDR State Machine — 6 States, Transitions, Technique Triggers | 3458764679164349822 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164349822) |
| 4 | Detection Evaluation Pipeline — Sigma, SPL, KQL, ESQL | 3458764679164390931 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164390931) |

## Row 2 — Integration and Data Flow (y=8000)

| # | Title | Widget ID | Direct Link |
|---|-------|-----------|-------------|
| 5 | 16-Vendor Enterprise API Simulation Architecture *(updated Jul 26 2026)* | 3458764679181478591 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679181478591) |
| 5-old | 4-Vendor Simulation Architecture — Splunk XSIAM CrowdStrike Defender *(superseded)* | 3458764679164391352 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164391352) |
| 6 | Joti Integration Data Flow — Audit Push, HUNT_TRIGGER, EXTRACTION | 3458764679164496484 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496484) |
| 7 | Pipeline Runner — PipelineConfig, DES Score Delta, Scheduling | 3458764679164391628 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164391628) |
| 8 | Database Schema — All 30+ ORM Models and Relationships | 3458764679164496676 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496676) |

## Row 3 — Workflows and Specialised Engines (y=16000)

| # | Title | Widget ID | Direct Link |
|---|-------|-----------|-------------|
| 9 | HITL Approval Engine — L0 to L3, Magic Link, Auto-Approval | 3458764679164496860 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496860) |
| 10 | Use Case and Detection Run — UseCaseRun, DES Scoring, Coverage | 3458764679164496903 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496903) |
| 11 | CSPM and VM Vulnerability Management — CVE, EPSS, Risk Scoring | 3458764679164568001 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568001) |
| 12 | Detection Rule Import Parse Deploy Evaluate Score | 3458764679164568082 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568082) |

## Row 4 — Operational Workflows (y=24000)

| # | Title | Widget ID | Direct Link |
|---|-------|-----------|-------------|
| 13 | Environment Config and SIEM Topology — All 4 Modes | 3458764679164568281 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568281) |
| 14 | Tabletop Exercise Workflow — Phases, Injects, Scoring | 3458764679164568348 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568348) |
| 15 | ITDR Scenario Execution — 10 Identity Attack Simulations | 3458764679164568484 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568484) |
| 16 | Sigma Rule Library — Import, Tag, Deploy, Evaluate, Manage | 3458764679164568723 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568723) |

## Row 5 — Platform Overview (y=32000)

| # | Title | Widget ID | Direct Link |
|---|-------|-----------|-------------|
| 17 | Complete Platform Architecture — All Subsystems Overview | 3458764679164615738 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164615738) |

## Row 6 — Vendor API Coverage (y=21500)

| # | Title | Widget ID | Direct Link |
|---|-------|-----------|-------------|
| 18 | 16-Vendor Enterprise API Simulation Architecture (full detail) | 3458764679181478591 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679181478591) |

---

## 16 Vendor API Simulations (Jul 26 2026)

| Category | Vendors | Files |
|----------|---------|-------|
| EDR / XDR (5) | CrowdStrike Falcon, Microsoft Defender MDE, SentinelOne Singularity, VMware Carbon Black, Palo Alto XSIAM | crowdstrike.py, defender.py, sentinelone.py, carbonblack.py, xsiam.py |
| SIEM / Log Analytics (3) | Splunk Enterprise Security, IBM QRadar, Elastic SIEM | splunk.py, qradar.py, elastic.py |
| Vulnerability Management / CSPM (3) | Tenable.io, Qualys VMDR, Wiz CSPM | tenable.py, qualys.py, wiz.py |
| ITSM / CMDB (2) | ServiceNow ITSM+CMDB, Jira Cloud+JSM | servicenow.py, jira.py |
| Identity & Access (2) | Okta Identity, Microsoft Entra ID | okta.py, entra_id.py |
| Network Security (1) | Palo Alto Panorama NGFW | panorama.py |

All files under `backend/api/vendor/`. All registered in `backend/main.py`.  
Seed data: CORP-WS-001 (jsmith, 10.10.1.101), CORP-SRV-001 (10.10.2.10), CORP-DC-001 (10.10.2.1).

---

## Diagram Colour Coding

| Colour | Meaning |
|--------|---------|
| Blue `#c6dcff` | Entry/exit points, infrastructure (UI, API, DB, platform-level); EDR/XDR vendors |
| Green `#adf0c7` | Core engine components (session, EDR, detection, orchestration); central orchestrator |
| Yellow `#fff6b6` | SIEM + Network vendors; process nodes |
| Red/Pink `#ffc6c6` | IAM/Identity vendors; Control plane (HITL, Joti integration) |
| Purple `#dedaff` | VM/CSPM vendors |
| Orange `#f8d3af` | ITSM/CMDB vendors |

## Related Documentation

- [Architecture Diagrams (Mermaid)](./PURPLELAB_ARCHITECTURE_DIAGRAMS.md)
- [QA Master Strategy](./PURPLELAB_QA_MASTER_STRATEGY.md)
- [Workflow Documentation](./PURPLELAB_WORKFLOW_DOCUMENTATION.md)
- [Test Cases (105 cases)](./PURPLELAB_TEST_CASES.md)
- [User and Admin Guide](./PURPLELAB_USER_ADMIN_GUIDE.md)
- [Comprehensive Test Suite](../backend/tests/test_purplelab_comprehensive.py)
