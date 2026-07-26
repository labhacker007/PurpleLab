# PurpleLab — Miro Board Diagram Index

**Board URL:** https://miro.com/app/board/uXjVH4f6yEA=/  
**Version:** 1.0 | **Date:** 2026-07-26 | **Total Diagrams:** 17

All 17 diagrams are interactive, zoomable, and fully linked on the Miro board.  
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
| 5 | Action Executor — 11 SOAR Actions, ContainmentAction Audit Log | 3458764679164391352 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164391352) |
| 6 | Joti Integration Data Flow — Audit Push, HUNT_TRIGGER, EXTRACTION | 3458764679164496484 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496484) |
| 7 | Pipeline Runner — PipelineConfig, DES Score Delta, Scheduling | 3458764679164391628 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164391628) |
| 8 | Database Schema — All 30+ ORM Models and Relationships | 3458764679164496676 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496676) |

## Row 3 — Workflows and Specialised Engines (y=16000)

| # | Title | Widget ID | Direct Link |
|---|-------|-----------|-------------|
| 9 | HITL Approval Engine — L0 to L3, Magic Link, Auto-Approval | 3458764679164496860 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496860) |
| 10 | Use Case and Detection Run — UseCaseRun, DES Scoring, Coverage | 3458764679164496903 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164496903) |
| 11 | CSPM and VM Vulnerability Management — CVE, EPSS, Risk Scoring | 3458764679164568001 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568001) |
| 12 | 4 Vendor API Emulations — Splunk, XSIAM, CrowdStrike, Defender | 3458764679164568082 | [Open](https://miro.com/app/board/uXjVH4f6yEA=/?moveToWidget=3458764679164568082) |

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

---

## Diagram Colour Coding

| Colour | Meaning |
|--------|---------|
| Blue `#c6dcff` | Entry/exit points, infrastructure (UI, API, DB, platform-level) |
| Green `#adf0c7` | Core engine components (session, EDR, detection, orchestration) |
| Yellow `#fff6b6` | Vendor API emulations (Splunk, XSIAM, CrowdStrike, Defender) |
| Red/Pink `#ffc6c6` | Control plane (HITL, Joti integration, pipeline runner, tabletop) |

## Related Documentation

- [Architecture Diagrams (Mermaid)](./PURPLELAB_ARCHITECTURE_DIAGRAMS.md)
- [QA Master Strategy](./PURPLELAB_QA_MASTER_STRATEGY.md)
- [Workflow Documentation](./PURPLELAB_WORKFLOW_DOCUMENTATION.md)
- [Test Cases (105 cases)](./PURPLELAB_TEST_CASES.md)
- [User and Admin Guide](./PURPLELAB_USER_ADMIN_GUIDE.md)
- [Comprehensive Test Suite](../backend/tests/test_purplelab_comprehensive.py)
