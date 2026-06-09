# Prior Art & Competitive Patent Landscape
## PurpleLab Platform — IP Analysis

**Date:** 2026-06-08  
**Purpose:** Prior art search to support provisional patent filings for PL-P1, PL-P2, PL-P3  
**Researcher:** Automated patent + academic literature search (USPTO, Google Patents, arXiv, IEEE)

---

## 1. Existing Patents in the BAS / Detection Effectiveness Space

### SafeBreach Ltd — Foundational BAS Execution Patents (2015–2018)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US9892260B2 | Apr 2015 | Feb 2018 | Graph-based breach scenario execution; DAG of action-component nodes; allocating simulator nodes to emulate attacker/defender; hash-based outcome verification; remediation recommendations |
| US9710653B2 | 2015 | 2017 | Parsing, targeting, and coordination of breach scenario elements |
| US9473522B2 | 2015 | 2016 | Virtualized simulation of malicious activity; success determination; remediation feedback |

**Coverage:** The mechanical execution of breach simulations using virtualized graph-structured scenario files.  
**Does NOT cover:** MITRE ATT&CK mapping, quantitative detection scoring formulas, coverage gap identification, gap-driven simulation dispatch, AI/LLM composition of simulation pipelines, threat intel integration.  
**Risk to PurpleLab:** None for PL-P1, PL-P2, PL-P3. SafeBreach patents are on simulation execution mechanics predating ATT&CK's public release.

---

### AttackIQ Inc — Cyber Security Posture Validation (2015–2016)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US20160044057A1 | Aug 2015 | Published 2016 | Multi-phase attack scenario deployment to network assets; collecting pass/fail outcome data; reporting defensive technology effectiveness |

**Coverage:** Deploying attack scenarios and producing pass/fail reports.  
**Does NOT cover:** Quantitative scoring, coverage metrics, ATT&CK technique-level analysis (predates ATT&CK v1 public release in 2018), gap analysis, automated dispatch.  
**Risk to PurpleLab:** None.

---

### Mandiant / Google LLC — Attack Simulation on Production Network (2019–2020)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US10757131B2 | Mar 2019 | Aug 2020 | Distributed attacker/target controller nodes on production networks; PCAP-driven testing; conditional multi-stage attack triggers |

**Coverage:** Production-network simulation execution with distributed agents.  
**Does NOT cover:** Coverage scoring, gap analysis, AI pipeline composition.  
**Risk to PurpleLab:** None.

---

### Picus Security / Ironsdc Corp — Stateful Multi-Attack Simulation (2022–2024)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US11991203B2 | Feb 2022 | May 2024 | "Decision tree compiler" transforming attack templates into branching logic paths; dynamically-determined attack sequences where each stage adapts based on prior results |

**Coverage:** Stateful, adaptive simulation where the next attack step is chosen based on prior step outcomes.  
**Does NOT cover:** Coverage scoring, ATT&CK gap identification, gap-driven simulation prioritization, threat intel feedback loops, AI composition.  
**Risk to PurpleLab:** The concept of adaptive simulation (our simulation picks scenarios based on technique gaps) could be argued as overlapping. **Distinction:** Picus's claim is about *intra-simulation* branching (step N+1 depends on step N result within a single scenario). PurpleLab's gap-driven dispatch is *inter-simulation* (which simulations to run next depends on coverage store state across all prior simulations). These are architecturally distinct.

---

### Tenable Inc — Continuous Scoring of Security Controls (2021–2024)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US11973788B2 | Mar 2021 | Apr 2024 | Vulnerability detection; security control identification; effectiveness scoring using ordered weighted averaging across six criteria (effectiveness, coverage, assurance, cost, impact, mitigation time); causal inference to estimate control influence; MITRE ATT&CK emulation datasets referenced |

**Coverage:** Scoring *existing deployed security controls* against *vulnerability scan data* using multi-criteria weighted averaging.  
**Does NOT cover:** Simulated attack outcomes driving scores, per-technique ATT&CK gap analysis, automated simulation dispatch triggered by gap identification.  
**Risk to PurpleLab:** **MODERATE** — This is the closest existing patent to PL-P1's scoring component. The key distinction is the data source: Tenable scores controls against static vulnerability scan data. PurpleLab scores detection rules against the actual outcomes of dynamic attack simulations. The causal inference approach (Tenable) vs. direct measurement approach (PurpleLab) is also distinct. **Mitigation:** Ensure PL-P1 claim language specifies "simulation outcome data" and "detection rule firing events" to distinguish from vulnerability scan–based scoring.

---

### NS Holdings / Siege Technologies — Assessing Effectiveness of Cybersecurity Technologies (2016–2019)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US10270798B2 | Oct 2016 | Apr 2019 | Testing components of an attack model at a network element twice (with and without the technology active); comparing results to quantify protection effectiveness at each kill-chain stage |

**Coverage:** A/B testing methodology for measuring security tool effectiveness at kill-chain stages.  
**Does NOT cover:** ATT&CK technique-level coverage tracking, automated gap closure, scoring formulas, AI composition.  
**Risk to PurpleLab:** Low. The A/B testing approach is conceptually different from measuring detection rule firing rates against simulated ATT&CK techniques.

---

### USPTO US12537846 — Cybersecurity Engine with LLM (2024)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US12537846 | ~2023 | 2024 | Using LLM iteratively to prepare prompts and receive responses for simulation task orchestration; LLM called multiple times during execution loop |

**Coverage:** LLM-in-the-execution-loop cybersecurity orchestration.  
**Does NOT cover:** Single-LLM-round composition with zero subsequent LLM calls; typed security simulation block DAGs; deterministic server-side execution.  
**Risk to PurpleLab:** **This patent is the key prior art to distinguish for PL-P3.** The architectural inversion — calling LLM once for composition vs. repeatedly during execution — is PurpleLab's specific novelty. PL-P3 claims must explicitly reference and distinguish from US12537846's iterative LLM execution pattern.

---

### FireCompass — Continuous Automated Red Teaming (2021–2023)

| Patent | Filed | Status | Core Claim |
|--------|-------|--------|-----------|
| US20210352100A1 | May 2021 | Published (pending/granted) | Frontier-driven attack graph traversal; RL-based adaptive learning from emulation outcomes; distributed self-launching subsystems; "attack frontiers" for scalable red teaming without full graph generation |

**Coverage:** RL-based penetration test path optimization — finds new network attack paths by adapting simulation strategy from prior run outcomes.  
**Does NOT cover:** ATT&CK technique-keyed coverage states (UNCOVERED/PARTIAL/COVERED), risk-weighted technique selection formula, detection rule validation via simulation, Sigma rule generation, coverage-gated dispatch.  
**Risk to PurpleLab:** LOW-MODERATE for PL-P1 — examiner may attempt to combine FireCompass (closed loop from simulation outcomes) with CardinalOps (ATT&CK technique tracking). Counter-argument: neither teaches nor suggests using simulation outcomes to update a per-ATT&CK-technique state machine keyed to detection rule validation, nor the risk-weighted dispatch formula with frequency × severity × time-weight components.  
**Risk for PL-P2, PL-P3:** None.

---

### KnowBe4 — Cybersecurity Attack Simulation for Training (2018–2021)

| Patent | Filed | Granted | Core Claim |
|--------|-------|---------|-----------|
| US10979448B2 | Nov 2018 | Apr 2021 | Phishing simulation and user security awareness training |

**Coverage:** Social engineering simulation for human behavior training.  
**Risk to PurpleLab:** None — orthogonal domain.

---

## 2. Commercial Products with No Known Patent Protection

### CardinalOps — Detection Posture Management

**Product:** Measures ATT&CK technique coverage across SIEM/EDR deployments; identifies detection gaps in deployed rules; depth scoring per ATT&CK layer.  
**Patent status:** No USPTO patents found. Appears to operate as trade secret / first-mover.  
**Commercial overlap with PurpleLab:** CardinalOps is the closest commercial analog to the PurpleLab coverage gap analysis feature — but it is entirely *passive* (analyzes existing deployed rules) with no simulation trigger, no feedback loop, no detection use case creation.  
**Strategic note:** CardinalOps has no blocking IP. They are a potential licensing partner or acquisition target, not an IP risk.

### Picus October 2025 Announcement

In October 2025, Picus announced AI-powered BAS using multi-agent orchestration to convert threat intelligence into ATT&CK-mapped simulations. The disclosed architecture: threat intel → payload/TTP mapping → executable simulations → AI-summarized reports. **No patent has been filed or published for this capability.** PurpleLab's development predates this announcement.

**Key distinctions from PurpleLab PL-P2:**
- Picus runs simulations for all extracted TTPs; PurpleLab dispatches only for *uncovered* techniques (coverage-gated dispatch)
- No Sigma rule generation step in Picus's disclosed pipeline
- No detection use case creation as an output
- No feedback loop back to coverage store

---

## 3. Academic Prior Art

### Direct Papers — Updated June 2026

| Paper | Published | Relevant To | What It Covers | What It Misses (PurpleLab's Novelty) |
|-------|-----------|------------|---------------|---------------------------------------|
| "SoK: MITRE ATT&CK in Research" (arXiv:2304.07411) | Apr 2023 | PL-P1, PL-P2 | Surveys 417 ATT&CK papers; **explicitly identifies automated detection effectiveness scoring as a research gap** — supports PurpleLab novelty claim | Does not describe automated scoring, simulation dispatch, or feedback loops |
| "Scalable Blue Team Evaluation" (arXiv:2312.17221) | Dec 2023 | PL-P1 | Automates posture evaluation in cyber range exercises | Focused on exercise reporting, not production detection stack; no simulation-driven coverage state machine |
| "MITRE ATT&CK Applications" (arXiv:2502.10825) | Feb 2025 | PL-P1 | Surveys ATT&CK use cases | Does not describe automated simulation-to-detection feedback loops |
| **"LLMCloudHunter"** (arXiv:2407.05194) | Jul 2024 | PL-P2 | LLM generates cloud detection rules (Splunk) from CTI; 92% precision | No coverage check; no simulation dispatch; no simulation-log grounding; no use case creation |
| **"IntelEX"** (arXiv:2412.10872) | Dec 2024 | **PL-P2 (critical)** | Extracts TTPs from CTI; generates Sigma rules via LLM with ICL; partial validation against pre-collected logs; 0.902 F1 on technique ID | **No coverage gate** (dispatches for all TTPs regardless of existing coverage); no live simulation dispatch; no coverage store update — stages 1+4+partial 5 only |
| "SigmaGen" (night-wolf.io) | Jul 2025 | PL-P2 | Fine-tuned LLM for Sigma rule generation from TI feeds | No coverage gate; no live re-simulation validation confirmed; no coverage store |
| "Bridging the Gap — LLM Agents to Sigma" (Giulia C., Medium) | Oct 2025 | PL-P2 | 4-version multi-agent Sigma generation pipeline | No coverage gate; no simulation dispatch; validation deferred to future work |
| "Architecting Resilient LLM Agents: Plan-then-Execute" (arXiv:2509.08646) | Sep 2025 | **PL-P3 (critical)** | Explicitly advocates plan-then-execute for security; DAG-based task dependency declarations | General principle only; no typed block port schemas; no `{{step_id.output_key}}` inter-step data chaining; no type-preserving template resolution; not a simulation composition system |
| "Prompt2DAG" (arXiv:2509.13487) | 2025 | PL-P3 | LLM-based pipeline DAG generation; Apache Airflow execution | Multi-stage LLM calls (not single-round); generic data enrichment domain (not security simulation); no typed block vocabulary; no type-preserving template chaining |
| "RulePilot" (arXiv:2511.12224) | Nov 2025 | PL-P2 | LLM converts NL descriptions to detection rules via IR + CoT | NL-to-rule only (no TI pipeline); no simulation dispatch; no coverage gate |
| **"CTI-REALM"** (arXiv:2603.13517, Microsoft Security AI) | **Mar 2026** | **PL-P2 (critical)** | Benchmark framework: CTI→TTP extraction→telemetry exploration→Sigma/KQL generation→validation against pre-recorded logs; scores agents at each checkpoint | **Benchmark only (not operational platform)**; uses 37 pre-recorded telemetry samples; **no coverage gate**; no live simulation dispatch conditioned on coverage gaps; no coverage store update — stages 1+4+5 only |
| "ADAPT: Game-Theoretic Automated Pentest" (arXiv:2411.00217) | Oct 2024 | — | Game-theoretic purple team modeling | No pipeline composition, detection coverage scoring, or feedback loop |

### MITRE ATT&CK Evaluations Scoring Specification

MITRE scores detection coverage per technique based on alert quality tiers, with Attack Chain Weighting (ACW) for criticality. This is a **manual, vendor-administered, annual evaluation** process — not an automated, self-service, simulation-triggered scoring engine. The methodology is public and non-patented. PurpleLab's DES/IHDS formulas are distinct in that they are automated, continuous, and driven by simulation outcomes rather than human-administered test cases.

**Key academic finding:** No published paper defines a composite "Detection Effectiveness Score" or "Integrated Hunt & Detection Score" as a quantitative metric computed automatically from simulated attack results. The research community has explicitly identified this as a gap (arXiv:2304.07411). PurpleLab's scoring system fills a documented research gap.

---

## 4. Freedom-to-Operate Summary

| PurpleLab Feature | Blocking Prior Art? | Action |
|---|---|---|
| Gap-weighted simulation dispatch (closed loop) | **None found** | File PL-P1 |
| ATT&CK coverage state machine (3-state, simulation-validated) | **None found** | Core of PL-P1; distinguish CardinalOps (SIEM-layer only) |
| Risk-weighted technique selection formula (freq × sev × time) | **None found** | File PL-P1 Claim 1(c) |
| Closed-loop coverage state update from simulation outcomes | **US20210352100 FireCompass** (different domain/objective) | Distinguish explicitly — FireCompass uses RL for path traversal, not detection coverage |
| Coverage-gated TI-to-detection pipeline | **None found** | The gate is the key novelty of PL-P2 |
| Sigma rule generation FROM live simulation logs | **IntelEX Dec 2024** (pre-recorded, no gate) | Distinguish: IntelEX uses pre-collected logs; PL-P2 requires LIVE dispatch conditioned on coverage gap |
| Single-LLM-round composition / zero-LLM execution | **US12537846** (LLM-in-loop, opposite architecture) | File PL-P3; explicitly reference and distinguish US12537846 |
| Typed block registry + wave execution + type-preserving resolver | **None found** | New independent Claim 11–14 in PL-P3 |
| General plan-then-execute pattern | **arXiv:2509.08646 Sep 2025** (general principle) | Do NOT claim general pattern; claim typed template chaining and typed block vocabulary specifically |
| DES scoring formula (5-dim geometric mean from sim outcomes) | **US11973788** (different data source: vuln scan, not simulation) | Defensive publication; file PL-P1 with formula and geometric mean distinction |
| IHDS multiplicative pipeline score | **None found** | Defensive publication on arXiv |
| Wave-based parallel execution of typed simulation steps | **None found** (Airflow/Prefect are general-purpose) | File as Claim 11 in PL-P3; distinguish on typed block vocabulary + security simulation domain |
| Stateful intra-simulation branching | **US11991203 Picus** (granted) | Do NOT claim intra-simulation branching; PL-P1 is inter-simulation (selection of NEXT simulation) |
| Basic simulation execution mechanics | **US9892260, US20160044057** | Do NOT claim how simulations execute; claim what drives their selection and what is done with their outcomes |
| Production-network simulation | **US10757131** | Do NOT claim distributed production-network simulation |

---

## 5. Sources

**Patents:**
- [SafeBreach US9892260 — Google Patents](https://patents.google.com/patent/US9892260B2/en)
- [AttackIQ US20160044057 — USPTO Report](https://uspto.report/patent/app/20160044057)
- [Mandiant/Google US10757131 — Google Patents](https://patents.google.com/patent/US10757131B2/en)
- [Picus/Ironsdc US11991203 — Google Patents](https://patents.google.com/patent/US11991203B2/en)
- [Tenable US11973788 — USPTO PDF](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11973788)
- [Siege Technologies US10270798 — Google Patents](https://patents.google.com/patent/US10270798B2/en)
- [US12537846 — Cybersecurity Engine with LLM, USPTO](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12537846)
- [FireCompass US20210352100A1 — Google Patents](https://patents.google.com/patent/US20210352100A1/en)
- [Zafran Security US12223062 — Google Patents](https://patents.google.com/patent/US12223062)

**Commercial products:**
- [FireCompass CART Patent Announcement](https://firecompass.com/firecompass-secures-upsto-patent-for-automated-red-teaming/)
- [CardinalOps — Eliminate Coverage Gaps](https://cardinalops.com/eliminate-detection-coverage-gaps-with-automation-and-mitre-attck/)
- [CardinalOps — Leveraging AI and ATT&CK](https://cardinalops.com/blog/leveraging-ai-automation-mitre-attack-eliminate-detection-coverage-gap/)
- [Picus AI BAS Announcement (Oct 2025) — Help Net Security](https://www.helpnetsecurity.com/2025/10/14/picus-security-validation-platform-bas/)
- [Picus + Recorded Future Intelligence-Led Validation (Jan 2026)](https://www.picussecurity.com/resource/blog/intelligence-led-validation-with-picus-and-recorded-future)
- [AttackIQ AI Agents — Watchtower (Aug 2025)](https://www.attackiq.com/2025/08/12/ai-agents/)
- [DeTT&CT GitHub](https://github.com/rabobank-cdc/DeTTECT)
- [MITRE CALDERA GitHub](https://github.com/apache/caldera)

**Academic papers (arXiv):**
- [SoK: MITRE ATT&CK in Research — arXiv:2304.07411](https://arxiv.org/pdf/2304.07411)
- [Scalable Blue Team Evaluation — arXiv:2312.17221](https://arxiv.org/html/2312.17221)
- [LLMCloudHunter — arXiv:2407.05194](https://arxiv.org/abs/2407.05194)
- [IntelEX — arXiv:2412.10872](https://arxiv.org/html/2412.10872v1)
- [Resilient LLM Agents Plan-then-Execute — arXiv:2509.08646](https://arxiv.org/pdf/2509.08646)
- [Prompt2DAG — arXiv:2509.13487](https://arxiv.org/html/2509.13487v1)
- [Evaluating LLM Detection Rules — arXiv:2509.16749](https://arxiv.org/abs/2509.16749)
- [ADAPT Game-Theoretic Pentest — arXiv:2411.00217](https://arxiv.org/abs/2411.00217)
- [RulePilot — arXiv:2511.12224](https://arxiv.org/abs/2511.12224)
- [CTI-REALM — arXiv:2603.13517](https://arxiv.org/html/2603.13517v1)
- [MITRE ATT&CK Applications — arXiv:2502.10825](https://arxiv.org/abs/2502.10825)

**Other:**
- [SafeBreach BAS Patents — IPWatchdog](https://ipwatchdog.com/2018/06/18/safebreach-issuance-breach-attack-simulation-patents/id=98340/)
- [SigmaGen — Night-Wolf.io (Jul 2025)](https://blogs.night-wolf.io/sigmagen-ai-powered-attck-mapped-threat-detection-with-sigma-rules)
- [CTI-REALM — Microsoft Security Blog (Mar 2026)](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/)
- [Giulia C. — LLM Agents for Sigma Detections (Oct 2025)](https://medium.com/@kawngc/bridging-the-gap-how-i-used-llm-agents-to-translate-threat-intelligence-into-sigma-detections-9537e7b49cb3)

*Research completed: June 9, 2026. 30+ sources verified.*
