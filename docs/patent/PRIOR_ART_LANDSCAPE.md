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

### FireCompass — Continuous Automated Red Teaming (2023)

| Patent | Status | Core Claim |
|--------|--------|-----------|
| Undisclosed number | Granted 2023 | Frontier-driven attack graph traversal; distributed self-launching subsystems; adaptive learning from emulation results |

**Coverage:** Automated red teaming with frontier-driven graph traversal (avoid full graph generation).  
**Does NOT cover:** Detection effectiveness scoring, simulation-driven gap closure, AI pipeline composition, threat intel integration.  
**Risk to PurpleLab:** None for PL-P1, PL-P2, PL-P3.

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

### Direct Papers

| Paper | Published | Relevance | Gap |
|-------|-----------|-----------|-----|
| "Scalable and Automated Evaluation of Blue Team Cyber Posture in Cyber Ranges" (arXiv:2312.17221) | Dec 2023 | Automates blue team posture evaluation in cyber range exercises | Focused on exercise reporting, not production detection stack measurement; no DES-type composite score |
| "SoK: The MITRE ATT&CK Framework in Research and Practice" (arXiv:2304.07411) | Apr 2023 | Systematizes 417 ATT&CK publications | Explicitly identifies automated detection effectiveness scoring as a *research gap*. This paper supports PurpleLab novelty. |
| "MITRE ATT&CK Applications in Cybersecurity and The Way Forward" (arXiv:2502.10825) | Feb 2025 | Surveys 417 papers on ATT&CK use | Does not describe automated simulation-to-detection feedback loops |
| "Architecting Resilient LLM Agents: Plan-then-Execute" (arXiv:2509.08646) | 2025 | Plan-then-execute LLM pattern | General paradigm; does not apply to security simulation domain; does not describe typed block DAGs or zero-execution LLM calls |
| "ADAPT: Game-Theoretic Framework for Automated Penetration Testing" (arXiv:2411.00217) | Oct 2024 | Game-theoretic purple team defense modeling | No pipeline composition, no detection coverage scoring, no feedback loop |

### MITRE ATT&CK Evaluations Scoring Specification

MITRE scores detection coverage per technique based on alert quality tiers, with Attack Chain Weighting (ACW) for criticality. This is a **manual, vendor-administered, annual evaluation** process — not an automated, self-service, simulation-triggered scoring engine. The methodology is public and non-patented. PurpleLab's DES/IHDS formulas are distinct in that they are automated, continuous, and driven by simulation outcomes rather than human-administered test cases.

**Key academic finding:** No published paper defines a composite "Detection Effectiveness Score" or "Integrated Hunt & Detection Score" as a quantitative metric computed automatically from simulated attack results. The research community has explicitly identified this as a gap (arXiv:2304.07411). PurpleLab's scoring system fills a documented research gap.

---

## 4. Freedom-to-Operate Summary

| PurpleLab Feature | Blocking Prior Art? | Notes |
|---|---|---|
| Gap-weighted simulation dispatch (closed loop) | **None found** | File PL-P1 |
| Threat intel → detection validation pipeline | **None found** | File PL-P2; watch Picus |
| Single-LLM-round composition / zero-LLM execution | **US12537846** (different architecture) | File PL-P3 with explicit distinction |
| DES scoring formula | **US11973788** (different data source) | Defensive publication; file PL-P1 with formula |
| IHDS composite formula | **None found** | Defensive publication |
| Stateful simulation execution | **US11991203** (different context) | Do not claim intra-simulation branching |
| Basic attack simulation execution | **US9892260, US20160044057** | Do not claim simulation execution mechanics |
| Production-network simulation | **US10757131** | Do not claim distributed production-network simulation |

---

## 5. Sources

- [SafeBreach US9892260 — Google Patents](https://patents.google.com/patent/US9892260B2/en)
- [AttackIQ US20160044057 — USPTO Report](https://uspto.report/patent/app/20160044057)
- [Mandiant/Google US10757131 — Google Patents](https://patents.google.com/patent/US10757131B2/en)
- [Picus/Ironsdc US11991203 — Google Patents](https://patents.google.com/patent/US11991203B2/en)
- [Tenable US11973788 — USPTO PDF](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11973788)
- [Siege Technologies US10270798 — Google Patents](https://patents.google.com/patent/US10270798B2/en)
- [US12537846 — Cybersecurity Engine with LLM, USPTO](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12537846)
- [FireCompass CART Patent Announcement](https://firecompass.com/firecompass-secures-upsto-patent-for-automated-red-teaming/)
- [CardinalOps Detection Posture Management](https://cardinalops.com/eliminate-detection-coverage-gaps-with-automation-and-mitre-attck/)
- [Picus AI BAS Announcement (Oct 2025) — Help Net Security](https://www.helpnetsecurity.com/2025/10/14/picus-security-validation-platform-bas/)
- [SoK: MITRE ATT&CK in Research — arXiv:2304.07411](https://arxiv.org/pdf/2304.07411)
- [Scalable Blue Team Evaluation — arXiv:2312.17221](https://arxiv.org/html/2312.17221)
- [Resilient LLM Agents Plan-then-Execute — arXiv:2509.08646](https://arxiv.org/pdf/2509.08646)
- [SafeBreach BAS Patents — IPWatchdog](https://ipwatchdog.com/2018/06/18/safebreach-issuance-breach-attack-simulation-patents/id=98340/)
