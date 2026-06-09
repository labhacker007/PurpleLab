# Patent Technical Disclosure
## PL-P1: Gap-Weighted Automated Simulation Dispatch with Closed-Loop Detection Coverage Convergence

**Disclosure ID:** PL-P1  
**Date of Invention:** 2025–2026  
**Inventors:** [To be completed before filing]  
**Assignee:** [Company name to be completed]  
**Status:** Ready for provisional patent application filing  
**Priority:** HIGHEST — File within 60 days. Picus announced a partial commercial analog (no patent filed) in October 2025.

---

## Title of Invention

System and Method for Gap-Weighted Automated Simulation Dispatch with Closed-Loop Detection Coverage Convergence

---

## Technical Field

The present invention relates to cybersecurity automation systems, and more particularly to a system and method for automatically identifying gaps in an organization's adversary technique detection coverage, prioritizing and dispatching targeted attack simulations against those gaps, measuring whether detection rules fire during simulation, and iteratively updating the coverage state to converge toward complete detection coverage without requiring human intervention between cycles.

---

## Background of the Invention

### The Detection Coverage Problem

Organizations deploying security information and event management (SIEM) systems, endpoint detection and response (EDR) platforms, and other security monitoring technologies face a fundamental measurement problem: they do not know which adversary techniques their detection stack can actually detect versus which techniques would go undetected during a real attack.

The MITRE ATT&CK framework (Adversarial Tactics, Techniques, and Common Knowledge) provides a standardized taxonomy of adversary behaviors organized into hundreds of named techniques (identified by T-codes such as T1059 for Command and Scripting Interpreter). While organizations map their detection rules to ATT&CK techniques, this mapping does not verify that the rules actually fire when the technique is executed. A rule may exist for a technique but fail to fire due to misconfiguration, log source gaps, or evasion.

### Prior Art and Its Limitations

**Breach and Attack Simulation (BAS) platforms** such as SafeBreach (US9892260B2, 2015), AttackIQ (US20160044057, 2015), and Mandiant/Google (US10757131B2, 2019) execute attack simulations and report pass/fail outcomes. However, these systems do not:
1. Maintain a persistent technique coverage store tracking which techniques have been *validated* through simulation
2. Automatically select which techniques to simulate next based on what is *uncovered*
3. Close the feedback loop by updating coverage state after simulation and re-prioritizing future simulations accordingly
4. Weight simulation dispatch by technique risk to maximize coverage improvement per simulation cycle

**Security control scoring systems** such as Tenable (US11973788B2, 2021) score existing deployed controls against vulnerability scan data using weighted averaging. However, these systems score controls against static scan data rather than measuring detection rule firing against dynamic attack simulation outcomes, and do not trigger simulations to validate uncovered controls.

**Detection posture management systems** (CardinalOps, commercial) analyze SIEM rule deployments to identify ATT&CK coverage gaps. However, these are purely passive analysis systems that do not dispatch simulations to validate or close the identified gaps. CardinalOps has filed no patents (confirmed via USPTO search as of June 2026).

**FireCompass Continuous Automated Red Teaming** (US20210352100A1, filed May 2021, Firecompass Technologies) discloses a continuous automated red teaming system with a reinforcement-learning-based learning loop that adapts based on simulation outcomes. However, FireCompass's system: (1) uses "attack frontiers" for traversal optimization (finding new attack paths through a network), not MITRE ATT&CK technique identifier–keyed coverage states; (2) does not maintain a per-technique coverage state machine (UNCOVERED/PARTIAL/COVERED) tracking whether a detection rule fires for each technique; (3) does not implement a risk-weighted technique selection formula based on threat intelligence frequency, severity, and time-since-simulated; and (4) dispatches simulations to find new network attack paths, not to validate detection rules for specific ATT&CK techniques. FireCompass is directed to penetration test path discovery; PL-P1 is directed to detection coverage validation per ATT&CK technique. These are architecturally and functionally distinct objectives.

**DeTT&CT** (Rabobank-CDC, open source, 2019–present) provides manual per-technique ATT&CK coverage scoring in YAML files and exports to ATT&CK Navigator layers. DeTT&CT requires human-authored YAML scoring and does not dispatch simulations, compute risk-weighted rankings, or close any feedback loop.

**No existing system** combines: (1) a persistent technique coverage store tracking simulation-validated coverage state, (2) automated identification and risk-weighted prioritization of uncovered techniques, (3) automated simulation dispatch targeting only uncovered techniques, (4) coverage state update from simulation outcomes, and (5) iterative repetition creating a self-converging coverage improvement loop.

### Summary of the Problem

The result of these limitations is that organizations' detection coverage either stagnates or drifts. Manual red team exercises are infrequent and expensive. Existing BAS tools require human operators to select which scenarios to run. Detection posture tools identify gaps but cannot close them automatically. There is no existing automated system that continuously identifies, simulates, and closes detection coverage gaps with minimal human intervention.

---

## Summary of the Invention

The present invention provides a computer-implemented system and method for automated, iterative detection coverage improvement through gap-weighted simulation dispatch.

The core inventive concept is a closed feedback loop comprising five components that execute repeatedly:

1. **Coverage Store** — A persistent data structure mapping each adversary technique identifier to one of three coverage states: (a) UNCOVERED — no validated detection rule; (b) PARTIALLY COVERED — rule exists but has not been confirmed to fire in simulation; (c) COVERED — at least one detection rule has successfully produced a detection event when the technique was executed in simulation.

2. **Gap Analyzer** — A component that queries the coverage store and produces a ranked list of UNCOVERED technique identifiers, ordered by a weighted risk score derived from at least two factors: (a) technique frequency in recent threat intelligence (how often adversaries use this technique), and (b) technique severity (the potential impact if undetected).

3. **Simulation Dispatcher** — A component that, without human initiation, generates simulation tasks targeting the ranked uncovered techniques and dispatches them to the simulation execution engine. Crucially, simulation tasks are dispatched *only* for techniques in UNCOVERED or PARTIALLY COVERED state, not for COVERED techniques, ensuring simulation resources are allocated where coverage improvement is possible.

4. **Outcome Processor** — A component that receives simulation execution logs indicating which, if any, detection rules produced detection events during each simulated technique execution, and updates the coverage store accordingly.

5. **Convergence Controller** — A component that schedules the gap analysis, dispatch, and outcome processing cycle at a configurable interval (e.g., every 24 hours), and tracks coverage convergence metrics over time.

The combined effect is that the system continuously finds what is not detected, simulates attacks against those gaps, validates whether detections fire, and updates its knowledge of what is covered — then repeats. Over successive cycles, the UNCOVERED set shrinks as techniques are either validated (moved to COVERED) or flagged for detection rule creation (remaining UNCOVERED but now with simulation evidence).

---

## Detailed Description of Preferred Embodiments

### Embodiment 1: Core Closed-Loop Architecture

#### 1.1 Technique Coverage Store

The coverage store is implemented as a database table with the following logical schema:

```
TechniqueCoverageRecord:
  technique_id       : VARCHAR — ATT&CK technique identifier (e.g., "T1059.001")
  coverage_state     : ENUM(UNCOVERED, PARTIAL, COVERED)
  last_simulated_at  : TIMESTAMP — when the technique was last targeted in simulation
  last_covered_at    : TIMESTAMP — when coverage was last validated
  detection_rule_ids : JSON ARRAY — IDs of rules that fired in simulation
  simulation_count   : INTEGER — number of times simulated
  risk_score         : FLOAT — composite risk weight for dispatch prioritization
  org_id             : UUID — organizational tenant identifier
```

Coverage state transitions:
- UNCOVERED → PARTIAL: a detection rule exists in the org's detection inventory for this technique
- PARTIAL → COVERED: a simulation executed the technique and the detection rule produced a detection event
- COVERED → PARTIAL: time-based decay (configurable, e.g., 90 days without re-validation)
- PARTIAL → UNCOVERED: detection rule deleted or disabled from inventory

#### 1.2 Gap Analysis and Risk-Weighted Ranking

The gap analyzer queries all techniques in UNCOVERED or PARTIAL state and computes a composite risk score:

```
risk_score(t) = α × frequency_weight(t) + β × severity_weight(t) + γ × time_weight(t)
```

Where:
- `frequency_weight(t)` — normalized count of threat intelligence reports referencing technique `t` in a recent time window (e.g., 90 days)
- `severity_weight(t)` — MITRE ATT&CK assigned severity tier or custom organizational severity override
- `time_weight(t)` — inverse of days since last simulated (prioritizes techniques not recently targeted)
- `α, β, γ` — configurable weights summing to 1.0

The output is an ordered list of technique identifiers, highest risk score first.

#### 1.3 Simulation Task Generation and Dispatch

For each technique in the ranked gap list (up to a configurable batch size per cycle), the system:

1. Queries the simulation catalog for available scenario templates targeting the technique
2. Selects scenarios matching the org's configured environment (SIEM platform, EDR, network topology)
3. Creates a simulation task record associating the technique, selected scenarios, and current cycle
4. Dispatches the task to the simulation execution engine via the pipeline block interface

If no catalog scenario exists for a technique, the technique is flagged in the coverage store with `no_scenario_available = TRUE` and excluded from dispatch until a scenario becomes available.

#### 1.4 Outcome Processing and Coverage State Update

After each simulation task completes:

1. The execution engine produces a structured outcome log containing: technique ID, scenario ID, list of detection events (rule ID, event timestamp, severity), and a binary pass/fail determination
2. The outcome processor reads the log and updates the coverage store:
   - If ≥1 detection event produced: `coverage_state = COVERED`, `last_covered_at = now()`, `detection_rule_ids = [rule_ids from events]`
   - If 0 detection events produced: `coverage_state = UNCOVERED`, `simulation_count += 1`, log simulation evidence for detection engineering review
3. A gap_closed event is emitted for each UNCOVERED→COVERED transition (feeds notification and reporting systems)

#### 1.5 Convergence Metrics

The convergence controller computes and stores per-cycle metrics:

```
coverage_percentage = COVERED_count / total_technique_count × 100
gap_closure_rate = techniques_moved_to_COVERED_this_cycle / UNCOVERED_count_start_of_cycle
estimated_cycles_to_full_coverage = UNCOVERED_count / moving_average(gap_closure_rate)
```

These metrics drive the executive detection coverage dashboard and IHDS scoring inputs.

---

### Embodiment 2: Integration with Detection Effectiveness Scoring (DES)

In a preferred embodiment, the coverage store state feeds directly into the Detection Effectiveness Score (DES):

```
DES = geometric_mean(
  breadth_score,      — COVERED_count / total_technique_count
  depth_score,        — average detection_rule_count per COVERED technique
  freshness_score,    — fraction of COVERED techniques validated within recency_window
  pass_rate_score,    — fraction of simulations that produced detection events
  signal_quality      — average alert severity of detection events produced
)
```

The gap-weighted dispatch directly improves DES by increasing `breadth_score` and `pass_rate_score` over successive cycles.

---

### Embodiment 3: Multi-Tenant Gap Prioritization

In a multi-tenant deployment, each tenant organization maintains its own coverage store with its own detection inventory, simulation history, and risk weights. Gap prioritization is computed per-tenant, allowing different organizations to converge at different rates based on their specific detection stack and threat profile.

Tenant-specific customizations include:
- Custom frequency weights based on organization industry (e.g., financial sector weighs T1566 Phishing higher)
- Custom severity overrides based on organizational risk assessment
- Custom recency windows for freshness decay
- Excluded techniques (e.g., techniques not in scope for compliance frameworks)

---

### Embodiment 4: Notification and Human-in-the-Loop Gate

In an alternative embodiment, the simulation dispatch step includes an optional human-in-the-loop (HITL) gate:

- The gap analyzer produces the ranked list and creates a pending dispatch queue
- A notification is sent to the security operations team with the proposed simulation batch
- The team can approve (execute as proposed), modify (change target techniques or batch size), or defer
- After a configurable timeout (e.g., 4 hours), the batch auto-approves if no response is received

This embodiment is appropriate for organizations that wish to audit simulation activity before execution.

---

## Claims

### Independent Claims

**Claim 1.** A computer-implemented method for closing detection coverage gaps in a security operations environment, comprising:
- (a) maintaining, by a computing system, a technique coverage store mapping each adversary technique identifier from a standardized adversary behavior framework to a coverage state, wherein a COVERED state requires that at least one detection rule associated with the technique identifier has successfully produced a detection event when the technique was executed in an automated simulation;
- (b) identifying, by a gap analyzer, a set of uncovered technique identifiers from the technique coverage store for which no such validated detection rule exists;
- (c) computing, for each uncovered technique identifier, a weighted risk score derived from at least (i) a measure of technique frequency in recent threat intelligence data and (ii) a measure of technique severity;
- (d) generating, automatically and without requiring human initiation, one or more simulation tasks targeting the uncovered technique identifiers in order of their weighted risk scores;
- (e) dispatching the simulation tasks to a simulation execution engine configured to execute attack behaviors corresponding to the targeted technique identifiers in an instrumented computing environment;
- (f) receiving simulation outcome data from the simulation execution engine indicating, for each dispatched simulation task, whether any detection rule produced a detection event during the simulation;
- (g) updating the technique coverage store based on the simulation outcome data, transitioning technique identifiers for which detection events were produced to a COVERED state; and
- (h) repeating steps (b) through (g) at a configurable interval, thereby iteratively reducing the set of uncovered technique identifiers through simulation-driven feedback.

**Claim 2.** The method of claim 1, wherein the standardized adversary behavior framework is the MITRE ATT&CK framework, and each adversary technique identifier is an ATT&CK technique code.

**Claim 3.** A computer-implemented system for automated detection coverage improvement, comprising:
- a technique coverage store storing, for each adversary technique identifier, a coverage state and associated metadata comprising at least a timestamp of last simulation and an array of detection rule identifiers that have fired against the technique in simulation;
- a gap analyzer configured to query the technique coverage store and produce a ranked list of uncovered technique identifiers ordered by a weighted risk score;
- an automated simulation dispatcher configured to generate simulation tasks targeting the ranked uncovered technique identifiers and dispatch them without requiring human initiation;
- a simulation execution engine configured to execute attack behaviors corresponding to the targeted technique identifiers and produce structured outcome logs; and
- an outcome processor configured to update the technique coverage store based on the outcome logs.

### Dependent Claims

**Claim 4.** The method of claim 1, wherein the coverage state comprises at least three states: UNCOVERED indicating no detection rule exists for the technique, PARTIALLY COVERED indicating a detection rule exists but has not been confirmed effective through simulation, and COVERED indicating the detection rule has been confirmed effective through simulation.

**Claim 5.** The method of claim 1, wherein the weighted risk score further incorporates a time weight derived from the inverse of the elapsed time since the technique was last simulated, such that techniques not recently targeted receive higher priority.

**Claim 6.** The method of claim 1, further comprising: computing a coverage convergence metric comprising a coverage percentage equal to the ratio of COVERED technique identifiers to total technique identifiers in scope, and tracking the coverage percentage over successive iterations to measure convergence progress.

**Claim 7.** The method of claim 1, wherein updating the technique coverage store further comprises: when simulation outcome data indicates that no detection rule produced a detection event for a targeted technique, storing the simulation execution log as evidence for detection engineering review, and incrementing a simulation attempt counter for the technique.

**Claim 8.** The method of claim 1, wherein the configurable interval and batch size of simulation tasks per interval are dynamically adjusted based on the rate of coverage convergence observed in prior iterations.

**Claim 9.** The method of claim 1, wherein the COVERED state is subject to time-based decay such that a COVERED technique transitions back to PARTIALLY COVERED after a configurable recency window without re-validation through simulation.

**Claim 10.** The method of claim 1, wherein the simulation tasks are dispatched only for technique identifiers in the uncovered set and not for technique identifiers already in COVERED state, such that simulation resources are concentrated on improving coverage rather than validating already-covered techniques.

**Claim 11.** The method of claim 1, wherein the simulation outcome data further feeds a Detection Effectiveness Score computation comprising a weighted geometric mean of at least: a breadth dimension measuring the fraction of in-scope technique identifiers in COVERED state, a depth dimension measuring the average number of detection rules per COVERED technique, and a freshness dimension measuring the fraction of COVERED techniques validated within a recency window.

**Claim 12.** The method of claim 1, wherein the gap analyzer computes separate weighted risk scores per organizational tenant, allowing different organizations sharing a multi-tenant deployment to maintain independent technique coverage stores and dispatch schedules.

---

## Abstract

A system and method for automated, iterative detection coverage improvement through gap-weighted simulation dispatch. A technique coverage store maps adversary technique identifiers to coverage states. A gap analyzer identifies uncovered techniques and ranks them by a weighted risk score incorporating threat frequency and technique severity. An automated dispatcher generates and dispatches simulation tasks targeting the highest-risk uncovered techniques without human intervention. An outcome processor updates the coverage store based on whether detection rules fired during simulation. The process repeats on a configurable schedule, causing the set of uncovered techniques to shrink over successive iterations as the system converges toward complete detection coverage. No prior art combines gap identification, risk-weighted simulation prioritization, simulation dispatch, outcome-driven coverage state update, and iterative convergence in a single automated feedback loop.

---

## Drawings (Described — Diagrams to be prepared for full utility application)

- **FIG. 1** — High-level closed-loop architecture: Coverage Store → Gap Analyzer → Dispatcher → Simulation Engine → Outcome Processor → Coverage Store (with iteration arrow)
- **FIG. 2** — Coverage store state machine: UNCOVERED ↔ PARTIAL ↔ COVERED with transition conditions
- **FIG. 3** — Risk score computation: frequency weight + severity weight + time weight → composite score → ranked gap list
- **FIG. 4** — Simulation task lifecycle: gap list entry → task creation → dispatch → execution → outcome log → store update
- **FIG. 5** — Coverage convergence graph over time: UNCOVERED count decreasing across successive cycles
- **FIG. 6** — Multi-tenant architecture: per-tenant coverage stores with shared simulation engine

---

## Notes for Patent Counsel

**Claim 1 distinction from US11973788 (Tenable):** Tenable claims scoring security controls against vulnerability scan data. Claim 1 specifically requires simulation-driven validation ("successfully produced a detection event when the technique was executed in an automated simulation") — a fundamentally different data source and validation mechanism.

**Claim 1 distinction from US11991203 (Picus):** Picus claims intra-simulation stateful branching (next attack step depends on prior step outcome within a single scenario). Claim 1 describes inter-simulation dispatch selection (which techniques to simulate is based on cross-session coverage store state). Completely different scope.

**Claim 1 distinction from SafeBreach/AttackIQ:** Those patents claim simulation execution mechanics. Claim 1 does not claim how simulations are executed, only the loop that selects what to simulate, updates coverage state, and repeats.

**Claim 1 distinction from FireCompass US20210352100A1:** FireCompass uses RL-based "attack frontier" traversal to optimize penetration test path discovery through a live network. This is distinct in three ways: (a) objective — FireCompass finds new attack paths through a network; PL-P1 validates detection rules for ATT&CK techniques; (b) data model — FireCompass has no per-ATT&CK-technique coverage state; PL-P1's coverage store is keyed by ATT&CK technique identifier; (c) loop purpose — FireCompass's RL loop learns better attack strategies; PL-P1's loop converges toward detection coverage completeness. Examiner may attempt to combine FireCompass (closed loop) + CardinalOps (ATT&CK technique coverage). Counter: the combination would not suggest using simulation outcomes to update a per-technique state machine, nor the risk-weighted dispatch formula.

**Claim 1 distinction from DeTT&CT (open source prior art):** DeTT&CT requires human-authored YAML coverage scoring; it does not compute risk-weighted rankings, dispatch simulations, or close any feedback loop. The "automated" element of Claim 1(d) is the key distinction.

**Strongest novel element:** Step (d) — generating simulation tasks automatically without human initiation, specifically for uncovered techniques only, based on risk-weighted ranking of the gap. The three-part risk formula (frequency_weight × α + severity_weight × β + time_weight × γ) as the ranking mechanism for simulation dispatch is not found in any prior art.

**Working code:** `backend/agent/pipeline/blocks.py` `get_gap_analysis` block + `run_scenario` block implement stages (b)–(e). The coverage state machine transitions are in the proposed coverage store schema. Enablement is strong.
