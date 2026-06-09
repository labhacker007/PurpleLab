# Patent Technical Disclosure
## PL-P2: Automated Threat-Intelligence-to-Detection-Validation Feedback Pipeline

**Disclosure ID:** PL-P2  
**Date of Invention:** 2025–2026  
**Inventors:** [To be completed before filing]  
**Assignee:** [Company name to be completed]  
**Status:** Ready for provisional patent application filing  
**Priority:** HIGH — File within 90 days. Picus announced a partial commercial analog (no patent filed) in October 2025.

---

## Title of Invention

System and Method for Automated Threat-Intelligence-to-Detection-Validation Feedback Pipeline with Coverage-Gated Simulation Dispatch and Simulation-Log-Driven Detection Rule Generation

---

## Technical Field

The present invention relates to cybersecurity automation systems, and more particularly to an automated pipeline that converts threat intelligence artifacts into validated detection capabilities by: extracting adversary techniques from intelligence sources, checking whether those techniques are covered by existing validated detection rules, dispatching targeted simulations only for uncovered techniques, generating candidate detection rules from simulation execution logs, validating those rules against the simulation logs, creating detection use case records, and updating the detection coverage store — all without requiring human engineering intervention between stages.

---

## Background of the Invention

### The Gap Between Threat Intelligence and Detection Engineering

Organizations face a structural operational gap: their threat intelligence team consumes reports about adversary activity (indicators of compromise, tactics, techniques, and procedures) while their detection engineering team maintains the SIEM rules and EDR signatures that detect those adversaries. These two functions operate largely independently, with intelligence-to-detection translation happening manually, infrequently, and incompletely.

When a threat intelligence analyst reads a report about a ransomware group using credential dumping (T1003), lateral movement via remote services (T1021), and data exfiltration over HTTP (T1048), they may create a threat intelligence record. However, whether the organization's SIEM actually has validated, working detection rules for these specific techniques is often unknown. The analyst cannot easily answer: "Do we detect this? Have we verified it works? If not, can we automatically create a detection?"

### The Manual Detection Engineering Bottleneck

Creating a detection rule from a threat intelligence report currently requires:
1. An analyst to read the report and identify techniques
2. A detection engineer to research the technique's behavioral signatures
3. The engineer to write a Sigma rule or SIEM-native query
4. QA testing of the rule against sample data
5. Deployment to the SIEM
6. Validation that the deployed rule fires against real or simulated data

This process takes days to weeks per technique and requires two or more skilled personnel. The result is that detection engineering perpetually lags behind threat intelligence, and coverage gaps persist for months.

### Prior Art and Its Limitations

**Threat intelligence platforms** (Recorded Future, ThreatConnect, Anomali, Mandiant Advantage) ingest and normalize threat intelligence and produce ATT&CK-mapped technique records. However, they do not check whether the consuming organization has working detections for those techniques, do not trigger simulations, and do not generate detection rules.

**BAS platforms** (SafeBreach, AttackIQ, Picus) run attack simulations and produce pass/fail results. They do not ingest threat intelligence to select which techniques to simulate, do not generate detection rules from simulation logs, and do not create detection use case records.

**Picus October 2025 announcement:** Picus announced an AI-powered feature to convert threat intelligence into simulations. The disclosed architecture covers: threat intel → TTP extraction → simulation execution → AI-generated report. **Key limitations of the Picus approach:** (1) dispatches simulations for all extracted techniques regardless of existing coverage — wastes simulation resources on already-covered techniques; (2) does not generate detection rules from simulation logs; (3) does not create detection use case records; (4) does not close the loop back to a coverage store. No patent has been filed for this capability.

**AI-driven detection rule generation tools** (Anvilogic, Panther, Hunters) generate SIEM queries from natural language or templates but do not ground the generation in simulation execution logs that prove the rule would fire on real behavioral data.

**IntelEX** (arXiv:2412.10872, NUS/NTU, December 2024) describes a system that extracts TTPs from CTI reports and generates Sigma rules using LLM with in-context learning. IntelEX achieves 0.902 F1 on technique identification. However, IntelEX: (1) does not check existing detection coverage per technique before dispatching; (2) processes all extracted techniques regardless of whether detection rules exist; (3) uses pre-collected attack telemetry as training context rather than live simulation dispatch gated on coverage gaps; (4) does not create detection use case records or update a coverage store. IntelEX covers stages 1 and 4 of the present invention but lacks the coverage gate (stage 2), coverage-gated dispatch (stage 3), and coverage feedback loop (stage 7).

**CTI-REALM** (arXiv:2603.13517, Microsoft Security AI, March 2026) is a benchmark framework for evaluating AI agents on end-to-end detection engineering. It provides 37 pre-recorded attack simulation telemetry samples and scores agents on TTP extraction, log query, and Sigma/KQL rule generation. CTI-REALM: (1) is a benchmark/evaluation framework, not an operational pipeline; (2) uses pre-recorded telemetry from pre-executed simulations (not live simulation dispatch); (3) has no coverage gate — all 37 samples are presented to all agents regardless of existing detection coverage; (4) has no detection use case creation; (5) has no coverage store update. CTI-REALM validates the scientific feasibility of stages 1, 4, and 5 but does not anticipate the present invention's coverage-gated architecture.

**No existing system** combines: (1) threat intelligence ingestion with technique extraction, (2) coverage-gated dispatch (simulate only uncovered techniques), (3) simulation-log-driven detection rule generation, (4) simulation-based rule validation (the rule fires on the same logs that proved the behavior), and (5) detection use case creation with feedback to the coverage store — in a single automated pipeline.

---

## Summary of the Invention

The present invention provides an automated pipeline that operationalizes threat intelligence into validated detection capabilities without requiring human engineering between stages.

The pipeline comprises seven sequential stages executed automatically upon receipt of a threat intelligence artifact:

1. **TTP Extraction** — Extract adversary technique identifiers from the intelligence artifact using named entity recognition or structured data parsing
2. **Coverage Check** — Query the technique coverage store (see PL-P1) for each extracted technique; identify the subset for which no validated detection rule exists
3. **Coverage-Gated Dispatch** — Dispatch simulation tasks only for the uncovered subset; skip techniques already COVERED (preserving simulation resources)
4. **Simulation Execution** — Execute attack behaviors corresponding to each uncovered technique in an instrumented environment; collect detailed execution logs
5. **Detection Rule Generation** — Invoke an AI function to generate candidate detection rules in a standardized format (e.g., Sigma YAML) grounded in the specific behavioral evidence in the simulation logs
6. **Simulation-Based Rule Validation** — Execute each candidate detection rule against the simulation execution logs to verify it produces a detection event; discard rules that do not fire
7. **Detection Use Case Creation and Coverage Update** — Create a detection use case record associating the validated rule with the technique and originating intelligence artifact; update the coverage store to COVERED for that technique

The key inventive contributions are: (a) coverage-gated dispatch — only uncovered techniques enter the simulation stage; (b) grounding detection rule generation in simulation execution logs rather than templates or natural language alone; (c) simulation-based rule validation before use case creation; and (d) the fully automated end-to-end pipeline from intelligence artifact to validated detection without human intervention between stages.

---

## Detailed Description of Preferred Embodiments

### Embodiment 1: Core Pipeline Architecture

#### Stage 1: Threat Intelligence Ingestion and TTP Extraction

The pipeline accepts threat intelligence artifacts in multiple formats:
- Structured STIX 2.1 bundles (via TAXII feed or direct upload)
- Semi-structured reports (PDF, Word, HTML) processed by a document parser
- Unstructured natural language text processed by a named entity recognition (NER) model

TTP extraction produces a set of ATT&CK technique identifiers:

```python
extraction_result = {
    "artifact_id": "article-uuid",
    "artifact_title": "APT29 Spring 2026 Campaign",
    "extracted_techniques": ["T1059.001", "T1566.002", "T1003.001", "T1048.003"],
    "extraction_confidence": {"T1059.001": 0.97, "T1566.002": 0.89, ...},
    "threat_actor": "APT29",
}
```

Only technique identifiers with extraction confidence above a configurable threshold (default: 0.75) proceed to Stage 2.

#### Stage 2: Coverage Check

For each extracted technique identifier, the system queries the technique coverage store and classifies it as:
- COVERED — has a validated detection rule; skip this technique (do not simulate)
- PARTIAL — rule exists but unvalidated; include in uncovered set
- UNCOVERED — no rule; include in uncovered set

The coverage check result produces two lists:
- `covered_techniques` — will be referenced in the use case but require no simulation
- `uncovered_techniques` — will proceed through simulation, rule generation, and validation stages

If all extracted techniques are COVERED, the pipeline concludes by creating a threat intelligence reference record but skips the simulation and rule generation stages — minimizing resource consumption.

#### Stage 3: Coverage-Gated Simulation Dispatch

For each technique in `uncovered_techniques`, the dispatcher:

1. Selects the most appropriate simulation scenario from the catalog (highest fidelity for the technique, compatible with the environment configuration)
2. Creates a simulation task associated with the originating intelligence artifact
3. Dispatches the task to the simulation execution engine

Tasks from the same intelligence artifact are batched and executed together, with a maximum configurable batch size (default: 5 techniques per artifact to manage simulation queue depth).

#### Stage 4: Simulation Execution and Log Collection

The simulation execution engine executes each attack behavior in an instrumented environment. For each simulated technique, the engine collects:

- **Process execution logs** — command line arguments, parent-child process relationships, file handles
- **Network logs** — connections, DNS queries, TLS SNI values, data volumes
- **Registry logs** — key reads, writes, deletes (Windows environments)
- **File system logs** — creates, reads, writes, deletes, permission changes
- **Authentication logs** — logon events, privilege escalations, token manipulations

These logs are structured and stored as the `simulation_execution_log` associated with the task. Critically, these logs represent ground truth behavioral evidence — they are the definitive record of what happened during the technique execution.

#### Stage 5: Simulation-Log-Grounded Detection Rule Generation

An AI function generates candidate detection rules grounded in the simulation execution log:

```python
generation_input = {
    "technique_id": "T1059.001",
    "technique_name": "Command and Scripting Interpreter: PowerShell",
    "simulation_execution_log": {
        "processes": [{"cmdline": "powershell.exe -EncodedCommand ...", ...}],
        "network": [],
        "registry": [{"key": "HKCU\\...", "value": "...", ...}],
    },
    "target_format": "sigma",
    "siem_platform": "splunk",
    "instruction": "Generate a Sigma rule that detects the specific behavior observed in these simulation logs",
}
```

The AI function produces one or more candidate rules in Sigma YAML format. Grounding the generation in actual simulation logs (rather than template-based generation) ensures that:
- The rule targets the specific behavioral signatures that were actually present during execution
- The rule is not over-broad (targeting generic PowerShell use) but specific to the observed execution pattern
- The rule can be validated against the same logs in Stage 6

#### Stage 6: Simulation-Based Rule Validation

Each candidate rule is executed against the simulation execution log using a Sigma rule evaluation engine (e.g., pySigma with appropriate backend).

Validation outcome:
- **PASS** — the rule produces a match against the simulation log. The rule is considered validated.
- **FAIL** — the rule does not match. The rule is discarded. If no candidate rules pass for a technique, the technique is flagged for manual detection engineering review.

This validation step is critical: it proves that the rule would have fired during the actual simulated attack, providing a higher confidence guarantee than static rule review.

#### Stage 7: Detection Use Case Creation and Coverage Update

For each technique with at least one validated rule:

1. A **detection use case record** is created:
```python
DetectionUseCase = {
    "technique_id": "T1059.001",
    "sigma_rule_yaml": "<validated rule YAML>",
    "validation_status": "validated",
    "source_technique": "T1059.001",
    "source_artifact_id": "article-uuid",
    "source_artifact_title": "APT29 Spring 2026 Campaign",
    "simulation_session_id": "sim-uuid",
    "detection_fired_count": 3,
    "deployment_status": "pending_deployment",
}
```

2. The **coverage store is updated** for the technique to COVERED with the use case ID as the associated detection record.

3. A **gap_closed notification** is emitted to the security operations team confirming that a detection gap identified from threat intelligence has been automatically remediated.

4. If the organization's automation policy allows it, the validated rule is automatically submitted to the SIEM deployment queue for production deployment.

---

### Embodiment 2: Integration with Threat Intelligence Platform

In a preferred embodiment, the pipeline receives trigger events from a connected Threat Intelligence Platform (TIP). When the TIP ingests and scores a new article above a quality threshold, it emits an event containing the extracted technique identifiers and associated metadata. The pipeline subscribes to this event stream and immediately begins Stage 2 for each qualifying article.

This allows the pipeline to operate in near-real-time: within hours of a threat intelligence report being published and ingested, the pipeline can identify uncovered techniques, execute simulations, generate detection rules, and create use cases — compressing the typical days-to-weeks detection engineering timeline to hours.

---

### Embodiment 3: Batch Pipeline Processing

In an alternative embodiment, the pipeline operates in batch mode on a schedule (e.g., nightly). All threat intelligence artifacts received since the last batch are processed together. Uncovered techniques across all artifacts are deduplicated, and the gap list is prioritized using the same risk-weighted scoring from PL-P1. This allows organizations with high-volume intelligence ingestion to manage simulation queue depth.

---

### Embodiment 4: Human-in-the-Loop Validation Gate

In an alternative embodiment, the detection use case creation step (Stage 7) includes an optional review gate. The system presents the generated rule, its validation result, and the simulation evidence to a detection engineer for review before creating the use case record. This embodiment is appropriate for organizations with compliance requirements mandating human review of new detection rules before deployment.

---

## Claims

### Independent Claims

**Claim 1.** A computer-implemented method for automated creation of validated detection capabilities from threat intelligence artifacts, comprising:
- (a) receiving a threat intelligence artifact;
- (b) extracting, from the threat intelligence artifact, a set of adversary technique identifiers from a standardized adversary behavior framework;
- (c) querying a technique coverage store to determine, for each extracted adversary technique identifier, whether a validated detection rule exists that has been confirmed effective through prior simulation;
- (d) identifying an uncovered subset comprising adversary technique identifiers for which no such validated detection rule exists;
- (e) dispatching, automatically and without human engineering intervention, simulation tasks targeting each adversary technique identifier in the uncovered subset to a simulation execution engine;
- (f) receiving simulation execution logs from the simulation execution engine comprising behavioral data recorded during execution of each simulated adversary technique;
- (g) generating, using an automated rule generation function operating on the simulation execution logs, one or more candidate detection rules in a standardized detection rule format;
- (h) validating each candidate detection rule by executing it against the simulation execution logs and confirming that the rule produces a detection event matching the simulated behavior;
- (i) creating a detection use case record associating each validated detection rule with the corresponding adversary technique identifier and the originating threat intelligence artifact; and
- (j) updating the technique coverage store to reflect the validated detection rule for the corresponding adversary technique identifier.

**Claim 2.** The method of claim 1, wherein step (e) dispatches simulation tasks only for adversary technique identifiers in the uncovered subset, and does not dispatch simulation tasks for adversary technique identifiers that are already validated in the technique coverage store, such that simulation resources are allocated exclusively to uncovered techniques.

**Claim 3.** A system for automated operationalization of threat intelligence into validated detection capabilities, comprising:
- a threat intelligence ingestion module configured to receive threat intelligence artifacts and extract adversary technique identifiers;
- a coverage check module configured to query a technique coverage store and identify technique identifiers lacking validated detection rules;
- a simulation dispatcher configured to automatically generate and dispatch simulation tasks targeting only uncovered technique identifiers;
- a simulation execution engine configured to execute attack behaviors and produce structured execution logs;
- a detection rule generation module configured to generate candidate detection rules grounded in the simulation execution logs;
- a rule validation module configured to execute each candidate rule against the execution logs and retain only rules that produce matching detection events; and
- a use case registry configured to store validated detection rules associated with their originating technique identifiers and threat intelligence artifacts.

### Dependent Claims

**Claim 4.** The method of claim 1, wherein the standardized detection rule format is Sigma YAML, enabling translation to multiple SIEM-native query languages.

**Claim 5.** The method of claim 1, wherein the automated rule generation function is a large language model prompted with the simulation execution logs as grounding evidence, such that generated rules reference the specific behavioral signatures observed during simulation rather than generic technique signatures.

**Claim 6.** The method of claim 1, wherein generating candidate detection rules further comprises generating multiple candidate rules per technique and selecting the rule achieving the highest detection precision against the simulation logs.

**Claim 7.** The method of claim 1, further comprising: submitting each validated detection rule to a SIEM deployment queue for automated deployment to the organization's production SIEM system upon confirmation that the rule's false positive rate estimate is below a configurable threshold.

**Claim 8.** The method of claim 1, wherein the technique coverage store is updated in real-time upon creation of the detection use case record, such that subsequent threat intelligence artifacts referencing the same adversary technique identifier are classified as covered at step (c) and no simulation is dispatched for that technique.

**Claim 9.** The method of claim 1, wherein extracting adversary technique identifiers comprises applying a named entity recognition model trained on cybersecurity text to identify ATT&CK technique references in unstructured natural language text of the threat intelligence artifact.

**Claim 10.** The method of claim 1, wherein if no candidate detection rule passes validation for a technique identifier, storing the simulation execution log as evidence for human detection engineering review and retaining the technique identifier in an UNCOVERED state in the coverage store.

**Claim 11.** The method of claim 1, further comprising: computing a threat intelligence operationalization score for an organization comprising the fraction of threat intelligence artifacts processed in a time window for which at least one new detection use case was created, as a measure of the organization's threat-informed detection engineering velocity.

**Claim 12.** The method of claim 1, wherein the threat intelligence artifact is a STIX 2.1 bundle received via a TAXII 2.1 collection, and extracting adversary technique identifiers comprises parsing ATT&CK pattern expressions from STIX Attack Pattern objects within the bundle.

---

## Abstract

A system and method for automatically converting threat intelligence artifacts into validated detection capabilities. Upon ingesting a threat intelligence artifact, the system extracts adversary technique identifiers, checks a coverage store to identify techniques lacking validated detection rules, and automatically dispatches simulations only for uncovered techniques — skipping techniques already covered to conserve resources. Simulation execution logs are collected and fed to a detection rule generation function that produces candidate Sigma rules grounded in the behavioral evidence from the simulation. Each candidate rule is validated by executing it against the same logs; only rules that produce detection events are accepted. Validated rules are stored as detection use cases associated with the originating technique and intelligence artifact, and the coverage store is updated. The pipeline operates end-to-end without human engineering intervention between stages, compressing detection engineering timelines from days to hours.

---

## Drawings (Described — Diagrams to be prepared for full utility application)

- **FIG. 1** — End-to-end pipeline flow: TI Artifact → TTP Extraction → Coverage Check → [Covered: skip | Uncovered: dispatch] → Simulation → Log Collection → Rule Generation → Validation → Use Case Creation → Coverage Store Update
- **FIG. 2** — Coverage check branching: extracted technique set split into COVERED (reference only) and UNCOVERED (full pipeline)
- **FIG. 3** — Rule generation and validation: simulation log → LLM → candidate rules → Sigma evaluation engine → validated rules (pass) / discarded rules (fail)
- **FIG. 4** — Detection use case record structure: technique_id, sigma_yaml, validation_status, source_artifact, simulation_session, detection_fired_count
- **FIG. 5** — Timeline compression: manual process (days/weeks) vs. automated pipeline (hours)
- **FIG. 6** — Real-time TIP integration: TIP event stream → pipeline trigger → stages 2-7 → use case creation → TIP coverage update notification

---

## Notes for Patent Counsel

**Key novelty:** The coverage-gated dispatch (step e + claim 2) is the central invention. No prior art routes simulation dispatch through a coverage check — all existing BAS systems either require manual scenario selection or simulate all techniques indiscriminately. The combination of (1) checking coverage first, (2) simulating only uncovered techniques, and (3) grounding rule generation in simulation logs appears in no prior patent or academic paper.

**Distinction from Picus October 2025 announcement:** Picus's disclosed pipeline covers TI→simulation→report. PL-P2 adds: coverage-gated dispatch (step c-e), simulation-log-grounded rule generation (step g), simulation-based rule validation (step h), and use case creation with coverage store update (steps i-j). These four stages are absent from Picus's disclosure.

**Distinction from AI-driven detection tools:** Tools like Anvilogic generate SIEM rules from natural language. The novelty in PL-P2 is grounding rule generation in simulation execution logs (step g) and validating the rule against those same logs (step h). The generated rule is not template-based but is derived from actual behavioral evidence.
