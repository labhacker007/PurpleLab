# Patent Technical Disclosure
## PL-P3: Single-Round LLM Composition with Deterministic Server-Side Execution for Security Simulation Pipelines

**Disclosure ID:** PL-P3  
**Date of Invention:** 2025–2026  
**Inventors:** [To be completed before filing]  
**Assignee:** [Company name to be completed]  
**Status:** Ready for provisional patent application filing  
**Priority:** MEDIUM — File with PL-P1 and PL-P2 as part of the same provisional application to establish priority date and reduce filing costs.

---

## Title of Invention

System and Method for Single-Round Language Model Composition of Typed Security Simulation Pipeline Definitions with Zero-Language-Model-Call Deterministic Server-Side Execution

---

## Technical Field

The present invention relates to artificial intelligence-assisted security operations automation, and more particularly to a system in which a language model is invoked exactly once to compose a complete, typed, serializable directed acyclic graph (DAG) representing a multi-step security simulation pipeline, after which all pipeline steps are executed deterministically by a server-side execution engine without any further language model invocations, using inter-step output reference templates to chain data between steps.

---

## Background of the Invention

### The Problem with Iterative LLM Agent Architectures in Security

Large language models (LLMs) are increasingly used in security operations to orchestrate multi-step workflows: running attack simulations, analyzing results, querying threat intelligence, generating detection rules, and producing reports. The predominant architecture for LLM-driven multi-step task execution is the **ReAct pattern** (Reasoning + Acting), in which the LLM is called once per step: it reasons about what action to take, the action is executed, and the result is fed back to the LLM as context for the next step.

This iterative architecture has fundamental cost and latency problems for security simulation workflows:
- **Token cost grows quadratically**: each LLM call includes all prior steps' outputs in its context window. For an N-step pipeline with average step output size S and per-step reasoning tokens R, total tokens = N×R + S×N×(N-1)/2
- **Latency adds up**: LLM API latency (typically 1–5 seconds per call) is incurred at every step. A 10-step pipeline has 10–50 seconds of LLM API latency in the critical path
- **Steps execute sequentially**: because each LLM call decides the next action, steps cannot be parallelized even when they are data-independent
- **Consistency degrades**: each successive LLM call may produce different tool selection decisions, creating non-deterministic execution behavior

Published analysis (LLMCompiler, ICML 2024) demonstrates that these issues result in 3–7× higher token costs and 3–4× higher latency compared to plan-then-execute architectures for multi-step tasks.

### Prior Art: LLM-in-Execution-Loop Systems

**US12537846** (USPTO, 2024) — "Cybersecurity Engine" — discloses a system in which a language model is called iteratively during execution: the LLM "prepares prompts" and "receives responses" at multiple steps during the orchestration process. This is the ReAct/iterative architecture applied to security operations. It directly represents the prior art that PL-P3 improves upon.

**Plan-then-execute LLM patterns** (arXiv:2509.08646 and others) describe the general paradigm of using LLMs to plan a sequence of actions before execution begins. However, these general patterns do not specify: (1) typed input/output port schemas for each block, (2) inter-step output reference template syntax, (3) serializable pipeline JSON representation, or (4) application to security simulation domain blocks.

**Apache Airflow, n8n, Prefect, Dagster** — pipeline orchestration systems using DAG representations and template-based inter-step data passing. These systems use visual/code-based DAG authoring — they do not use LLMs to compose the DAG from natural language intent.

**No existing system** combines: (1) single-LLM-round pipeline composition from natural language, (2) typed security simulation block schemas exposing input/output port specifications, (3) `{{step_id.output_key}}` output reference template syntax for data chaining, (4) pre-execution type validation, (5) topological sort for parallel wave grouping, and (6) fully deterministic zero-LLM server-side execution.

---

## Summary of the Invention

The present invention provides a system for composing and executing security simulation pipelines in which the LLM is invoked exactly once — to transform natural language intent into a complete pipeline definition — after which the engine executes all steps deterministically using no further LLM calls.

The system comprises four components:

1. **Block Registry** — A catalog of typed security simulation blocks, each declaring its identifier, input port schema (name, type, required flag), and output port schema (name, type). The registry serves as the LLM's complete vocabulary of available operations. Block schemas are exposed via a discovery endpoint (`GET /pipeline/blocks`) so the LLM retrieves current schemas dynamically rather than relying on static training knowledge.

2. **Composition Engine** — Accepts a natural language description of a simulation workflow, fetches the block registry schemas, and invokes the LLM exactly once with a structured prompt. The LLM's response is a complete pipeline definition: a JSON document specifying pipeline name, and an array of steps, each with a unique step ID, a block identifier, and a resolved input map (literal values or `{{step_id.output_key}}` reference tokens). No further LLM calls are made after this response.

3. **Pre-Execution Validator** — Before any step is executed, the pipeline definition is validated: (a) all block identifiers exist in the registry, (b) all required inputs are provided, (c) all `{{step_id.output_key}}` references point to declared output keys on existing steps, (d) connected types are compatible per a type compatibility table. Validation errors are returned to the user before execution begins — no partial execution occurs for invalid pipelines.

4. **Deterministic Execution Engine** — Parses `{{step_id.output_key}}` references to build a dependency graph, applies Kahn's topological sort algorithm to group independent steps into parallel waves, and executes each wave using concurrent async execution. Within a wave, steps execute concurrently. Between waves, steps execute sequentially in dependency order. At no point during execution is the LLM invoked. Data flows between steps via template resolution: when a step begins, all `{{step_id.output_key}}` tokens in its input map are resolved by substituting the actual values produced by the referenced prior step.

**Token efficiency:** The total LLM token cost is constant regardless of pipeline length — one composition call per pipeline. A 10-step pipeline costs the same LLM tokens as a 2-step pipeline. Under the iterative ReAct architecture, the same 10-step pipeline would cost approximately 5–7× more LLM tokens (depending on step output sizes and reasoning length).

---

## Detailed Description of Preferred Embodiments

### Embodiment 1: Block Registry and Schema Discovery

The block registry contains typed specifications for each security simulation block. Each block definition comprises:

```
BlockDefinition:
  block_id    : STRING — unique identifier (e.g., "create_environment")
  category    : ENUM(infrastructure, threat_intel, simulation, scoring, detection, reporting, utility)
  label       : STRING — human-readable display name
  description : STRING — semantic description used by LLM for block selection
  inputs      : MAP<name, InputSpec>
  outputs     : MAP<name, OutputSpec>
  tags        : ARRAY<STRING>

InputSpec:
  type        : ENUM(string, integer, number, boolean, array, object)
  required    : BOOLEAN
  description : STRING

OutputSpec:
  type        : ENUM(string, integer, number, boolean, array, object)
  description : STRING
```

The registry is exposed via a discovery API endpoint. The LLM queries this endpoint dynamically to obtain current block schemas, eliminating the need to encode block specifications in training data or static system prompts. When a new block is added to the registry, it immediately becomes available to the LLM without any prompt engineering changes.

Example block definition (JSON form returned by discovery endpoint):

```json
{
  "id": "run_scenario_batch",
  "category": "simulation",
  "label": "Run Scenario Batch",
  "description": "Execute multiple simulation scenarios concurrently and collect outcome data",
  "inputs": {
    "scenario_ids": {"type": "array", "required": true, "description": "List of scenario IDs to execute"},
    "max_concurrent": {"type": "integer", "required": false, "description": "Max concurrent executions; default 5"}
  },
  "outputs": {
    "sessions": {"type": "array", "description": "Simulation session records"},
    "session_ids": {"type": "array", "description": "IDs of created sessions"},
    "total_run": {"type": "integer", "description": "Count of scenarios executed"},
    "errors": {"type": "array", "description": "Scenarios that failed to execute"}
  }
}
```

The registry currently contains blocks for: environment creation, product configuration, threat profile application, scenario listing, individual scenario execution, batch scenario execution, use case execution, all-use-case execution, coverage scoring, gap analysis, Sigma rule import, detection use case creation, SIEM deployment, report generation, and no-operation wait steps.

---

### Embodiment 2: Single-Round LLM Composition

The composition engine constructs a structured prompt containing:
1. The block registry schemas (retrieved fresh from the discovery endpoint)
2. The `{{step_id.output_key}}` template syntax specification
3. The required JSON output format (pipeline definition schema)
4. The user's natural language intent

Example prompt structure (condensed):

```
You are a security simulation pipeline composer. Available blocks:
<block registry schemas>

Pipeline format:
{"name": "<string>", "steps": [{"id": "<unique>", "block": "<block_id>", "inputs": {...}}]}

Data flow: use {{step_id.output_key}} to pass outputs from prior steps as inputs.
Independent steps execute in parallel automatically.

User intent: "Run an APT29 red team exercise against our environment and calculate scores"

Respond with only the pipeline JSON. No explanation.
```

The LLM responds with a complete pipeline definition:

```json
{
  "name": "APT29 Red Team Exercise",
  "steps": [
    {"id": "env", "block": "create_environment", "inputs": {"name": "APT29 Exercise"}},
    {"id": "profile", "block": "apply_threat_profile",
     "inputs": {"environment_id": "{{env.environment_id}}", "threat_actor": "APT29"}},
    {"id": "scenarios", "block": "list_scenarios",
     "inputs": {"technique_ids": "{{profile.technique_ids}}"}},
    {"id": "batch", "block": "run_scenario_batch",
     "inputs": {"scenario_ids": "{{scenarios.scenario_ids}}"}},
    {"id": "score", "block": "calculate_scores", "inputs": {}}
  ]
}
```

This is the **only** LLM invocation for the entire pipeline. The engine proceeds to validation and execution without calling the LLM again.

---

### Embodiment 3: Pre-Execution Type Validation

The validator checks the pipeline definition before any execution begins:

```
VALIDATION CHECKS:
1. For each step:
   a. block_id exists in registry
   b. step.id is unique within the pipeline
2. For each step's inputs:
   a. all required inputs are present (as literals or {{...}} references)
   b. for each {{step_id.output_key}} reference:
      - step_id refers to a step defined earlier in the pipeline
      - output_key is declared in the referenced step's block outputs schema
      - output type is compatible with the receiving input type (per compatibility table)
```

Type compatibility table:

| Output type | Compatible input types |
|-------------|----------------------|
| string | string |
| integer | integer, number, string |
| number | number, string |
| boolean | boolean, string |
| array | array |
| object | object |

Validation returns a list of error strings. If non-empty, the pipeline is rejected before execution begins and all errors are returned to the user. This allows the LLM to retry composition with corrected instructions.

---

### Embodiment 4: Topological Sort and Parallel Wave Execution

The execution engine builds a dependency graph by parsing all `{{step_id.output_key}}` references across all steps' input values. Steps with no unresolved dependencies are grouped into Wave 1. After Wave 1 completes, steps whose dependencies are now all resolved form Wave 2. This continues until all steps are assigned to a wave.

For the example pipeline above:
- Wave 1: `env` (no dependencies), `score` (no dependencies) — execute concurrently
- Wave 2: `profile` (depends on `env.environment_id`) — executes after Wave 1
- Wave 3: `scenarios` (depends on `profile.technique_ids`) — executes after Wave 2
- Wave 4: `batch` (depends on `scenarios.scenario_ids`) — executes after Wave 3

Wall-clock execution time = sum of the slowest step per wave (not sum of all steps). Steps in Wave 1 execute concurrently and their combined time equals the slower of the two, not their sum.

This is a direct consequence of the single-round composition architecture: because the full pipeline structure is known before execution begins, the dependency graph can be analyzed upfront and independent steps can be parallelized. The iterative ReAct architecture cannot parallelize steps because it decides each action one at a time.

---

### Embodiment 5: Template Resolution and Type Preservation

At the start of each step's execution, the engine resolves all `{{step_id.output_key}}` references in the step's input map:

- **Single-template values** (the entire input value is `"{{step_id.output_key}}"`) — the referenced value is substituted directly, preserving its original Python type. If the referenced output is a list, the resolved input is a list. If it is an integer, the resolved input is an integer.
- **Inline-template values** (the template appears within a string, e.g., `"drill-{{env.name}}-v2"`) — string interpolation is performed; the result is always a string.

This type preservation is important for downstream steps that receive arrays or structured objects from upstream steps — the receiving block function receives the original data structure without string conversion.

---

## Claims

### Independent Claims

**Claim 1.** A computer-implemented system for composing and executing security simulation pipelines, comprising:
- (a) a block registry storing typed specifications for a plurality of security simulation block types, each specification comprising a block identifier, an input port schema specifying named inputs with type and required flag, and an output port schema specifying named outputs with type;
- (b) a discovery endpoint configured to expose the block registry as structured data retrievable by a language model;
- (c) a composition engine configured to receive a natural language description of a desired simulation workflow, retrieve the block registry from the discovery endpoint, invoke a language model exactly once with the natural language description and the retrieved block registry, and receive from the language model a pipeline definition comprising a directed acyclic graph of steps, each step specifying a block identifier, a unique step identifier, and an input map in which inter-step data dependencies are expressed as reference tokens of the form `{{step_identifier.output_key}}`; and
- (d) a deterministic execution engine configured to, without invoking the language model again: parse the reference tokens to determine inter-step dependencies, group independent steps into parallel execution waves using topological sorting, execute steps within each wave concurrently, resolve reference tokens by substituting actual output values from previously completed steps, and return per-step execution results.

**Claim 2.** The system of claim 1, wherein the composition engine invokes the language model exactly once per pipeline execution and the deterministic execution engine makes zero language model invocations, such that the total language model token cost for an N-step pipeline is constant with respect to N.

**Claim 3.** A computer-implemented method for executing a multi-step security simulation workflow, comprising:
- invoking a language model exactly once with a natural language description of the workflow and a registry of available security simulation block types with their typed input/output schemas;
- receiving from the language model a pipeline definition specifying a sequence of steps, each step identifying a block type and an input map using reference tokens to chain outputs of prior steps as inputs;
- validating the pipeline definition by checking that all referenced block types exist, all required inputs are present, and all reference tokens point to declared output keys on existing steps;
- building a dependency graph from the reference tokens;
- grouping steps with no unresolved dependencies into a first parallel execution wave, and subsequent steps into successive waves in topological order;
- executing each wave's steps concurrently using asynchronous execution;
- for each step in each wave, resolving reference tokens by substituting actual output values from previously completed steps before executing the step; and
- returning a structured result comprising per-step outputs, execution status, and summary metrics;
- wherein no language model invocations are made after the initial composition invocation.

### Dependent Claims

**Claim 4.** The system of claim 1, wherein the block registry comprises security simulation block types comprising at least: a simulation environment provisioning block, a threat actor profile application block, a scenario batch execution block, a coverage scoring block, and a report generation block.

**Claim 5.** The system of claim 1, further comprising a pre-execution validator configured to, before executing any step: verify that all block identifiers in the pipeline definition exist in the block registry, verify that all required inputs are provided as literals or resolvable reference tokens, verify that all reference tokens reference output keys declared in the referenced block's output port schema, and verify that connected output and input port types are compatible per a type compatibility table; and to return all validation errors before initiating any execution.

**Claim 6.** The system of claim 1, wherein resolving a reference token of the form `{{step_identifier.output_key}}` whose entire input value consists of the reference token preserves the original data type of the referenced output value, such that array and structured object outputs are received by downstream block functions as their original types without string conversion.

**Claim 7.** The method of claim 3, wherein the registry of available security simulation block types is retrieved dynamically from the discovery endpoint at composition time, such that blocks added to the registry after system deployment are immediately available to the language model without modifying system prompts or retraining the language model.

**Claim 8.** The method of claim 3, wherein the concurrent execution of steps within a parallel wave uses asynchronous I/O to execute all steps in the wave simultaneously, such that the wall-clock time for a wave equals the execution time of the slowest step in the wave rather than the sum of all step execution times.

**Claim 9.** The method of claim 3, wherein if the pipeline definition fails validation, the validation errors are returned to the language model as feedback for a second and final composition attempt, and if the second attempt also fails validation, the pipeline is rejected without execution.

**Claim 10.** The system of claim 1, further comprising a pipeline template registry storing pre-composed pipeline definitions for common security simulation workflows, retrievable by the language model as starting points for customization, such that the language model can modify a template rather than composing from scratch for known workflow patterns.

---

## Abstract

A system and method for composing and executing security simulation pipelines in which a language model is invoked exactly once — to convert a natural language workflow description into a typed, serializable pipeline definition — after which a deterministic server-side execution engine runs all steps with zero additional language model calls. The pipeline definition is a directed acyclic graph of typed security simulation blocks connected by `{{step_id.output_key}}` inter-step output reference tokens. Pre-execution validation catches type mismatches, missing required inputs, and invalid block references before any execution begins. The execution engine performs topological sort to group independent steps into parallel waves, executes each wave concurrently, and resolves reference tokens by substituting actual step outputs. The resulting architecture achieves constant language model token cost regardless of pipeline length and parallel execution of independent steps, as distinct from iterative ReAct architectures in which the language model is called once per step and steps execute sequentially.

---

## Drawings (Described — Diagrams to be prepared for full utility application)

- **FIG. 1** — Architecture overview: Natural Language → [LLM, called once] → Pipeline JSON → Validator → Execution Engine → Results; annotation showing "0 LLM calls" during execution phase
- **FIG. 2** — Block registry schema: BlockDef structure with block_id, inputs (name/type/required), outputs (name/type)
- **FIG. 3** — Pipeline definition JSON structure: name + steps array with id/block/inputs
- **FIG. 4** — `{{step_id.output_key}}` template syntax: example chain showing env→profile→scenarios→batch
- **FIG. 5** — Topological sort wave grouping: dependency graph → wave assignments → parallel execution timeline
- **FIG. 6** — Token cost comparison: PL-P3 (flat line) vs. ReAct/iterative (quadratic growth) as function of pipeline step count
- **FIG. 7** — Type preservation: single-template vs. inline-template resolution behavior

---

## Notes for Patent Counsel

**Primary distinction from US12537846:** That patent describes calling the LLM iteratively during execution. Claim 1(c) and claim 2 explicitly specify "invoke a language model exactly once" and "zero language model invocations" during execution. The architectural inversion is the core novelty.

**Distinction from general plan-then-execute patterns:** General plan-then-execute LLM papers (arXiv:2509.08646) describe the paradigm but not: (1) typed port schemas with input/output type specifications, (2) `{{step_id.output_key}}` reference syntax, (3) pre-execution type validation, (4) dynamic registry discovery via API endpoint, or (5) security simulation domain blocks. The claim should be narrowed to the specific combination of these elements rather than plan-then-execute generally.

**Strongest novel element:** The dynamic discovery endpoint (claim 7) allowing the LLM to retrieve current block schemas at composition time — blocks added after deployment are immediately available without prompt changes. This specific pattern applied to security simulation pipeline composition appears in no prior art.
