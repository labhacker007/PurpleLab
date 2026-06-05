"""Pipeline executor — wave-based parallel execution.

Architecture:
  1. VALIDATE  — block IDs exist, required inputs present, connection types match
  2. DAG BUILD — parse {{step_id.output_key}} refs → dependency graph (Kahn's algo)
  3. EXECUTE   — asyncio.gather() per wave; steps in the same wave run concurrently
  4. RESOLVE   — each step gets only its declared inputs, not the full context bag

Token efficiency:
  The AI composes the pipeline JSON once (1 LLM round).
  All waves execute server-side in one tool call (0 further LLM rounds).
  Each step receives only its resolved inputs — no accumulated context growth.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from backend.agent.pipeline.blocks import BLOCK_REGISTRY, get_block

logger = logging.getLogger(__name__)

_TMPL_RE = re.compile(r"\{\{(\w+)\.(\w+)\}\}")

# JSON-Schema-style type compatibility table (source_type → accepted_target_types)
_COMPAT: dict[str, set[str]] = {
    "string":  {"string"},
    "integer": {"integer", "number", "string"},
    "number":  {"number", "string"},
    "boolean": {"boolean", "string"},
    "array":   {"array"},
    "object":  {"object"},
}


# ── Dependency parsing ────────────────────────────────────────────────────────

def _extract_deps(raw_inputs: Any) -> set[str]:
    """Return all step IDs referenced via {{step_id.key}} in a value tree."""
    deps: set[str] = set()

    def _scan(v: Any) -> None:
        if isinstance(v, str):
            for m in _TMPL_RE.finditer(v):
                deps.add(m.group(1))
        elif isinstance(v, list):
            for item in v:
                _scan(item)
        elif isinstance(v, dict):
            for val in v.values():
                _scan(val)

    _scan(raw_inputs)
    return deps


def _extract_refs(raw_inputs: Any) -> list[tuple[str, str]]:
    """Return all (step_id, output_key) pairs referenced in a value tree."""
    refs: list[tuple[str, str]] = []

    def _scan(v: Any) -> None:
        if isinstance(v, str):
            for m in _TMPL_RE.finditer(v):
                refs.append((m.group(1), m.group(2)))
        elif isinstance(v, list):
            for item in v:
                _scan(item)
        elif isinstance(v, dict):
            for val in v.values():
                _scan(val)

    _scan(raw_inputs)
    return refs


# ── Topological sort (Kahn's algorithm) ──────────────────────────────────────

def _topological_waves(steps: list[dict]) -> list[list[dict]]:
    """Group steps into waves — all steps within a wave are independent (no deps on each other).

    Steps in the same wave execute concurrently via asyncio.gather().
    Critical-path latency = sum of slowest step per wave, NOT sum of all steps.
    """
    id_to_step = {s.get("id", f"_s{i}"): s for i, s in enumerate(steps)}
    valid_ids = set(id_to_step.keys())

    # Build dependency graph (only count deps on other pipeline steps)
    dep_graph: dict[str, set[str]] = {
        sid: _extract_deps(s.get("inputs", {})) & valid_ids
        for sid, s in id_to_step.items()
    }

    resolved: set[str] = set()
    remaining = dict(id_to_step)
    waves: list[list[dict]] = []
    max_iter = len(steps) + 1  # cycle guard

    while remaining and max_iter > 0:
        max_iter -= 1
        # Steps whose deps are all already resolved → can run this wave
        ready = [sid for sid in remaining if dep_graph[sid].issubset(resolved)]

        if not ready:
            # Cycle: fall back — grab remaining steps sequentially one at a time
            logger.warning("pipeline_dag_cycle: falling back to sequential for remaining steps")
            ready = [next(iter(remaining))]

        wave = [remaining.pop(sid) for sid in ready]
        resolved.update(ready)
        waves.append(wave)

    return waves


# ── Pre-execution validation ──────────────────────────────────────────────────

def validate_pipeline(pipeline: dict[str, Any]) -> list[str]:
    """Validate a pipeline definition before execution. Returns list of error strings.

    Checks:
    - All block IDs exist
    - All required inputs are provided (as literals or {{...}} refs)
    - All {{step_id.output_key}} refs point to existing steps + declared output keys
    - Type compatibility between connected outputs and inputs
    """
    errors: list[str] = []
    steps = pipeline.get("steps", [])
    if not steps:
        return ["Pipeline has no steps"]

    # Index blocks and collect per-step declared output keys
    step_block: dict[str, str] = {}
    for step in steps:
        sid = step.get("id")
        bid = step.get("block")
        if not sid:
            errors.append(f"Step is missing 'id' field: {step}")
            continue
        if not bid:
            errors.append(f"Step '{sid}' is missing 'block' field")
            continue
        if not get_block(bid):
            errors.append(f"Step '{sid}': unknown block '{bid}'. Available: {sorted(BLOCK_REGISTRY.keys())}")
            continue
        step_block[sid] = bid

    if errors:
        return errors  # can't proceed without valid block refs

    # Check required inputs + connection compatibility
    for step in steps:
        sid = step.get("id", "")
        bid = step_block.get(sid)
        if not bid:
            continue
        block_def = get_block(bid)
        raw_inputs = step.get("inputs", {})

        # Check required inputs exist
        for input_name, input_spec in block_def.inputs.items():
            if input_spec.get("required", False) and input_name not in raw_inputs:
                errors.append(f"Step '{sid}' ({bid}): required input '{input_name}' is missing")

        # Check {{...}} refs resolve to valid step+output
        for ref_step_id, ref_key in _extract_refs(raw_inputs):
            if ref_step_id not in step_block:
                errors.append(
                    f"Step '{sid}' ({bid}): references '{{{{{{ref_step_id}}.{ref_key}}}}}' "
                    f"but step '{ref_step_id}' does not exist in this pipeline"
                )
                continue
            ref_block = get_block(step_block[ref_step_id])
            if ref_key not in ref_block.outputs:
                declared = list(ref_block.outputs.keys())
                errors.append(
                    f"Step '{sid}' ({bid}): references '{{{{{{ref_step_id}}.{ref_key}}}}}' "
                    f"but '{ref_step_id}' ({step_block[ref_step_id]}) only declares outputs: {declared}"
                )
                continue

            # Type compatibility check (best-effort — only when input type is declared)
            for input_name, input_spec in block_def.inputs.items():
                val = raw_inputs.get(input_name)
                if not isinstance(val, str):
                    continue
                m = _TMPL_RE.fullmatch(val.strip())
                if m and m.group(1) == ref_step_id and m.group(2) == ref_key:
                    src_type = ref_block.outputs.get(ref_key, {}).get("type", "")
                    dst_type = input_spec.get("type", "")
                    if src_type and dst_type:
                        compatible = _COMPAT.get(src_type, {dst_type})
                        if dst_type not in compatible:
                            errors.append(
                                f"Step '{sid}' ({bid}): input '{input_name}' expects type "
                                f"'{dst_type}' but '{{{{{{ref_step_id}}.{ref_key}}}}}' "
                                f"produces '{src_type}'"
                            )

    return errors


# ── Template resolver ─────────────────────────────────────────────────────────

def _resolve(value: Any, outputs: dict[str, Any]) -> Any:
    """Recursively resolve {{step.key}} templates. Preserves original type for single-template values."""
    if isinstance(value, str):
        single = _TMPL_RE.fullmatch(value.strip())
        if single:
            step_id, key = single.group(1), single.group(2)
            step_out = outputs.get(step_id, {})
            if key not in step_out:
                raise ValueError(
                    f"Template '{{{{{step_id}.{key}}}}}' not found — "
                    f"step '{step_id}' outputs: {list(step_out.keys())}"
                )
            return step_out[key]

        def _sub(m: re.Match) -> str:
            sid, k = m.group(1), m.group(2)
            return str(outputs.get(sid, {}).get(k, m.group(0)))

        return _TMPL_RE.sub(_sub, value)

    if isinstance(value, list):
        return [_resolve(item, outputs) for item in value]

    if isinstance(value, dict):
        return {k: _resolve(v, outputs) for k, v in value.items()}

    return value


# ── Executor ──────────────────────────────────────────────────────────────────

class PipelineError(Exception):
    def __init__(self, step_id: str, block_id: str, cause: Exception) -> None:
        super().__init__(f"step '{step_id}' ({block_id}) failed: {cause}")
        self.step_id = step_id
        self.block_id = block_id
        self.cause = cause


class PipelineExecutor:
    """Execute a pipeline definition using wave-based parallel execution."""

    async def run(self, pipeline: dict[str, Any]) -> dict[str, Any]:
        """Validate, build DAG, execute waves concurrently, return structured result.

        Result shape:
          pipeline_name, steps_run, steps_succeeded, steps_failed,
          waves_run, outputs, step_results, validation_errors, summary
        """
        name = pipeline.get("name", "Unnamed pipeline")
        steps = pipeline.get("steps", [])

        if not steps:
            return _empty_result(name, "Pipeline has no steps.")

        # 1. Validate
        validation_errors = validate_pipeline(pipeline)
        if validation_errors:
            return {
                "pipeline_name": name,
                "validation_errors": validation_errors,
                "steps_run": 0, "steps_succeeded": 0, "steps_failed": 0,
                "waves_run": 0, "outputs": {}, "step_results": [],
                "summary": f"Pipeline validation failed: {validation_errors[0]}",
            }

        # 2. Build execution waves
        waves = _topological_waves(steps)
        logger.info("pipeline_start name=%r steps=%d waves=%d", name, len(steps), len(waves))

        # 3. Execute wave by wave
        all_outputs: dict[str, Any] = {}
        step_results: list[dict] = []
        succeeded = 0
        failed = 0
        aborted_early = False

        for wave_idx, wave in enumerate(waves):
            wave_label = f"wave_{wave_idx + 1}"
            wave_step_ids = [s.get("id", "") for s in wave]
            logger.info("pipeline_%s steps=%s", wave_label, wave_step_ids)

            # Run all steps in this wave concurrently
            wave_tasks = [
                _run_step(step, all_outputs, wave_idx + 1)
                for step in wave
            ]
            wave_outcomes = await asyncio.gather(*wave_tasks)

            for step, (step_id, output, error, status) in zip(wave, wave_outcomes):
                block_id = step["block"]
                block_def = get_block(block_id)
                label = block_def.label if block_def else block_id

                result_entry = {
                    "step_id": step_id,
                    "block": block_id,
                    "label": label,
                    "wave": wave_idx + 1,
                    "status": status,
                }
                if status == "success":
                    all_outputs[step_id] = output
                    result_entry["output"] = output
                    succeeded += 1
                    logger.info("pipeline_step_ok step=%s outputs=%s", step_id, list(output.keys()))
                else:
                    result_entry["error"] = error
                    result_entry["output"] = {}
                    failed += 1
                    logger.error("pipeline_step_err step=%s err=%s", step_id, error)
                    # Template errors are always fatal — the step that needs this data can't proceed
                    if status == "template_error":
                        aborted_early = True

                step_results.append(result_entry)

            if aborted_early:
                remaining = sum(len(w) for w in waves[wave_idx + 1:])
                if remaining:
                    logger.warning("pipeline_aborted_early remaining_steps=%d", remaining)
                break

        # 4. Build summary
        total_steps = len(steps)
        if aborted_early:
            summary = (
                f"Pipeline aborted after a template error. "
                f"{succeeded} step(s) succeeded, {failed} failed, "
                f"{total_steps - succeeded - failed} skipped."
            )
        elif failed == 0:
            summary = f"All {succeeded} steps completed successfully across {len(waves)} wave(s)."
        elif succeeded == 0:
            summary = f"Pipeline failed — all {failed} steps encountered errors."
        else:
            summary = (
                f"{succeeded} of {succeeded + failed} steps succeeded "
                f"across {len(waves)} wave(s); {failed} step(s) failed."
            )

        return {
            "pipeline_name": name,
            "steps_run": succeeded + failed,
            "steps_succeeded": succeeded,
            "steps_failed": failed,
            "waves_run": len(waves),
            "outputs": all_outputs,
            "step_results": step_results,
            "validation_errors": [],
            "summary": summary,
        }


async def _run_step(
    step: dict, all_outputs: dict[str, Any], wave_num: int
) -> tuple[str, dict | None, str | None, str]:
    """Execute a single step. Returns (step_id, output, error_msg, status)."""
    step_id: str = step.get("id", "")
    block_id: str = step["block"]
    block_def = get_block(block_id)

    # Resolve template inputs
    try:
        resolved_inputs = _resolve(step.get("inputs", {}), all_outputs)
    except ValueError as tmpl_err:
        return step_id, None, str(tmpl_err), "template_error"

    # Execute the block function
    try:
        output = await block_def.fn(**resolved_inputs)
        return step_id, output, None, "success"
    except Exception as exc:
        return step_id, None, str(exc), "error"


def _empty_result(name: str, summary: str) -> dict[str, Any]:
    return {
        "pipeline_name": name,
        "steps_run": 0, "steps_succeeded": 0, "steps_failed": 0,
        "waves_run": 0, "outputs": {}, "step_results": [],
        "validation_errors": [], "summary": summary,
    }
