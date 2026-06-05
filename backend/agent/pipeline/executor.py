"""Pipeline executor — runs a pipeline definition produced by the AI.

A pipeline is a JSON-serialisable dict:
{
  "name": "APT29 Coverage Drill",
  "steps": [
    {
      "id": "env",
      "block": "create_environment",
      "inputs": {"name": "APT29 drill", "description": "Quick lab"}
    },
    {
      "id": "profile",
      "block": "apply_threat_profile",
      "inputs": {
        "environment_id": "{{env.environment_id}}",
        "threat_actor": "APT29"
      }
    },
    {
      "id": "score",
      "block": "calculate_scores",
      "inputs": {}
    }
  ]
}

Template values `{{step_id.output_key}}` are resolved after each step completes.

Execution is sequential (topological by dependency order). Parallel execution is
a future enhancement — for now ordering via step list position is sufficient.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from backend.agent.pipeline.blocks import BLOCK_REGISTRY, get_block

logger = logging.getLogger(__name__)

_TMPL_RE = re.compile(r"\{\{(\w+)\.(\w+)\}\}")


class PipelineError(Exception):
    """Raised when a pipeline step fails — includes step_id and cause."""
    def __init__(self, step_id: str, block_id: str, cause: Exception) -> None:
        super().__init__(f"step '{step_id}' ({block_id}) failed: {cause}")
        self.step_id = step_id
        self.block_id = block_id
        self.cause = cause


def _resolve(value: Any, outputs: dict[str, Any]) -> Any:
    """Recursively resolve {{step.key}} templates in strings, lists, and dicts."""
    if isinstance(value, str):
        # If the entire string is one template, return the raw resolved value (preserves type)
        single = _TMPL_RE.fullmatch(value.strip())
        if single:
            step_id, key = single.group(1), single.group(2)
            step_out = outputs.get(step_id, {})
            if key not in step_out:
                raise ValueError(f"Template '{{{{{{step_id}}.{key}}}}}' not found — step '{step_id}' output keys: {list(step_out.keys())}")
            return step_out[key]
        # Otherwise inline substitution (always produces string)
        def _sub(m: re.Match) -> str:
            step_id, key = m.group(1), m.group(2)
            val = outputs.get(step_id, {}).get(key, m.group(0))
            return str(val)
        return _TMPL_RE.sub(_sub, value)

    if isinstance(value, list):
        return [_resolve(item, outputs) for item in value]

    if isinstance(value, dict):
        return {k: _resolve(v, outputs) for k, v in value.items()}

    return value


class PipelineExecutor:
    """Execute a pipeline definition and return step-by-step results."""

    async def run(self, pipeline: dict[str, Any]) -> dict[str, Any]:
        """Run all steps and return a structured result.

        Returns:
          {
            "pipeline_name": str,
            "steps_run": int,
            "steps_succeeded": int,
            "steps_failed": int,
            "outputs": {step_id: output_dict},
            "step_results": [...],   ← ordered list for display
            "summary": str,          ← human-readable summary
          }
        """
        name = pipeline.get("name", "Unnamed pipeline")
        steps = pipeline.get("steps", [])
        if not steps:
            return {"pipeline_name": name, "steps_run": 0, "steps_succeeded": 0,
                    "steps_failed": 0, "outputs": {}, "step_results": [],
                    "summary": "Pipeline has no steps."}

        # Validate block IDs upfront
        for step in steps:
            bid = step.get("block")
            if not bid or not get_block(bid):
                available = sorted(BLOCK_REGISTRY.keys())
                return {
                    "error": f"Unknown block '{bid}' in step '{step.get('id', '?')}'. Available: {available}",
                    "pipeline_name": name, "steps_run": 0, "steps_succeeded": 0,
                    "steps_failed": 0, "outputs": {}, "step_results": [],
                    "summary": f"Pipeline aborted: unknown block '{bid}'.",
                }

        all_outputs: dict[str, dict] = {}
        step_results: list[dict] = []
        succeeded = 0
        failed = 0

        for step in steps:
            step_id: str = step.get("id", f"step_{len(step_results)}")
            block_id: str = step["block"]
            raw_inputs: dict = step.get("inputs", {})
            block_def = get_block(block_id)
            assert block_def is not None  # already validated above

            # Resolve templates
            try:
                resolved_inputs = _resolve(raw_inputs, all_outputs)
            except ValueError as tmpl_err:
                err_msg = str(tmpl_err)
                logger.error("pipeline_template_error step=%s err=%s", step_id, err_msg)
                step_results.append({
                    "step_id": step_id,
                    "block": block_id,
                    "label": block_def.label,
                    "status": "error",
                    "error": err_msg,
                    "output": {},
                })
                failed += 1
                # Template errors are fatal — we can't continue without the input
                break

            logger.info("pipeline_step_start step=%s block=%s inputs=%s", step_id, block_id, list(resolved_inputs.keys()))

            try:
                output = await block_def.fn(**resolved_inputs)
                all_outputs[step_id] = output
                step_results.append({
                    "step_id": step_id,
                    "block": block_id,
                    "label": block_def.label,
                    "status": "success",
                    "output": output,
                })
                succeeded += 1
                logger.info("pipeline_step_done step=%s output_keys=%s", step_id, list(output.keys()))
            except Exception as exc:
                logger.error("pipeline_step_error step=%s block=%s err=%s", step_id, block_id, exc)
                step_results.append({
                    "step_id": step_id,
                    "block": block_id,
                    "label": block_def.label,
                    "status": "error",
                    "error": str(exc),
                    "output": {},
                })
                failed += 1
                # Non-template errors are non-fatal — continue remaining steps
                # unless the next step depends on this one's output (template will fail cleanly)

        # Build human summary
        if failed == 0:
            summary = f"All {succeeded} steps completed successfully."
        elif succeeded == 0:
            summary = f"Pipeline failed — all {failed} steps encountered errors."
        else:
            summary = f"{succeeded} of {succeeded + failed} steps completed successfully; {failed} step(s) failed."

        return {
            "pipeline_name": name,
            "steps_run": succeeded + failed,
            "steps_succeeded": succeeded,
            "steps_failed": failed,
            "outputs": all_outputs,
            "step_results": step_results,
            "summary": summary,
        }
