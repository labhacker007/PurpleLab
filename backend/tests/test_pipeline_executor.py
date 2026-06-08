"""Unit tests for the pipeline executor — no HTTP calls, no DB.

Tests:
  - _extract_deps     : parses {{step_id.key}} refs correctly
  - _extract_refs     : extracts (step_id, key) pairs from value trees
  - _topological_waves: DAG grouping with Kahn's algorithm
  - _resolve          : template resolution, type preservation, nested values
  - validate_pipeline : all error paths — unknown block, missing input,
                        bad ref, type mismatch, empty pipeline
  - PipelineExecutor  : end-to-end execution with synthetic blocks,
                        parallel wave ordering, error isolation, template errors
"""
from __future__ import annotations

import asyncio
import time
import pytest
from unittest.mock import AsyncMock, patch
from typing import Any

# ── Imports under test ────────────────────────────────────────────────────────
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from backend.agent.pipeline.executor import (
    _extract_deps,
    _extract_refs,
    _topological_waves,
    _resolve,
    validate_pipeline,
    PipelineExecutor,
    PipelineError,
)
from backend.agent.pipeline.blocks import BLOCK_REGISTRY, BlockDef, get_block


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _make_synthetic_block(block_id: str, outputs: dict, delay: float = 0.0) -> BlockDef:
    """Create a fast synthetic block that records its call and returns given outputs."""
    call_log: list[dict] = []

    async def _fn(**kwargs):
        if delay:
            await asyncio.sleep(delay)
        call_log.append({"inputs": kwargs, "time": time.monotonic()})
        return outputs

    blk = BlockDef(
        block_id=block_id,
        category="test",
        label=block_id,
        description="synthetic test block",
        inputs={k: {"type": "string", "required": False} for k in []},
        outputs={k: {"type": "string"} for k in outputs},
        fn=_fn,
    )
    blk._call_log = call_log  # attach for inspection
    return blk


def _pipeline(steps: list[dict], name: str = "Test") -> dict:
    return {"name": name, "steps": steps}


# ────────────────────────────────────────────────────────────────────────────
# _extract_deps
# ────────────────────────────────────────────────────────────────────────────

class TestExtractDeps:
    def test_no_templates(self):
        assert _extract_deps({"name": "APT drill", "count": 5}) == set()

    def test_single_template(self):
        assert _extract_deps({"env_id": "{{env.environment_id}}"}) == {"env"}

    def test_multiple_templates(self):
        deps = _extract_deps({
            "env_id": "{{env.environment_id}}",
            "actor": "{{profile.threat_actor}}",
        })
        assert deps == {"env", "profile"}

    def test_inline_string_template(self):
        deps = _extract_deps({"label": "drill-{{env.name}}-v2"})
        assert deps == {"env"}

    def test_nested_dict(self):
        deps = _extract_deps({"outer": {"inner": "{{step_a.val}}"}})
        assert deps == {"step_a"}

    def test_list_values(self):
        deps = _extract_deps({"ids": ["{{a.id}}", "{{b.id}}", "literal"]})
        assert deps == {"a", "b"}

    def test_deeply_nested(self):
        deps = _extract_deps({"x": {"y": {"z": "{{deep.key}}"}}})
        assert deps == {"deep"}

    def test_same_step_multiple_keys(self):
        deps = _extract_deps({
            "id": "{{env.environment_id}}",
            "name": "{{env.environment_name}}",
        })
        assert deps == {"env"}  # deduplicated


# ────────────────────────────────────────────────────────────────────────────
# _extract_refs
# ────────────────────────────────────────────────────────────────────────────

class TestExtractRefs:
    def test_empty(self):
        assert _extract_refs({}) == []

    def test_single(self):
        refs = _extract_refs({"x": "{{env.environment_id}}"})
        assert ("env", "environment_id") in refs

    def test_multiple_different_keys(self):
        refs = _extract_refs({
            "a": "{{env.environment_id}}",
            "b": "{{env.environment_name}}",
        })
        assert ("env", "environment_id") in refs
        assert ("env", "environment_name") in refs

    def test_from_list(self):
        refs = _extract_refs({"ids": ["{{step_a.val}}", "{{step_b.val}}"]})
        assert ("step_a", "val") in refs
        assert ("step_b", "val") in refs


# ────────────────────────────────────────────────────────────────────────────
# _topological_waves
# ────────────────────────────────────────────────────────────────────────────

class TestTopologicalWaves:
    def test_no_dependencies_all_in_one_wave(self):
        steps = [
            {"id": "a", "block": "calculate_scores", "inputs": {}},
            {"id": "b", "block": "get_gap_analysis", "inputs": {}},
            {"id": "c", "block": "generate_report", "inputs": {}},
        ]
        waves = _topological_waves(steps)
        assert len(waves) == 1
        assert len(waves[0]) == 3

    def test_linear_chain_one_per_wave(self):
        steps = [
            {"id": "a", "block": "create_environment", "inputs": {}},
            {"id": "b", "block": "apply_threat_profile",
             "inputs": {"environment_id": "{{a.environment_id}}"}},
            {"id": "c", "block": "run_scenario",
             "inputs": {"scenario_id": "{{b.scenario_id}}"}},
        ]
        waves = _topological_waves(steps)
        assert len(waves) == 3
        assert waves[0][0]["id"] == "a"
        assert waves[1][0]["id"] == "b"
        assert waves[2][0]["id"] == "c"

    def test_diamond_dag(self):
        """A→B, A→C, B+C→D should produce 3 waves."""
        steps = [
            {"id": "a", "block": "create_environment", "inputs": {}},
            {"id": "b", "block": "apply_threat_profile",
             "inputs": {"environment_id": "{{a.environment_id}}"}},
            {"id": "c", "block": "calculate_scores",
             "inputs": {"ref": "{{a.environment_id}}"}},
            {"id": "d", "block": "generate_report",
             "inputs": {"b_out": "{{b.technique_count}}", "c_out": "{{c.des_score}}"}},
        ]
        waves = _topological_waves(steps)
        # wave 1: a, wave 2: b+c (parallel), wave 3: d
        assert len(waves) == 3
        wave2_ids = {s["id"] for s in waves[1]}
        assert wave2_ids == {"b", "c"}
        assert waves[2][0]["id"] == "d"

    def test_independent_steps_merged_into_same_wave(self):
        steps = [
            {"id": "s1", "block": "calculate_scores", "inputs": {}},
            {"id": "s2", "block": "get_gap_analysis", "inputs": {}},
            {"id": "s3", "block": "generate_report", "inputs": {}},
        ]
        waves = _topological_waves(steps)
        assert len(waves) == 1
        assert len(waves[0]) == 3

    def test_fan_out_from_single_root(self):
        """One create_environment feeds 3 independent apply steps."""
        steps = [
            {"id": "root", "block": "create_environment", "inputs": {}},
            {"id": "b1", "block": "apply_threat_profile",
             "inputs": {"environment_id": "{{root.environment_id}}"}},
            {"id": "b2", "block": "list_scenarios",
             "inputs": {"environment_id": "{{root.environment_id}}"}},
            {"id": "b3", "block": "calculate_scores",
             "inputs": {"ref": "{{root.environment_id}}"}},
        ]
        waves = _topological_waves(steps)
        assert len(waves) == 2
        assert waves[0][0]["id"] == "root"
        assert len(waves[1]) == 3  # b1, b2, b3 all parallel

    def test_real_apt_red_team_template(self):
        """The apt_red_team template should produce 2 waves."""
        from backend.agent.tools.pipeline_tools import _PIPELINE_TEMPLATES
        steps = _PIPELINE_TEMPLATES["apt_red_team"]["steps"]
        waves = _topological_waves(steps)
        # env (no deps), profile (deps on env) → at least 2 waves
        wave_counts = [len(w) for w in waves]
        assert len(waves) >= 2
        # env must be in the first wave
        assert any(s["id"] == "env" for s in waves[0])


# ────────────────────────────────────────────────────────────────────────────
# _resolve
# ────────────────────────────────────────────────────────────────────────────

class TestResolve:
    def test_literal_string_unchanged(self):
        assert _resolve("hello", {}) == "hello"

    def test_single_template_preserves_type(self):
        outputs = {"env": {"environment_id": "uuid-1234"}}
        result = _resolve("{{env.environment_id}}", outputs)
        assert result == "uuid-1234"

    def test_single_template_preserves_list_type(self):
        outputs = {"step": {"ids": ["a", "b", "c"]}}
        result = _resolve("{{step.ids}}", outputs)
        assert result == ["a", "b", "c"]

    def test_single_template_preserves_int_type(self):
        outputs = {"step": {"count": 42}}
        result = _resolve("{{step.count}}", outputs)
        assert result == 42

    def test_inline_string_substitution_always_string(self):
        outputs = {"step": {"val": 99}}
        result = _resolve("score is {{step.val}} points", outputs)
        assert result == "score is 99 points"
        assert isinstance(result, str)

    def test_dict_recursive(self):
        outputs = {"env": {"environment_id": "env-abc"}}
        result = _resolve({"id": "{{env.environment_id}}", "name": "drill"}, outputs)
        assert result == {"id": "env-abc", "name": "drill"}

    def test_list_recursive(self):
        outputs = {"env": {"environment_id": "env-abc"}}
        result = _resolve(["{{env.environment_id}}", "literal"], outputs)
        assert result == ["env-abc", "literal"]

    def test_missing_template_raises(self):
        with pytest.raises(ValueError, match="environment_id"):
            _resolve("{{env.environment_id}}", {"env": {}})

    def test_missing_step_returns_unresolved_in_inline(self):
        # Inline substitution: unresolved refs stay as-is
        result = _resolve("id={{unknown.val}}", {})
        assert "{{unknown.val}}" in result

    def test_non_string_passthrough(self):
        assert _resolve(42, {}) == 42
        assert _resolve(True, {}) is True
        assert _resolve(None, {}) is None


# ────────────────────────────────────────────────────────────────────────────
# validate_pipeline
# ────────────────────────────────────────────────────────────────────────────

class TestValidatePipeline:
    def test_valid_simple_pipeline(self):
        p = _pipeline([
            {"id": "env", "block": "create_environment",
             "inputs": {"name": "test"}},
        ])
        errors = validate_pipeline(p)
        assert errors == []

    def test_empty_pipeline(self):
        errors = validate_pipeline({"name": "x", "steps": []})
        assert len(errors) == 1
        assert "no steps" in errors[0].lower()

    def test_unknown_block(self):
        p = _pipeline([{"id": "s1", "block": "nonexistent_block", "inputs": {}}])
        errors = validate_pipeline(p)
        assert any("nonexistent_block" in e for e in errors)

    def test_missing_required_input(self):
        p = _pipeline([
            {"id": "s1", "block": "create_environment", "inputs": {}},
            # apply_threat_profile requires environment_id and threat_actor
        ])
        errors = validate_pipeline(p)
        # create_environment requires "name" — should be flagged
        assert any("name" in e for e in errors)

    def test_bad_template_ref_to_nonexistent_step(self):
        p = _pipeline([
            {"id": "s1", "block": "apply_threat_profile",
             "inputs": {
                 "environment_id": "{{ghost.environment_id}}",
                 "threat_actor": "APT29",
             }},
        ])
        errors = validate_pipeline(p)
        assert any("ghost" in e for e in errors)

    def test_bad_template_ref_to_wrong_output_key(self):
        p = _pipeline([
            {"id": "env", "block": "create_environment", "inputs": {"name": "test"}},
            {"id": "s2", "block": "apply_threat_profile",
             "inputs": {
                 "environment_id": "{{env.NONEXISTENT_KEY}}",
                 "threat_actor": "APT29",
             }},
        ])
        errors = validate_pipeline(p)
        assert any("NONEXISTENT_KEY" in e for e in errors)

    def test_valid_chain_with_template_refs(self):
        p = _pipeline([
            {"id": "env",     "block": "create_environment",
             "inputs": {"name": "drill"}},
            {"id": "profile", "block": "apply_threat_profile",
             "inputs": {
                 "environment_id": "{{env.environment_id}}",
                 "threat_actor": "APT29",
             }},
        ])
        errors = validate_pipeline(p)
        assert errors == []

    def test_step_missing_id(self):
        p = _pipeline([{"block": "calculate_scores", "inputs": {}}])
        errors = validate_pipeline(p)
        assert any("id" in e.lower() for e in errors)

    def test_multiple_errors_collected(self):
        p = _pipeline([
            {"id": "bad1", "block": "nonexistent_1", "inputs": {}},
            {"id": "bad2", "block": "nonexistent_2", "inputs": {}},
        ])
        errors = validate_pipeline(p)
        assert len(errors) >= 2


# ────────────────────────────────────────────────────────────────────────────
# PipelineExecutor with synthetic blocks
# ────────────────────────────────────────────────────────────────────────────

class TestPipelineExecutor:
    """Uses synthetic blocks patched into BLOCK_REGISTRY to avoid HTTP calls."""

    @pytest.fixture
    def synthetic_registry(self):
        """Temporarily inject synthetic blocks and restore originals on teardown."""
        synthetic = {
            "env_block": _make_synthetic_block(
                "env_block",
                {"environment_id": "env-123", "environment_name": "test-env"},
            ),
            "profile_block": _make_synthetic_block(
                "profile_block",
                {"technique_ids": ["T1059", "T1078"], "technique_count": 2},
            ),
            "score_block": _make_synthetic_block(
                "score_block",
                {"des_score": 72, "ihds_score": 68},
            ),
            "slow_block_a": _make_synthetic_block(
                "slow_block_a", {"result_a": "done"}, delay=0.05,
            ),
            "slow_block_b": _make_synthetic_block(
                "slow_block_b", {"result_b": "done"}, delay=0.05,
            ),
            "error_block": _make_synthetic_block(
                "error_block", {},
            ),
        }

        # Inject into registry
        original = {}
        for k, v in synthetic.items():
            original[k] = BLOCK_REGISTRY.get(k)
            BLOCK_REGISTRY[k] = v

        # Make error_block actually raise
        async def _raise(**_):
            raise RuntimeError("intentional block failure")
        BLOCK_REGISTRY["error_block"].fn = _raise

        yield synthetic

        # Restore
        for k, orig in original.items():
            if orig is None:
                BLOCK_REGISTRY.pop(k, None)
            else:
                BLOCK_REGISTRY[k] = orig

    @pytest.mark.asyncio
    async def test_single_step_succeeds(self, synthetic_registry):
        executor = PipelineExecutor()
        result = await executor.run(_pipeline([
            {"id": "e1", "block": "env_block", "inputs": {}},
        ]))
        assert result["steps_succeeded"] == 1
        assert result["steps_failed"] == 0
        assert result["outputs"]["e1"]["environment_id"] == "env-123"

    @pytest.mark.asyncio
    async def test_template_resolution_across_steps(self, synthetic_registry):
        executor = PipelineExecutor()
        result = await executor.run(_pipeline([
            {"id": "env",     "block": "env_block", "inputs": {}},
            {"id": "profile", "block": "profile_block",
             "inputs": {"environment_id": "{{env.environment_id}}"}},
        ]))
        assert result["steps_succeeded"] == 2
        # profile_block received env.environment_id as input
        call_inputs = synthetic_registry["profile_block"]._call_log[0]["inputs"]
        assert call_inputs.get("environment_id") == "env-123"

    @pytest.mark.asyncio
    async def test_parallel_steps_run_concurrently(self, synthetic_registry):
        """Two slow_block steps with no deps should complete faster than sequential."""
        executor = PipelineExecutor()
        t0 = time.monotonic()
        result = await executor.run(_pipeline([
            {"id": "a", "block": "slow_block_a", "inputs": {}},
            {"id": "b", "block": "slow_block_b", "inputs": {}},
        ]))
        elapsed = time.monotonic() - t0

        assert result["steps_succeeded"] == 2
        assert result["waves_run"] == 1  # both in same wave
        # Both steps have 0.05s delay. Sequential = 0.1s. Parallel ≈ 0.05s.
        assert elapsed < 0.09, f"Expected parallel execution <0.09s, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_wave_ordering(self, synthetic_registry):
        """Dependent steps run in correct wave order."""
        executor = PipelineExecutor()
        result = await executor.run(_pipeline([
            {"id": "env",     "block": "env_block", "inputs": {}},
            {"id": "profile", "block": "profile_block",
             "inputs": {"environment_id": "{{env.environment_id}}"}},
            {"id": "score",   "block": "score_block", "inputs": {}},
        ]))
        # env and score have no mutual deps → wave 1; profile depends on env → wave 2
        assert result["waves_run"] == 2
        wave1_ids = {r["step_id"] for r in result["step_results"] if r["wave"] == 1}
        wave2_ids = {r["step_id"] for r in result["step_results"] if r["wave"] == 2}
        assert "env" in wave1_ids
        assert "score" in wave1_ids
        assert "profile" in wave2_ids

    @pytest.mark.asyncio
    async def test_block_error_is_non_fatal(self, synthetic_registry):
        """An error in one block doesn't prevent independent blocks from running."""
        executor = PipelineExecutor()
        result = await executor.run(_pipeline([
            {"id": "err",   "block": "error_block", "inputs": {}},
            {"id": "score", "block": "score_block", "inputs": {}},
        ]))
        assert result["steps_failed"] == 1
        assert result["steps_succeeded"] == 1
        score_result = next(r for r in result["step_results"] if r["step_id"] == "score")
        assert score_result["status"] == "success"

    @pytest.mark.asyncio
    async def test_template_error_is_fatal(self, synthetic_registry):
        """A step whose upstream failed at runtime gets template_error (not validation_error).

        Strategy:
          1. error_block fails at runtime (raises), so it's NOT added to all_outputs.
          2. downstream references {{broken.produced_value}}.
          3. Validation passes because we temporarily declare produced_value as an output.
          4. At runtime _resolve raises ValueError → status=template_error.
        """
        error_blk = BLOCK_REGISTRY["error_block"]
        # Temporarily declare an output so validate_pipeline passes
        original_outputs = error_blk.outputs
        error_blk.outputs = {"produced_value": {"type": "string", "description": "never produced"}}
        try:
            executor = PipelineExecutor()
            result = await executor.run(_pipeline([
                # error_block fails at runtime → NOT added to all_outputs
                {"id": "broken",     "block": "error_block", "inputs": {}},
                # downstream depends on broken.produced_value → template_error at runtime
                {"id": "downstream", "block": "profile_block",
                 "inputs": {"environment_id": "{{broken.produced_value}}"}},
            ]))
        finally:
            error_blk.outputs = original_outputs

        downstream_r = next(r for r in result["step_results"] if r["step_id"] == "downstream")
        assert downstream_r["status"] == "template_error"

    @pytest.mark.asyncio
    async def test_validation_failure_returns_errors_not_executing(self, synthetic_registry):
        """Validation errors prevent execution."""
        executor = PipelineExecutor()
        result = await executor.run(_pipeline([
            {"id": "s1", "block": "nonexistent_block_xyz", "inputs": {}},
        ]))
        assert result["validation_errors"] != []
        assert result["steps_run"] == 0

    @pytest.mark.asyncio
    async def test_result_shape(self, synthetic_registry):
        """All expected keys are present in the result."""
        executor = PipelineExecutor()
        result = await executor.run(_pipeline([
            {"id": "env", "block": "env_block", "inputs": {}},
        ]))
        required_keys = {
            "pipeline_name", "steps_run", "steps_succeeded", "steps_failed",
            "waves_run", "outputs", "step_results", "validation_errors", "summary",
        }
        assert required_keys.issubset(result.keys())

    @pytest.mark.asyncio
    async def test_outputs_accessible_by_step_id(self, synthetic_registry):
        executor = PipelineExecutor()
        result = await executor.run(_pipeline([
            {"id": "env",   "block": "env_block",   "inputs": {}},
            {"id": "score", "block": "score_block", "inputs": {}},
        ]))
        assert "env" in result["outputs"]
        assert "score" in result["outputs"]
        assert result["outputs"]["env"]["environment_id"] == "env-123"
        assert result["outputs"]["score"]["des_score"] == 72


# ────────────────────────────────────────────────────────────────────────────
# Templates integration
# ────────────────────────────────────────────────────────────────────────────

class TestPipelineTemplates:
    def test_all_four_templates_exist(self):
        from backend.agent.tools.pipeline_tools import _PIPELINE_TEMPLATES
        assert set(_PIPELINE_TEMPLATES.keys()) == {
            "apt_red_team", "detection_gap_close", "full_coverage_drill", "quick_assessment"
        }

    def test_all_template_blocks_registered(self):
        from backend.agent.tools.pipeline_tools import _PIPELINE_TEMPLATES
        for tid, t in _PIPELINE_TEMPLATES.items():
            for step in t["steps"]:
                bid = step["block"]
                assert get_block(bid) is not None, \
                    f"Template '{tid}' step '{step['id']}' references unknown block '{bid}'"

    def test_all_templates_pass_validation(self):
        from backend.agent.tools.pipeline_tools import _PIPELINE_TEMPLATES
        for tid, t in _PIPELINE_TEMPLATES.items():
            errors = validate_pipeline(t)
            assert errors == [], \
                f"Template '{tid}' failed validation: {errors}"
