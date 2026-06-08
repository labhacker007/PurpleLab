"""Registry integrity tests — every block must have the right shape.

No HTTP calls; no DB; no mocking needed.  These are pure structural checks
that catch regressions like missing fn=, misnamed output keys, or a block
that forgot to declare outputs.
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest
import inspect
from backend.agent.pipeline.blocks import BLOCK_REGISTRY, BlockDef, get_block

# ── Expected catalogue ────────────────────────────────────────────────────────

EXPECTED_BLOCK_IDS = {
    # infrastructure
    "create_environment",
    "add_product",
    # threat_intel
    "apply_threat_profile",
    # simulation
    "list_scenarios",
    "run_scenario",
    "run_scenario_batch",
    # scoring
    "calculate_scores",
    "get_gap_analysis",
    # detection
    "import_sigma_rules",
    "create_use_case",
    "deploy_to_siem",
    "run_all_use_cases",
    "run_use_case",
    # reporting
    "generate_report",
    # utility
    "noop",
}

EXPECTED_CATEGORIES = {
    "infrastructure", "threat_intel", "simulation",
    "scoring", "detection", "reporting", "utility",
}


# ── Basic registry completeness ───────────────────────────────────────────────

class TestRegistryCompleteness:
    def test_all_expected_blocks_registered(self):
        registered = set(BLOCK_REGISTRY.keys())
        missing = EXPECTED_BLOCK_IDS - registered
        assert not missing, f"Missing blocks: {missing}"

    def test_no_extra_unknown_blocks(self):
        registered = set(BLOCK_REGISTRY.keys())
        unexpected = registered - EXPECTED_BLOCK_IDS
        assert not unexpected, f"Unexpected blocks found: {unexpected}"

    def test_total_count(self):
        assert len(BLOCK_REGISTRY) == len(EXPECTED_BLOCK_IDS)

    def test_get_block_returns_correct_def(self):
        blk = get_block("create_environment")
        assert blk is not None
        assert blk.block_id == "create_environment"

    def test_get_block_returns_none_for_unknown(self):
        assert get_block("nonexistent_block_xyz") is None


# ── Per-block structural invariants ──────────────────────────────────────────

class TestBlockStructure:
    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_block_exists(self, block_id):
        assert block_id in BLOCK_REGISTRY

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_block_has_non_empty_label(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        assert blk.label and len(blk.label) > 2, f"{block_id}: empty label"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_block_has_non_empty_description(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        assert blk.description and len(blk.description) > 10, \
            f"{block_id}: description too short or empty"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_block_has_known_category(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        assert blk.category in EXPECTED_CATEGORIES, \
            f"{block_id}: category '{blk.category}' not in known categories"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_block_has_callable_fn(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        assert callable(blk.fn), f"{block_id}: fn is not callable"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_block_fn_is_async(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        assert inspect.iscoroutinefunction(blk.fn), \
            f"{block_id}: fn must be async (coroutinefunction)"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_block_outputs_non_empty(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        assert blk.outputs and len(blk.outputs) >= 1, \
            f"{block_id}: block has no declared outputs"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_every_output_has_type(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        for out_key, out_spec in blk.outputs.items():
            assert "type" in out_spec, \
                f"{block_id}.outputs.{out_key}: missing 'type' field"
            assert out_spec["type"] in {
                "string", "integer", "number", "boolean", "array", "object"
            }, f"{block_id}.outputs.{out_key}: unknown type '{out_spec['type']}'"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_every_input_has_type(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        for inp_key, inp_spec in blk.inputs.items():
            assert "type" in inp_spec, \
                f"{block_id}.inputs.{inp_key}: missing 'type' field"
            assert inp_spec["type"] in {
                "string", "integer", "number", "boolean", "array", "object"
            }, f"{block_id}.inputs.{inp_key}: unknown type '{inp_spec['type']}'"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_every_input_has_required_flag(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        for inp_key, inp_spec in blk.inputs.items():
            assert "required" in inp_spec, \
                f"{block_id}.inputs.{inp_key}: missing 'required' flag"
            assert isinstance(inp_spec["required"], bool), \
                f"{block_id}.inputs.{inp_key}: 'required' must be a bool"


# ── schema() method ───────────────────────────────────────────────────────────

class TestBlockSchema:
    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_schema_returns_correct_keys(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        s = blk.schema()
        assert set(s.keys()) >= {
            "id", "category", "label", "description", "inputs", "outputs", "tags"
        }, f"{block_id}: schema() missing keys, got {set(s.keys())}"

    @pytest.mark.parametrize("block_id", sorted(EXPECTED_BLOCK_IDS))
    def test_schema_id_matches_registry_key(self, block_id):
        blk = BLOCK_REGISTRY[block_id]
        assert blk.schema()["id"] == block_id

    def test_schema_does_not_expose_fn(self):
        """schema() should never leak the implementation function."""
        for block_id, blk in BLOCK_REGISTRY.items():
            s = blk.schema()
            assert "fn" not in s, f"{block_id}: schema() should not include fn"

    def test_tags_is_list(self):
        for block_id, blk in BLOCK_REGISTRY.items():
            s = blk.schema()
            assert isinstance(s["tags"], list), \
                f"{block_id}: tags must be a list, got {type(s['tags'])}"


# ── Specific block output key expectations ────────────────────────────────────

class TestKeyBlockOutputs:
    """Spot-check the most commonly referenced output keys used in templates."""

    def test_create_environment_outputs(self):
        blk = get_block("create_environment")
        assert "environment_id" in blk.outputs
        assert "environment_name" in blk.outputs

    def test_apply_threat_profile_outputs(self):
        blk = get_block("apply_threat_profile")
        assert "technique_ids" in blk.outputs
        assert "technique_count" in blk.outputs

    def test_list_scenarios_outputs(self):
        blk = get_block("list_scenarios")
        assert "scenario_ids" in blk.outputs
        assert "total" in blk.outputs  # total count, not scenario_count

    def test_calculate_scores_outputs(self):
        blk = get_block("calculate_scores")
        assert "des_score" in blk.outputs
        assert "ihds_score" in blk.outputs

    def test_get_gap_analysis_outputs(self):
        blk = get_block("get_gap_analysis")
        assert "top_gap_techniques" in blk.outputs
        assert "gap_count" in blk.outputs

    def test_generate_report_outputs(self):
        blk = get_block("generate_report")
        assert "url" in blk.outputs  # not report_url

    def test_import_sigma_rules_outputs(self):
        blk = get_block("import_sigma_rules")
        assert "rule_ids" in blk.outputs
        assert "rule_count" in blk.outputs  # not rules_imported

    def test_create_use_case_outputs(self):
        blk = get_block("create_use_case")
        assert "use_case_id" in blk.outputs

    def test_run_scenario_batch_outputs(self):
        blk = get_block("run_scenario_batch")
        assert "sessions" in blk.outputs  # not results
        assert "total_run" in blk.outputs


# ── Required inputs spot-check ────────────────────────────────────────────────

class TestRequiredInputs:
    def test_create_environment_requires_name(self):
        blk = get_block("create_environment")
        assert blk.inputs["name"]["required"] is True

    def test_apply_threat_profile_requires_env_and_actor(self):
        blk = get_block("apply_threat_profile")
        assert blk.inputs["environment_id"]["required"] is True
        assert blk.inputs["threat_actor"]["required"] is True

    def test_run_scenario_requires_scenario_id(self):
        blk = get_block("run_scenario")
        assert blk.inputs["scenario_id"]["required"] is True

    def test_run_use_case_requires_use_case_id(self):
        blk = get_block("run_use_case")
        assert blk.inputs["use_case_id"]["required"] is True

    def test_noop_has_no_required_inputs(self):
        blk = get_block("noop")
        required = [k for k, v in blk.inputs.items() if v.get("required")]
        assert not required, f"noop should not require any inputs, got: {required}"

    def test_calculate_scores_has_no_required_inputs(self):
        blk = get_block("calculate_scores")
        required = [k for k, v in blk.inputs.items() if v.get("required")]
        assert not required, f"calculate_scores should not require any inputs, got: {required}"


# ── Category groupings ────────────────────────────────────────────────────────

class TestCategoryGroupings:
    def test_infrastructure_blocks(self):
        infra = {k for k, v in BLOCK_REGISTRY.items() if v.category == "infrastructure"}
        assert infra == {"create_environment", "add_product"}

    def test_simulation_blocks(self):
        sim = {k for k, v in BLOCK_REGISTRY.items() if v.category == "simulation"}
        assert sim == {"list_scenarios", "run_scenario", "run_scenario_batch"}

    def test_detection_blocks(self):
        det = {k for k, v in BLOCK_REGISTRY.items() if v.category == "detection"}
        assert det == {"import_sigma_rules", "create_use_case", "deploy_to_siem",
                       "run_all_use_cases", "run_use_case"}

    def test_scoring_blocks(self):
        scoring = {k for k, v in BLOCK_REGISTRY.items() if v.category == "scoring"}
        assert scoring == {"calculate_scores", "get_gap_analysis"}
