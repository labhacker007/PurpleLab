"""Unit tests for the pipeline agent tools.

Tests:
  - _list_blocks()           : returns correct catalogue shape
  - _get_pipeline_templates(): returns 4 templates with required fields
  - register_pipeline_tools(): registers list_blocks, run_pipeline, get_pipeline_templates
  - run_pipeline tool schema : well-formed JSON Schema
  - Tool functions are callable and return expected shapes
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest
import inspect
from backend.agent.tools.pipeline_tools import (
    _list_blocks,
    _get_pipeline_templates,
    _run_pipeline,
    register_pipeline_tools,
    _PIPELINE_TEMPLATES,
)


# ────────────────────────────────────────────────────────────────────────────
# _list_blocks
# ────────────────────────────────────────────────────────────────────────────

class TestListBlocks:
    def test_returns_dict(self):
        result = _list_blocks()
        assert isinstance(result, dict)

    def test_total_blocks_15(self):
        result = _list_blocks()
        assert result["total_blocks"] == 15

    def test_categories_key_present(self):
        result = _list_blocks()
        assert "categories" in result

    def test_hint_key_present(self):
        result = _list_blocks()
        assert "hint" in result

    def test_categories_is_dict(self):
        result = _list_blocks()
        assert isinstance(result["categories"], dict)

    def test_all_expected_categories_present(self):
        cats = set(_list_blocks()["categories"].keys())
        assert cats >= {
            "infrastructure", "threat_intel", "simulation",
            "scoring", "detection", "reporting", "utility"
        }

    def test_each_block_entry_has_id_label_description(self):
        for cat, blocks in _list_blocks()["categories"].items():
            for blk in blocks:
                assert "id" in blk, f"category {cat}: block missing id"
                assert "label" in blk, f"{blk.get('id')}: missing label"
                assert "description" in blk, f"{blk.get('id')}: missing description"

    def test_outputs_as_dict_with_types(self):
        for cat, blocks in _list_blocks()["categories"].items():
            for blk in blocks:
                for out_key, out_val in blk.get("outputs", {}).items():
                    assert isinstance(out_val, (str, dict)), \
                        f"{blk['id']}.outputs.{out_key}: expected str or dict, got {type(out_val)}"

    def test_inputs_have_type_and_required(self):
        for cat, blocks in _list_blocks()["categories"].items():
            for blk in blocks:
                for inp_key, inp_spec in blk.get("inputs", {}).items():
                    assert "type" in inp_spec, \
                        f"{blk['id']}.inputs.{inp_key}: missing 'type'"
                    assert "required" in inp_spec, \
                        f"{blk['id']}.inputs.{inp_key}: missing 'required'"

    def test_hint_contains_template_syntax(self):
        hint = _list_blocks()["hint"]
        assert "{{" in hint or "step_id" in hint, \
            "Hint should mention {{step_id.key}} template syntax"

    def test_create_environment_in_infrastructure(self):
        infra = _list_blocks()["categories"].get("infrastructure", [])
        ids = {b["id"] for b in infra}
        assert "create_environment" in ids


# ────────────────────────────────────────────────────────────────────────────
# _get_pipeline_templates
# ────────────────────────────────────────────────────────────────────────────

class TestGetPipelineTemplates:
    def test_returns_dict(self):
        assert isinstance(_get_pipeline_templates(), dict)

    def test_templates_key_is_list(self):
        result = _get_pipeline_templates()
        assert isinstance(result["templates"], list)

    def test_four_templates(self):
        result = _get_pipeline_templates()
        assert len(result["templates"]) == 4

    def test_template_ids(self):
        result = _get_pipeline_templates()
        ids = {t["id"] for t in result["templates"]}
        assert ids == {"apt_red_team", "detection_gap_close", "full_coverage_drill", "quick_assessment"}

    def test_each_template_has_required_fields(self):
        result = _get_pipeline_templates()
        for t in result["templates"]:
            assert "id" in t
            assert "name" in t
            assert "description" in t
            assert "step_count" in t
            assert "step_blocks" in t

    def test_template_step_counts(self):
        result = _get_pipeline_templates()
        counts = {t["id"]: t["step_count"] for t in result["templates"]}
        assert counts["apt_red_team"] == 5
        assert counts["detection_gap_close"] == 5
        assert counts["full_coverage_drill"] == 3
        assert counts["quick_assessment"] == 3

    def test_template_definitions_included(self):
        result = _get_pipeline_templates()
        assert "template_definitions" in result
        defs = result["template_definitions"]
        assert set(defs.keys()) == {"apt_red_team", "detection_gap_close", "full_coverage_drill", "quick_assessment"}

    def test_template_definitions_have_steps(self):
        result = _get_pipeline_templates()
        for tid, tdef in result["template_definitions"].items():
            assert "steps" in tdef, f"Template '{tid}' definition missing 'steps'"
            assert len(tdef["steps"]) > 0

    def test_step_blocks_non_empty(self):
        result = _get_pipeline_templates()
        for t in result["templates"]:
            assert len(t["step_blocks"]) > 0

    def test_usage_hint_present(self):
        result = _get_pipeline_templates()
        assert "usage" in result
        assert len(result["usage"]) > 10

    def test_apt_red_team_step_blocks(self):
        result = _get_pipeline_templates()
        apt = next(t for t in result["templates"] if t["id"] == "apt_red_team")
        blocks = apt["step_blocks"]
        assert "create_environment" in blocks
        assert "apply_threat_profile" in blocks
        assert "calculate_scores" in blocks


# ────────────────────────────────────────────────────────────────────────────
# register_pipeline_tools
# ────────────────────────────────────────────────────────────────────────────

class TestRegisterPipelineTools:
    def test_registers_three_tools(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        assert len(tool_map) == 3
        assert len(schema_list) == 3

    def test_tool_names(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        assert set(tool_map.keys()) == {"list_blocks", "run_pipeline", "get_pipeline_templates"}

    def test_schema_names_match_tool_map(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        schema_names = {s["name"] for s in schema_list}
        assert schema_names == set(tool_map.keys())

    def test_all_schemas_have_description(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        for s in schema_list:
            assert "description" in s and len(s["description"]) > 10, \
                f"{s['name']}: missing or short description"

    def test_all_schemas_have_input_schema(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        for s in schema_list:
            assert "input_schema" in s, f"{s['name']}: missing input_schema"
            assert s["input_schema"]["type"] == "object"

    def test_run_pipeline_input_schema_requires_pipeline(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        rp = next(s for s in schema_list if s["name"] == "run_pipeline")
        assert "pipeline" in rp["input_schema"]["properties"]
        assert "pipeline" in rp["input_schema"]["required"]

    def test_list_blocks_no_required_inputs(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        lb = next(s for s in schema_list if s["name"] == "list_blocks")
        assert lb["input_schema"]["required"] == []

    def test_get_templates_no_required_inputs(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        gt = next(s for s in schema_list if s["name"] == "get_pipeline_templates")
        assert gt["input_schema"]["required"] == []

    def test_list_blocks_tool_callable(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        result = tool_map["list_blocks"]()
        assert isinstance(result, dict)
        assert result["total_blocks"] == 15

    def test_get_templates_tool_callable(self):
        tool_map = {}
        schema_list = []
        register_pipeline_tools(tool_map, schema_list)
        result = tool_map["get_pipeline_templates"]()
        assert isinstance(result, dict)
        assert len(result["templates"]) == 4


# ────────────────────────────────────────────────────────────────────────────
# run_pipeline tool (mocked)
# ────────────────────────────────────────────────────────────────────────────

class TestRunPipelineTool:
    @pytest.mark.asyncio
    async def test_run_pipeline_returns_result(self):
        from backend.agent.pipeline.blocks import BLOCK_REGISTRY
        blk = BLOCK_REGISTRY["calculate_scores"]
        original = blk.fn

        async def _mock(**_):
            return {"des_score": 88, "ihds_score": 82, "coverage_percentage": 90,
                    "technique_coverage_count": 10, "total_techniques": 11}

        blk.fn = _mock
        try:
            result = await _run_pipeline({
                "name": "Tool test",
                "steps": [
                    {"id": "s", "block": "calculate_scores", "inputs": {}}
                ]
            })
        finally:
            blk.fn = original

        assert result["steps_succeeded"] == 1
        assert result["outputs"]["s"]["des_score"] == 88

    @pytest.mark.asyncio
    async def test_run_pipeline_handles_exception_gracefully(self):
        from backend.agent.pipeline.blocks import BLOCK_REGISTRY
        blk = BLOCK_REGISTRY["get_gap_analysis"]
        original = blk.fn

        async def _explode(**_):
            raise RuntimeError("network timeout")

        blk.fn = _explode
        try:
            result = await _run_pipeline({
                "name": "Error test",
                "steps": [
                    {"id": "g", "block": "get_gap_analysis", "inputs": {}}
                ]
            })
        finally:
            blk.fn = original

        # Should NOT raise; should return a result dict with failure info
        assert isinstance(result, dict)
        assert "summary" in result

    @pytest.mark.asyncio
    async def test_run_pipeline_validation_error_case(self):
        result = await _run_pipeline({
            "name": "Unknown block",
            "steps": [
                {"id": "x", "block": "block_that_doesnt_exist", "inputs": {}}
            ]
        })
        assert isinstance(result, dict)
        # Validation should catch it before execution
        assert result.get("steps_run", 0) == 0
