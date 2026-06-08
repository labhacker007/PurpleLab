"""API integration tests for the pipeline REST endpoints.

Endpoints under test:
  GET  /api/v2/pipeline/blocks
  POST /api/v2/pipeline/compose/validate
  POST /api/v2/pipeline/compose/run      (mocked — blocks make real HTTP calls)

Uses FastAPI TestClient / ASGI transport so no live server required.
The run endpoint patches BLOCK_REGISTRY.fn to avoid real PurpleLab HTTP calls.
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from typing import Any

# FastAPI test client
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


# ────────────────────────────────────────────────────────────────────────────
# GET /api/v2/pipeline/blocks
# ────────────────────────────────────────────────────────────────────────────

class TestListBlocks:
    def test_status_200(self):
        r = client.get("/api/v2/pipeline/blocks")
        assert r.status_code == 200

    def test_total_blocks_equals_15(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        assert data["total_blocks"] == 15

    def test_blocks_by_category_present(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        assert "blocks_by_category" in data
        cats = data["blocks_by_category"]
        assert isinstance(cats, dict) and len(cats) > 0

    def test_expected_categories_present(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        cats = set(data["blocks_by_category"].keys())
        assert cats >= {
            "infrastructure", "threat_intel", "simulation",
            "scoring", "detection", "reporting", "utility"
        }

    def test_each_block_has_required_fields(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        for cat, blocks in data["blocks_by_category"].items():
            for blk in blocks:
                assert "id" in blk, f"block missing 'id' in category {cat}"
                assert "label" in blk, f"block {blk.get('id')} missing 'label'"
                assert "description" in blk, f"block {blk.get('id')} missing 'description'"
                assert "inputs" in blk, f"block {blk.get('id')} missing 'inputs'"
                assert "outputs" in blk, f"block {blk.get('id')} missing 'outputs'"

    def test_all_output_keys_have_type(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        for cat, blocks in data["blocks_by_category"].items():
            for blk in blocks:
                for out_key, out_spec in blk.get("outputs", {}).items():
                    assert "type" in out_spec, \
                        f"{blk['id']}.outputs.{out_key} missing 'type'"

    def test_four_templates_returned(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        assert "templates" in data
        assert len(data["templates"]) == 4

    def test_template_ids(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        ids = {t["id"] for t in data["templates"]}
        assert ids == {"apt_red_team", "detection_gap_close", "full_coverage_drill", "quick_assessment"}

    def test_template_has_step_count(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        for t in data["templates"]:
            assert "step_count" in t and t["step_count"] > 0

    def test_composition_syntax_in_response(self):
        data = client.get("/api/v2/pipeline/blocks").json()
        assert "composition_syntax" in data or "hint" in str(data)


# ────────────────────────────────────────────────────────────────────────────
# POST /api/v2/pipeline/compose/validate
# ────────────────────────────────────────────────────────────────────────────

VALID_SIMPLE = {
    "pipeline": {
        "name": "Test",
        "steps": [
            {
                "id": "env",
                "block": "create_environment",
                "inputs": {"name": "drill"}
            }
        ]
    }
}

VALID_CHAIN = {
    "pipeline": {
        "name": "Chained",
        "steps": [
            {
                "id": "env",
                "block": "create_environment",
                "inputs": {"name": "drill"}
            },
            {
                "id": "profile",
                "block": "apply_threat_profile",
                "inputs": {
                    "environment_id": "{{env.environment_id}}",
                    "threat_actor": "APT29"
                }
            }
        ]
    }
}


class TestValidateEndpoint:
    def test_valid_simple_pipeline(self):
        r = client.post("/api/v2/pipeline/compose/validate", json=VALID_SIMPLE)
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True
        assert data["errors"] == []

    def test_valid_chain_pipeline(self):
        r = client.post("/api/v2/pipeline/compose/validate", json=VALID_CHAIN)
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True

    def test_unknown_block_returns_invalid(self):
        payload = {
            "pipeline": {
                "name": "Bad",
                "steps": [
                    {"id": "s1", "block": "no_such_block", "inputs": {}}
                ]
            }
        }
        r = client.post("/api/v2/pipeline/compose/validate", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert any("no_such_block" in e for e in data["errors"])

    def test_bad_template_ref_returns_invalid(self):
        payload = {
            "pipeline": {
                "name": "Bad ref",
                "steps": [
                    {
                        "id": "env",
                        "block": "create_environment",
                        "inputs": {"name": "drill"}
                    },
                    {
                        "id": "profile",
                        "block": "apply_threat_profile",
                        "inputs": {
                            "environment_id": "{{env.NONEXISTENT_KEY}}",
                            "threat_actor": "APT29"
                        }
                    }
                ]
            }
        }
        r = client.post("/api/v2/pipeline/compose/validate", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert any("NONEXISTENT_KEY" in e for e in data["errors"])

    def test_missing_required_input_returns_invalid(self):
        payload = {
            "pipeline": {
                "name": "Missing required",
                "steps": [
                    {
                        "id": "env",
                        "block": "create_environment",
                        "inputs": {}  # name is required
                    }
                ]
            }
        }
        r = client.post("/api/v2/pipeline/compose/validate", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert any("name" in e for e in data["errors"])

    def test_empty_pipeline_returns_invalid(self):
        payload = {"pipeline": {"name": "Empty", "steps": []}}
        r = client.post("/api/v2/pipeline/compose/validate", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False

    def test_response_includes_execution_plan(self):
        r = client.post("/api/v2/pipeline/compose/validate", json=VALID_CHAIN)
        data = r.json()
        assert "execution_plan" in data
        plan = data["execution_plan"]
        assert isinstance(plan, list) and len(plan) > 0

    def test_response_includes_wave_count(self):
        r = client.post("/api/v2/pipeline/compose/validate", json=VALID_CHAIN)
        data = r.json()
        assert "wave_count" in data
        assert data["wave_count"] >= 1

    def test_response_includes_step_count(self):
        r = client.post("/api/v2/pipeline/compose/validate", json=VALID_CHAIN)
        data = r.json()
        assert "step_count" in data
        assert data["step_count"] == 2

    def test_execution_plan_wave_structure(self):
        r = client.post("/api/v2/pipeline/compose/validate", json=VALID_CHAIN)
        data = r.json()
        plan = data["execution_plan"]
        # Each wave is {"wave": int, "parallel_steps": [step_id, ...]}
        for wave_entry in plan:
            assert isinstance(wave_entry, dict)
            assert "wave" in wave_entry
            assert "parallel_steps" in wave_entry
            for step_id in wave_entry["parallel_steps"]:
                assert isinstance(step_id, str)

    def test_chain_produces_two_waves(self):
        """env (no deps) + profile (deps on env) must produce 2 waves."""
        r = client.post("/api/v2/pipeline/compose/validate", json=VALID_CHAIN)
        data = r.json()
        assert data["wave_count"] == 2
        assert data["execution_plan"][0]["parallel_steps"] == ["env"]
        assert data["execution_plan"][1]["parallel_steps"] == ["profile"]

    def test_independent_steps_same_wave(self):
        """score + gaps have no deps → single wave."""
        payload = {
            "pipeline": {
                "name": "Independent",
                "steps": [
                    {"id": "score", "block": "calculate_scores", "inputs": {}},
                    {"id": "gaps", "block": "get_gap_analysis", "inputs": {}},
                ]
            }
        }
        r = client.post("/api/v2/pipeline/compose/validate", json=payload)
        data = r.json()
        assert data["valid"] is True
        assert data["wave_count"] == 1
        assert len(data["execution_plan"][0]) == 2

    def test_malformed_body_returns_422(self):
        r = client.post("/api/v2/pipeline/compose/validate", json={"not_pipeline": {}})
        assert r.status_code == 422

    def test_template_ref_to_ghost_step(self):
        payload = {
            "pipeline": {
                "name": "Ghost ref",
                "steps": [
                    {
                        "id": "s1",
                        "block": "apply_threat_profile",
                        "inputs": {
                            "environment_id": "{{nonexistent.environment_id}}",
                            "threat_actor": "APT41"
                        }
                    }
                ]
            }
        }
        r = client.post("/api/v2/pipeline/compose/validate", json=payload)
        data = r.json()
        assert data["valid"] is False
        assert any("nonexistent" in e for e in data["errors"])


# ────────────────────────────────────────────────────────────────────────────
# POST /api/v2/pipeline/compose/run  (mocked block functions)
# ────────────────────────────────────────────────────────────────────────────

def _patch_block(block_id: str, return_value: dict):
    """Context manager that replaces a block's fn with a fast async mock."""
    from backend.agent.pipeline.blocks import BLOCK_REGISTRY
    blk = BLOCK_REGISTRY[block_id]
    original = blk.fn

    async def _mock(**_):
        return return_value

    blk.fn = _mock

    class _CM:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            blk.fn = original

    return _CM()


class TestRunEndpoint:
    def test_valid_single_step_run(self):
        with _patch_block("create_environment",
                          {"environment_id": "env-test", "environment_name": "drill"}):
            r = client.post("/api/v2/pipeline/compose/run", json={
                "pipeline": {
                    "name": "Single step run",
                    "steps": [
                        {"id": "env", "block": "create_environment",
                         "inputs": {"name": "drill"}}
                    ]
                }
            })
        assert r.status_code == 200
        data = r.json()
        assert data["steps_succeeded"] == 1
        assert data["steps_failed"] == 0
        assert data["outputs"]["env"]["environment_id"] == "env-test"

    def test_template_chain_resolves_correctly(self):
        with _patch_block("create_environment",
                          {"environment_id": "env-42", "environment_name": "test"}):
            with _patch_block("apply_threat_profile",
                              {"technique_ids": ["T1059"], "technique_count": 1,
                               "scenario": "APT29 initial access"}):
                r = client.post("/api/v2/pipeline/compose/run", json={
                    "pipeline": {
                        "name": "Chain run",
                        "steps": [
                            {"id": "env",     "block": "create_environment",
                             "inputs": {"name": "test"}},
                            {"id": "profile", "block": "apply_threat_profile",
                             "inputs": {
                                 "environment_id": "{{env.environment_id}}",
                                 "threat_actor": "APT29"
                             }},
                        ]
                    }
                })
        assert r.status_code == 200
        data = r.json()
        assert data["steps_succeeded"] == 2
        assert data["outputs"]["env"]["environment_id"] == "env-42"
        assert data["outputs"]["profile"]["technique_count"] == 1

    def test_result_keys_present(self):
        with _patch_block("calculate_scores",
                          {"des_score": 80, "ihds_score": 75, "coverage_percentage": 82}):
            r = client.post("/api/v2/pipeline/compose/run", json={
                "pipeline": {
                    "name": "Keys check",
                    "steps": [
                        {"id": "s", "block": "calculate_scores", "inputs": {}}
                    ]
                }
            })
        data = r.json()
        required = {
            "pipeline_name", "steps_run", "steps_succeeded", "steps_failed",
            "waves_run", "outputs", "step_results", "validation_errors", "summary",
        }
        assert required.issubset(data.keys())

    def test_validation_error_prevents_run(self):
        r = client.post("/api/v2/pipeline/compose/run", json={
            "pipeline": {
                "name": "Invalid block",
                "steps": [
                    {"id": "x", "block": "block_that_does_not_exist", "inputs": {}}
                ]
            }
        })
        assert r.status_code == 200
        data = r.json()
        assert data["steps_run"] == 0
        assert data["validation_errors"] != []

    def test_error_in_one_step_is_isolated(self):
        """One failing block doesn't prevent an independent block from running."""
        with _patch_block("calculate_scores",
                          {"des_score": 72, "ihds_score": 65, "coverage_percentage": 70}):
            # error_block doesn't exist — will be caught at validation
            # Use an existing block with a patched exception instead
            from backend.agent.pipeline.blocks import BLOCK_REGISTRY
            blk = BLOCK_REGISTRY["get_gap_analysis"]
            original_fn = blk.fn

            async def _explode(**_):
                raise RuntimeError("simulated block failure")

            blk.fn = _explode
            try:
                r = client.post("/api/v2/pipeline/compose/run", json={
                    "pipeline": {
                        "name": "Partial failure",
                        "steps": [
                            {"id": "gap",   "block": "get_gap_analysis", "inputs": {}},
                            {"id": "score", "block": "calculate_scores", "inputs": {}},
                        ]
                    }
                })
            finally:
                blk.fn = original_fn

        data = r.json()
        assert data["steps_failed"] == 1
        assert data["steps_succeeded"] == 1

    def test_malformed_body_returns_422(self):
        r = client.post("/api/v2/pipeline/compose/run", json={"not_a_pipeline": True})
        assert r.status_code == 422

    def test_empty_steps_returns_error_summary(self):
        r = client.post("/api/v2/pipeline/compose/run", json={
            "pipeline": {"name": "Empty", "steps": []}
        })
        assert r.status_code == 200
        data = r.json()
        assert data["steps_run"] == 0


# ────────────────────────────────────────────────────────────────────────────
# Template validation via API
# ────────────────────────────────────────────────────────────────────────────

class TestTemplateValidation:
    """Validate all 4 built-in templates via the HTTP endpoint."""

    @pytest.mark.parametrize("template_id", [
        "apt_red_team", "detection_gap_close", "full_coverage_drill", "quick_assessment"
    ])
    def test_template_passes_validation(self, template_id):
        from backend.agent.tools.pipeline_tools import _PIPELINE_TEMPLATES
        payload = {"pipeline": _PIPELINE_TEMPLATES[template_id]}
        r = client.post("/api/v2/pipeline/compose/validate", json=payload)
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True, \
            f"Template '{template_id}' failed validation: {data.get('errors')}"

    def test_apt_red_team_has_correct_waves(self):
        """apt_red_team: env/score parallel → profile → scenarios → batch/report parallel."""
        from backend.agent.tools.pipeline_tools import _PIPELINE_TEMPLATES
        payload = {"pipeline": _PIPELINE_TEMPLATES["apt_red_team"]}
        data = client.post("/api/v2/pipeline/compose/validate", json=payload).json()
        assert data["valid"] is True
        assert data["wave_count"] >= 2  # at least env wave and profile wave
        assert data["step_count"] == 5

    def test_quick_assessment_all_independent(self):
        """quick_assessment: score, gaps, report all independent → 1 or 2 waves max."""
        from backend.agent.tools.pipeline_tools import _PIPELINE_TEMPLATES
        payload = {"pipeline": _PIPELINE_TEMPLATES["quick_assessment"]}
        data = client.post("/api/v2/pipeline/compose/validate", json=payload).json()
        assert data["valid"] is True
        assert data["step_count"] == 3
