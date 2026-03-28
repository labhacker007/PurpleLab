"""Shared fixtures for the Joti Sim test suite.

Handles both current (backend.generators) and future (backend.engine.generators)
import paths gracefully.
"""
from __future__ import annotations

import sys
import os
import pytest

# Ensure the project root is on sys.path so `backend` is importable
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.generators.base import BaseGenerator, GeneratorConfig
from backend.generators import GENERATOR_REGISTRY
from backend.engine import SimulationEngine, SessionConfig, ProductNode, TargetNode


# ---------------------------------------------------------------------------
# Generator fixtures
# ---------------------------------------------------------------------------

def _make_config(product_type: str, **overrides) -> GeneratorConfig:
    """Create a GeneratorConfig with sensible defaults for testing."""
    defaults = {
        "product_type": product_type,
        "target_url": "http://test-target.example.com/webhook",
        "webhook_token": "test-token-abc",
        "events_per_minute": 2.0,
        "severity_weights": {"critical": 0.25, "high": 0.25, "medium": 0.25, "low": 0.25},
        "enabled": True,
    }
    defaults.update(overrides)
    return GeneratorConfig(**defaults)


@pytest.fixture
def make_config():
    """Factory fixture for GeneratorConfig."""
    return _make_config


@pytest.fixture
def all_generator_classes():
    """Return the full GENERATOR_REGISTRY dict."""
    return GENERATOR_REGISTRY


@pytest.fixture(params=list(GENERATOR_REGISTRY.keys()))
def generator_instance(request):
    """Parametrized fixture that yields one instance per registered generator."""
    product_type = request.param
    gen_cls = GENERATOR_REGISTRY[product_type]
    config = _make_config(product_type)
    return gen_cls(config)


@pytest.fixture
def splunk_gen():
    return GENERATOR_REGISTRY["splunk"](_make_config("splunk"))


@pytest.fixture
def crowdstrike_gen():
    return GENERATOR_REGISTRY["crowdstrike"](_make_config("crowdstrike"))


@pytest.fixture
def sentinel_gen():
    return GENERATOR_REGISTRY["sentinel"](_make_config("sentinel"))


@pytest.fixture
def okta_gen():
    return GENERATOR_REGISTRY["okta"](_make_config("okta"))


@pytest.fixture
def proofpoint_gen():
    return GENERATOR_REGISTRY["proofpoint"](_make_config("proofpoint"))


@pytest.fixture
def qradar_gen():
    return GENERATOR_REGISTRY["qradar"](_make_config("qradar"))


@pytest.fixture
def elastic_gen():
    return GENERATOR_REGISTRY["elastic"](_make_config("elastic"))


@pytest.fixture
def guardduty_gen():
    return GENERATOR_REGISTRY["guardduty"](_make_config("guardduty"))


@pytest.fixture
def carbon_black_gen():
    return GENERATOR_REGISTRY["carbon_black"](_make_config("carbon_black"))


@pytest.fixture
def defender_gen():
    return GENERATOR_REGISTRY["defender_endpoint"](_make_config("defender_endpoint"))


@pytest.fixture
def entra_id_gen():
    return GENERATOR_REGISTRY["entra_id"](_make_config("entra_id"))


@pytest.fixture
def servicenow_gen():
    return GENERATOR_REGISTRY["servicenow"](_make_config("servicenow"))


# ---------------------------------------------------------------------------
# Engine fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine():
    """Fresh SimulationEngine instance (not the global singleton)."""
    return SimulationEngine()


@pytest.fixture
def sample_session_config():
    """A valid SessionConfig with one product and one target."""
    product = ProductNode(
        product_type="splunk",
        label="Test Splunk",
        config=_make_config("splunk"),
        connected_to=None,
    )
    target = TargetNode(
        label="Test Target",
        base_url="http://localhost:9999",
        webhook_path="/api/alerts/ingest/{token}",
    )
    product.connected_to = target.id
    return SessionConfig(
        name="Test Session",
        products=[product],
        targets=[target],
    )


# ---------------------------------------------------------------------------
# FastAPI test client fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Synchronous TestClient for the FastAPI app."""
    from fastapi.testclient import TestClient
    from backend.main import app
    return TestClient(app)


@pytest.fixture
def async_client():
    """Async client for the FastAPI app (for use with pytest-asyncio)."""
    import httpx
    from backend.main import app
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )
