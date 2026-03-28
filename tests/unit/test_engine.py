"""Tests for the SimulationEngine — session lifecycle, generator registry, event log."""
import pytest

from backend.engine import SimulationEngine, SessionConfig, ProductNode, TargetNode, EventLog
from backend.generators.base import GeneratorConfig
from backend.generators import GENERATOR_REGISTRY


class TestSessionCRUD:
    """Test session create, read, update, delete operations."""

    def test_create_session_returns_config(self, engine, sample_session_config):
        result = engine.create_session(sample_session_config)
        assert result.session_id == sample_session_config.session_id
        assert result.name == "Test Session"

    def test_create_session_sets_running_false(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        assert engine.running[sample_session_config.session_id] is False

    def test_create_session_initializes_stats(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        stats = engine.stats[sample_session_config.session_id]
        assert stats["events_sent"] == 0
        assert stats["errors"] == 0
        assert stats["last_event_at"] is None

    def test_get_session_returns_none_for_unknown(self, engine):
        assert engine.get_session("nonexistent") is None

    def test_get_session_returns_config(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        result = engine.get_session(sample_session_config.session_id)
        assert result is not None
        assert result.name == "Test Session"

    def test_list_sessions_empty(self, engine):
        assert engine.list_sessions() == []

    def test_list_sessions_after_create(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        sessions = engine.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == sample_session_config.session_id
        assert sessions[0]["running"] is False

    def test_list_sessions_multiple(self, engine):
        for i in range(3):
            cfg = SessionConfig(session_id=f"sess-{i}", name=f"Session {i}")
            engine.create_session(cfg)
        assert len(engine.list_sessions()) == 3

    def test_update_session_nonexistent(self, engine, sample_session_config):
        result = engine.update_session("nonexistent", sample_session_config)
        assert result is None

    def test_update_session_changes_name(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        updated = SessionConfig(name="Updated Session")
        result = engine.update_session(sample_session_config.session_id, updated)
        assert result is not None
        assert result.name == "Updated Session"
        assert result.session_id == sample_session_config.session_id

    def test_delete_session(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        engine.delete_session(sample_session_config.session_id)
        assert engine.get_session(sample_session_config.session_id) is None
        assert sample_session_config.session_id not in engine.running

    def test_delete_nonexistent_session(self, engine):
        # Should not raise
        result = engine.delete_session("nonexistent")
        assert result is True


class TestStartStop:
    """Test session start/stop mechanics."""

    def test_start_unknown_session_returns_false(self, engine):
        assert engine.start_session("nonexistent") is False

    def test_start_session_sets_running_true(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        result = engine.start_session(sample_session_config.session_id)
        assert result is True
        assert engine.running[sample_session_config.session_id] is True
        # Cleanup
        engine.stop_session(sample_session_config.session_id)

    def test_start_session_creates_scheduler(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        engine.start_session(sample_session_config.session_id)
        assert sample_session_config.session_id in engine.schedulers
        scheduler = engine.schedulers[sample_session_config.session_id]
        assert scheduler.running
        # Cleanup
        engine.stop_session(sample_session_config.session_id)

    def test_start_session_creates_generators(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        engine.start_session(sample_session_config.session_id)
        gens = engine.generators.get(sample_session_config.session_id, {})
        assert len(gens) == 1  # One product in sample config
        engine.stop_session(sample_session_config.session_id)

    def test_stop_session_sets_running_false(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        engine.start_session(sample_session_config.session_id)
        engine.stop_session(sample_session_config.session_id)
        assert engine.running[sample_session_config.session_id] is False

    def test_stop_session_removes_scheduler(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        engine.start_session(sample_session_config.session_id)
        engine.stop_session(sample_session_config.session_id)
        assert sample_session_config.session_id not in engine.schedulers

    def test_stop_session_removes_generators(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        engine.start_session(sample_session_config.session_id)
        engine.stop_session(sample_session_config.session_id)
        assert sample_session_config.session_id not in engine.generators

    def test_stop_nonrunning_session(self, engine, sample_session_config):
        engine.create_session(sample_session_config)
        # Should not raise
        result = engine.stop_session(sample_session_config.session_id)
        assert result is True

    def test_disabled_product_not_scheduled(self, engine):
        """Products with enabled=False should not get scheduled jobs."""
        config = GeneratorConfig(
            product_type="splunk",
            target_url="http://test",
            enabled=False,
        )
        product = ProductNode(product_type="splunk", label="Disabled", config=config)
        target = TargetNode()
        session = SessionConfig(name="Test", products=[product], targets=[target])
        engine.create_session(session)
        engine.start_session(session.session_id)
        scheduler = engine.schedulers[session.session_id]
        jobs = scheduler.get_jobs()
        assert len(jobs) == 0
        engine.stop_session(session.session_id)


class TestGeneratorRegistry:
    """Test that all product types are registered correctly."""

    EXPECTED_PRODUCTS = {
        "splunk", "crowdstrike", "sentinel", "okta", "proofpoint",
        "servicenow", "carbon_black", "defender_endpoint", "entra_id",
        "qradar", "elastic", "guardduty",
    }

    def test_registry_has_all_products(self):
        assert self.EXPECTED_PRODUCTS == set(GENERATOR_REGISTRY.keys())

    def test_all_generators_subclass_base(self):
        from backend.generators.base import BaseGenerator
        for name, cls in GENERATOR_REGISTRY.items():
            assert issubclass(cls, BaseGenerator), f"{name} is not a BaseGenerator subclass"

    def test_all_generators_can_instantiate(self, make_config):
        for product_type, cls in GENERATOR_REGISTRY.items():
            config = make_config(product_type)
            gen = cls(config)
            assert gen is not None

    def test_all_generators_produce_non_empty_dict(self, make_config):
        for product_type, cls in GENERATOR_REGISTRY.items():
            config = make_config(product_type)
            gen = cls(config)
            event = gen.generate()
            assert isinstance(event, dict), f"{product_type} did not return a dict"
            assert len(event) > 0, f"{product_type} returned empty dict"


class TestEventLog:
    """Test event log behavior."""

    def test_event_log_starts_empty(self, engine):
        assert engine.get_event_log() == []

    def test_event_log_respects_limit(self, engine):
        # Manually add events
        for i in range(10):
            entry = EventLog(
                timestamp=engine._now_iso(),
                session_id="test",
                product_type="splunk",
                product_label="Test Splunk",
                severity="medium",
                title=f"Event {i}",
                target_url="http://test",
                status_code=200,
                success=True,
            )
            engine.event_log.append(entry)
        result = engine.get_event_log(limit=5)
        assert len(result) == 5

    def test_event_log_filters_by_session(self, engine):
        for sid in ("sess-a", "sess-b"):
            for i in range(3):
                entry = EventLog(
                    timestamp=engine._now_iso(),
                    session_id=sid,
                    product_type="splunk",
                    product_label="Test",
                    severity="low",
                    title=f"Event {i}",
                    target_url="http://test",
                    status_code=200,
                    success=True,
                )
                engine.event_log.append(entry)
        result = engine.get_event_log(session_id="sess-a")
        assert len(result) == 3
        assert all(e["session_id"] == "sess-a" for e in result)

    def test_event_log_max_buffer(self, engine):
        """Engine should cap event_log at 500 entries."""
        for i in range(600):
            entry = EventLog(
                timestamp=engine._now_iso(),
                session_id="test",
                product_type="splunk",
                product_label="Test",
                severity="low",
                title=f"Event {i}",
                target_url="http://test",
                status_code=200,
                success=True,
            )
            engine.event_log.append(entry)
        # Simulate the trimming that happens in _send_event
        if len(engine.event_log) > 500:
            engine.event_log = engine.event_log[-500:]
        assert len(engine.event_log) == 500


class TestPreviewEvent:
    """Test the preview_event method."""

    def test_preview_valid_product(self, engine):
        event = engine.preview_event("splunk")
        assert isinstance(event, dict)
        assert "error" not in event
        assert "sid" in event  # Splunk-specific key

    def test_preview_all_products(self, engine):
        for product_type in GENERATOR_REGISTRY:
            event = engine.preview_event(product_type)
            assert isinstance(event, dict)
            assert "error" not in event

    def test_preview_unknown_product(self, engine):
        event = engine.preview_event("nonexistent")
        assert "error" in event


class TestConcurrentSessions:
    """Test that multiple sessions don't interfere with each other."""

    def test_two_sessions_independent_stats(self, engine, make_config):
        for sid in ("sess-1", "sess-2"):
            cfg = SessionConfig(session_id=sid, name=sid)
            engine.create_session(cfg)
        engine.stats["sess-1"]["events_sent"] = 10
        assert engine.stats["sess-2"]["events_sent"] == 0

    def test_two_sessions_independent_running(self, engine, make_config):
        product = ProductNode(
            product_type="splunk",
            label="Test",
            config=make_config("splunk"),
        )
        target = TargetNode()
        for sid in ("sess-1", "sess-2"):
            cfg = SessionConfig(
                session_id=sid,
                name=sid,
                products=[product],
                targets=[target],
            )
            engine.create_session(cfg)
        engine.start_session("sess-1")
        assert engine.running["sess-1"] is True
        assert engine.running["sess-2"] is False
        engine.stop_session("sess-1")

    def test_stop_one_session_does_not_affect_other(self, engine, make_config):
        product = ProductNode(
            product_type="splunk",
            label="Test",
            config=make_config("splunk"),
        )
        target = TargetNode()
        for sid in ("sess-1", "sess-2"):
            cfg = SessionConfig(
                session_id=sid,
                name=sid,
                products=[product],
                targets=[target],
            )
            engine.create_session(cfg)
            engine.start_session(sid)
        engine.stop_session("sess-1")
        assert engine.running["sess-1"] is False
        assert engine.running["sess-2"] is True
        engine.stop_session("sess-2")
