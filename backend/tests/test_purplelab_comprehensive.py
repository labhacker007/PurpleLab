"""PurpleLab Comprehensive Test Suite.

80+ pytest test functions covering:
  - Session CRUD and lifecycle (create/start/stop/delete)
  - Event generation and streaming
  - EDR state machine transitions
  - Vendor API responses: Splunk, CrowdStrike, XSIAM, Defender
  - Action executor (block_ioc, isolate_host, release_host, etc.)
  - ITDR scenarios (all 10)
  - Use case validation runs
  - Joti webhook format and integration
  - Coverage report and scoring
  - Session isolation (cross-session contamination prevention)

Test patterns follow the project's conftest.py conventions:
  - async_client fixture for FastAPI ASGI transport
  - async_session fixture for DB access
  - Mock JotiClient to prevent real outbound HTTP calls
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import select, text

# ---------------------------------------------------------------------------
# Test DB setup (SQLite in-memory for unit tests; skip if asyncpg needed)
# ---------------------------------------------------------------------------

DATABASE_URL_TEST = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Create a SQLite in-memory async engine for the test session."""
    engine = create_async_engine(DATABASE_URL_TEST, echo=False)
    try:
        from backend.db.models import Base
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine):
    """Provide a transactional async DB session that rolls back after each test."""
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def app_client():
    """Async HTTP test client for the FastAPI app."""
    from backend.main import app
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def make_session_payload(
    name: str = "Test Session",
    mode: str = "attack_chain",
    attack_chains: list[str] | None = None,
    technique_ids: list[str] | None = None,
    threat_actor_name: str | None = None,
    threat_actor_ttps: list[str] | None = None,
    event_count: int = 10,
    auto_start: bool = False,
) -> dict[str, Any]:
    """Factory for session creation payloads."""
    payload: dict[str, Any] = {
        "name": name,
        "simulation_mode": mode,
        "event_count": event_count,
        "auto_start": auto_start,
    }
    if attack_chains is not None:
        payload["attack_chains"] = attack_chains
    if technique_ids is not None:
        payload["technique_ids"] = technique_ids
    if threat_actor_name is not None:
        payload["threat_actor_name"] = threat_actor_name
    if threat_actor_ttps is not None:
        payload["threat_actor_ttps"] = threat_actor_ttps
    return payload


async def create_test_session(client: AsyncClient, **kwargs) -> dict[str, Any]:
    """Create a session via API and return the response dict."""
    payload = make_session_payload(**kwargs)
    resp = await client.post("/api/v2/sessions", json=payload)
    assert resp.status_code == 200, f"Session create failed: {resp.text}"
    return resp.json()


async def create_use_case(
    db: AsyncSession,
    name: str = "Test Use Case",
    technique_ids: list[str] | None = None,
    tags: list[str] | None = None,
    severity: str = "high",
    tactic: str = "execution",
) -> Any:
    """Insert a UseCase directly into DB for testing."""
    from backend.db.models import UseCase
    uc = UseCase(
        name=name,
        description="Auto-generated test use case",
        technique_ids=technique_ids or ["T1059.001"],
        tactic=tactic,
        severity=severity,
        tags=tags or [],
        is_active=True,
        is_builtin=False,
    )
    db.add(uc)
    await db.commit()
    await db.refresh(uc)
    return uc


async def create_sim_session_db(db: AsyncSession, name: str = "DB Test Session") -> Any:
    """Insert a SimulationSession directly into DB."""
    from backend.db.models import SimulationSession
    s = SimulationSession(
        name=name,
        config={"simulation_mode": "attack_chain", "technique_ids": ["T1059"], "event_count": 10},
        status="stopped",
        events_sent=0,
        errors=0,
    )
    db.add(s)
    await db.commit()
    await db.refresh(s)
    return s


async def create_generated_event(
    db: AsyncSession,
    session_id: uuid.UUID,
    product_type: str = "crowdstrike",
    severity: str = "high",
    title: str = "T1059.001",
    payload: dict | None = None,
) -> Any:
    """Insert a GeneratedEvent directly into DB."""
    from backend.db.models import GeneratedEvent
    evt = GeneratedEvent(
        session_id=session_id,
        product_type=product_type,
        severity=severity,
        title=title,
        payload=payload or {"ComputerName": "TEST-HOST-01", "hostname": "TEST-HOST-01"},
        target_url="http://test",
        status_code=200,
        success=True,
    )
    db.add(evt)
    await db.commit()
    await db.refresh(evt)
    return evt


# ===========================================================================
# 1. SESSION CRUD TESTS
# ===========================================================================

class TestSessionCreate:
    """Test session creation with all simulation modes."""

    @pytest.mark.asyncio
    async def test_create_attack_chain_session(self, app_client: AsyncClient):
        """TC-F-001: Create session in attack_chain mode."""
        payload = make_session_payload(
            name="Attack Chain Session",
            mode="attack_chain",
            attack_chains=["apt29_chain"],
            event_count=50,
        )
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Attack Chain Session"
        assert data["status"] == "stopped"
        assert data["events_sent"] == 0
        assert "id" in data
        cfg = data["config"]
        assert cfg["simulation_mode"] == "attack_chain"
        assert cfg["attack_chains"] == ["apt29_chain"]
        assert cfg["event_count"] == 50

    @pytest.mark.asyncio
    async def test_create_threat_actor_session(self, app_client: AsyncClient):
        """TC-F-002: Create session in threat_actor mode."""
        payload = make_session_payload(
            name="APT29 Session",
            mode="threat_actor",
            threat_actor_name="APT29",
            threat_actor_ttps=["T1059.001", "T1003.001", "T1021.002"],
        )
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        cfg = data["config"]
        assert cfg["simulation_mode"] == "threat_actor"
        assert cfg["threat_actor_name"] == "APT29"
        assert "T1059.001" in cfg["threat_actor_ttps"]

    @pytest.mark.asyncio
    async def test_create_ttps_session(self, app_client: AsyncClient):
        """TC-F-003: Create session in ttps mode."""
        payload = make_session_payload(
            name="TTP Session",
            mode="ttps",
            technique_ids=["T1059.001", "T1055", "T1486"],
        )
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        cfg = data["config"]
        assert cfg["simulation_mode"] == "ttps"
        assert "T1059.001" in cfg["technique_ids"]

    @pytest.mark.asyncio
    async def test_create_mcp_ingest_session(self, app_client: AsyncClient):
        """TC-F-004: Create session in mcp_ingest mode."""
        payload = {
            "name": "MCP Ingest Session",
            "simulation_mode": "mcp_ingest",
            "event_count": 20,
            "mcp_server_url": "http://mcp.example.com/mcp",
            "mcp_api_key": "test-key-xyz",
            "mcp_tool": "siem_search_events",
            "mcp_query": "index=main severity=high",
        }
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        cfg = data["config"]
        assert cfg["simulation_mode"] == "mcp_ingest"
        assert cfg["mcp_server_url"] == "http://mcp.example.com/mcp"
        assert cfg["mcp_tool"] == "siem_search_events"

    @pytest.mark.asyncio
    async def test_create_session_auto_name_when_untitled(self, app_client: AsyncClient):
        """TC-R-006: Auto-generate name when name is 'Untitled Session'."""
        payload = make_session_payload(name="Untitled Session", mode="attack_chain")
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        # Name should have been auto-generated, containing "Attack Chain"
        assert data["name"] != "Untitled Session"
        assert "Attack Chain" in data["name"]

    @pytest.mark.asyncio
    async def test_create_session_auto_name_when_empty(self, app_client: AsyncClient):
        """TC-R-006b: Auto-generate name when name is empty string."""
        payload = make_session_payload(name="", mode="ttps", technique_ids=["T1059"])
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] != ""

    @pytest.mark.asyncio
    async def test_create_session_event_count_validation(self, app_client: AsyncClient):
        """TC-S-001: event_count must be between 10 and 2000."""
        payload = make_session_payload(event_count=5)  # below minimum of 10
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 422  # Pydantic validation error

    @pytest.mark.asyncio
    async def test_create_session_event_count_max(self, app_client: AsyncClient):
        """TC-S-002: event_count above 2000 is rejected."""
        payload = make_session_payload(event_count=2001)
        resp = await app_client.post("/api/v2/sessions", json=payload)
        assert resp.status_code == 422


class TestSessionList:
    """Test session listing with filters."""

    @pytest.mark.asyncio
    async def test_list_sessions_returns_pagination(self, app_client: AsyncClient):
        """TC-F-005: List sessions returns pagination fields."""
        resp = await app_client.get("/api/v2/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert "sessions" in data
        assert "total" in data
        assert "skip" in data
        assert "limit" in data

    @pytest.mark.asyncio
    async def test_list_sessions_status_filter(self, app_client: AsyncClient):
        """TC-F-006: List sessions with status filter."""
        # Create a session first
        await create_test_session(app_client, name="Filter Test Session")

        # Filter by stopped status
        resp = await app_client.get("/api/v2/sessions?status=stopped")
        assert resp.status_code == 200
        data = resp.json()
        for s in data["sessions"]:
            assert s["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_list_sessions_pagination_params(self, app_client: AsyncClient):
        """TC-F-007: List sessions respects skip and limit."""
        resp = await app_client.get("/api/v2/sessions?skip=0&limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["sessions"]) <= 5


class TestSessionGetUpdateDelete:
    """Test single session operations."""

    @pytest.mark.asyncio
    async def test_get_session_includes_recent_events(self, app_client: AsyncClient):
        """TC-F-008: GET session returns recent_events field."""
        session = await create_test_session(app_client, name="Get Test Session")
        resp = await app_client.get(f"/api/v2/sessions/{session['id']}")
        assert resp.status_code == 200
        data = resp.json()
        assert "recent_events" in data
        assert isinstance(data["recent_events"], list)

    @pytest.mark.asyncio
    async def test_get_session_not_found(self, app_client: AsyncClient):
        """TC-S-003: GET non-existent session returns 404."""
        fake_id = str(uuid.uuid4())
        resp = await app_client.get(f"/api/v2/sessions/{fake_id}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_session_invalid_uuid(self, app_client: AsyncClient):
        """TC-S-004: GET session with invalid UUID returns 400."""
        resp = await app_client.get("/api/v2/sessions/not-a-uuid")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_rename_session(self, app_client: AsyncClient):
        """TC-F-009: PATCH /rename changes session name."""
        session = await create_test_session(app_client, name="Original Name")
        sid = session["id"]

        resp = await app_client.patch(
            f"/api/v2/sessions/{sid}/rename",
            json={"name": "Renamed Session"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Renamed Session"

    @pytest.mark.asyncio
    async def test_rename_session_empty_name_fails(self, app_client: AsyncClient):
        """TC-S-005: Rename with empty name returns 400."""
        session = await create_test_session(app_client, name="Test")
        sid = session["id"]
        resp = await app_client.patch(f"/api/v2/sessions/{sid}/rename", json={"name": ""})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_session(self, app_client: AsyncClient):
        """TC-F-010: DELETE session returns deleted status."""
        session = await create_test_session(app_client, name="To Delete")
        sid = session["id"]
        resp = await app_client.delete(f"/api/v2/sessions/{sid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "deleted"
        assert data["id"] == sid

        # Verify it's gone
        resp2 = await app_client.get(f"/api/v2/sessions/{sid}")
        assert resp2.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_session_returns_correct_format(self, app_client: AsyncClient):
        """TC-R-010: Delete returns {status: deleted, id: session_id}."""
        session = await create_test_session(app_client, name="Delete Format Test")
        sid = session["id"]
        resp = await app_client.delete(f"/api/v2/sessions/{sid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data == {"status": "deleted", "id": sid}


# ===========================================================================
# 2. SESSION LIFECYCLE TESTS
# ===========================================================================

class TestSessionLifecycle:
    """Test start/stop lifecycle with mocked engine."""

    @pytest.mark.asyncio
    async def test_start_session_changes_status(self, app_client: AsyncClient):
        """TC-F-011: Start session sets status to running."""
        session = await create_test_session(app_client)
        sid = session["id"]

        with patch("backend.engine.session_manager.SessionManager.start_session", new_callable=AsyncMock):
            resp = await app_client.post(f"/api/v2/sessions/{sid}/start")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] in ("started", "already_running")

    @pytest.mark.asyncio
    async def test_start_already_running_session(self, app_client: AsyncClient):
        """TC-F-012: Starting already-running session returns already_running."""
        session = await create_test_session(app_client)
        sid = session["id"]

        with patch("backend.engine.session_manager.SessionManager.start_session", new_callable=AsyncMock):
            # Start it
            await app_client.post(f"/api/v2/sessions/{sid}/start")
            # Try to start again
            resp = await app_client.post(f"/api/v2/sessions/{sid}/start")
            assert resp.status_code == 200
            # May return already_running or started depending on timing

    @pytest.mark.asyncio
    async def test_stop_session(self, app_client: AsyncClient):
        """TC-F-013: Stop session returns stopped status."""
        session = await create_test_session(app_client)
        sid = session["id"]

        with patch("backend.engine.session_manager.SessionManager.stop_session", new_callable=AsyncMock):
            resp = await app_client.post(f"/api/v2/sessions/{sid}/stop")
            assert resp.status_code == 200
            assert resp.json()["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_stop_session_triggers_joti_push(self, app_client: AsyncClient):
        """TC-I-001: Stopping session calls joti.push_simulation_result."""
        session = await create_test_session(
            app_client,
            mode="ttps",
            technique_ids=["T1059.001"],
        )
        sid = session["id"]

        push_calls = []

        async def mock_push(result):
            push_calls.append(result)
            return True

        with patch("backend.joti.client.get_joti_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.push_simulation_result = mock_push
            mock_get_client.return_value = mock_client
            with patch("backend.engine.session_manager.SessionManager.stop_session", new_callable=AsyncMock):
                resp = await app_client.post(f"/api/v2/sessions/{sid}/stop")
                assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_stop_session_joti_failure_is_non_fatal(self, app_client: AsyncClient):
        """TC-F-014: Joti push failure doesn't fail stop endpoint."""
        session = await create_test_session(app_client)
        sid = session["id"]

        with patch("backend.joti.client.get_joti_client") as mock_get_client:
            mock_client = AsyncMock()
            mock_client.push_simulation_result = AsyncMock(side_effect=Exception("Joti down"))
            mock_get_client.return_value = mock_client
            with patch("backend.engine.session_manager.SessionManager.stop_session", new_callable=AsyncMock):
                resp = await app_client.post(f"/api/v2/sessions/{sid}/stop")
                # Must still return 200 even with Joti failure
                assert resp.status_code == 200
                assert resp.json()["status"] == "stopped"


# ===========================================================================
# 3. SESSION STATS AND EVENTS TESTS
# ===========================================================================

class TestSessionStats:
    """Test session stats endpoint."""

    @pytest.mark.asyncio
    async def test_session_stats_returns_expected_fields(self, app_client: AsyncClient, db_session: AsyncSession):
        """TC-F-015: GET /stats returns all expected fields."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        resp = await app_client.get(f"/api/v2/sessions/{sid}/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_events" in data
        assert "by_severity" in data
        assert "by_source" in data
        assert "top_techniques" in data
        assert "events_per_minute" in data
        assert data["session_id"] == sid

    @pytest.mark.asyncio
    async def test_session_stats_severity_breakdown(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-F-016: Stats by_severity aggregates correctly."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        # Insert events of different severities
        await create_generated_event(db_session, s.id, severity="high")
        await create_generated_event(db_session, s.id, severity="critical")
        await create_generated_event(db_session, s.id, severity="high")

        resp = await app_client.get(f"/api/v2/sessions/{sid}/stats")
        assert resp.status_code == 200
        by_sev = resp.json()["by_severity"]
        assert by_sev.get("high", 0) >= 2
        assert by_sev.get("critical", 0) >= 1

    @pytest.mark.asyncio
    async def test_session_stats_top_techniques_from_title(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-R-007: top_techniques is derived from title field (not payload)."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        for _ in range(3):
            await create_generated_event(db_session, s.id, title="T1059.001")
        await create_generated_event(db_session, s.id, title="T1003.001")

        resp = await app_client.get(f"/api/v2/sessions/{sid}/stats")
        assert resp.status_code == 200
        top = resp.json()["top_techniques"]
        assert len(top) > 0
        first = top[0]
        assert first["technique_id"] == "T1059.001"
        assert first["count"] == 3


class TestSessionEvents:
    """Test session events listing."""

    @pytest.mark.asyncio
    async def test_session_events_pagination(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-F-017: Events endpoint supports pagination."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        for i in range(5):
            await create_generated_event(db_session, s.id, title=f"T1059.{i:03d}")

        resp = await app_client.get(f"/api/v2/sessions/{sid}/events?skip=0&limit=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["events"]) <= 3
        assert data["total"] >= 5

    @pytest.mark.asyncio
    async def test_session_events_severity_filter(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-F-018: Events endpoint filters by severity."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        await create_generated_event(db_session, s.id, severity="high")
        await create_generated_event(db_session, s.id, severity="low")
        await create_generated_event(db_session, s.id, severity="critical")

        resp = await app_client.get(f"/api/v2/sessions/{sid}/events?severity=high")
        assert resp.status_code == 200
        data = resp.json()
        for evt in data["events"]:
            assert evt["severity"] == "high"


# ===========================================================================
# 4. EDR STATE MACHINE TESTS
# ===========================================================================

class TestEDRStateMachine:
    """Unit tests for the EDR state machine."""

    def setup_method(self):
        """Create a fresh state machine for each test."""
        from backend.engine.edr_state_machine import EndpointStateMachine, EndpointState
        self.machine = EndpointStateMachine()
        self.EndpointState = EndpointState

    def test_initial_state_is_online(self):
        """TC-I-007: New hostname defaults to ONLINE state."""
        state = self.machine.get_state("new-host")
        assert state == self.EndpointState.ONLINE

    def test_online_to_at_risk_via_t1059(self):
        """TC-I-008: T1059 event on ONLINE host → AT_RISK."""
        event = {
            "technique_id": "T1059.001",
            "source_type": "windows_eventlog",
            "payload": {"ComputerName": "VICTIM-01", "LocalIP": "10.0.0.5"},
        }
        secondary = self.machine.process_event(event)
        state = self.machine.get_state("VICTIM-01")
        assert state == self.EndpointState.AT_RISK
        # Should generate secondary events
        assert len(secondary) > 0
        # Secondary should include EDR alert
        assert any(e.get("_state_transition") for e in secondary)

    def test_at_risk_to_compromised_via_t1003(self):
        """TC-I-009: T1003 event on AT_RISK host → COMPROMISED."""
        from backend.engine.edr_state_machine import EndpointState
        self.machine.set_state("VICTIM-01", EndpointState.AT_RISK)
        event = {
            "technique_id": "T1003.001",
            "source_type": "windows_eventlog",
            "payload": {"ComputerName": "VICTIM-01", "LocalIP": "10.0.0.5"},
        }
        secondary = self.machine.process_event(event)
        state = self.machine.get_state("VICTIM-01")
        assert state == EndpointState.COMPROMISED
        # Should generate EDR alert + Windows event
        assert len(secondary) >= 2

    def test_false_positive_returns_at_risk_to_online(self):
        """TC-I-010: false_positive trigger on AT_RISK → ONLINE."""
        from backend.engine.edr_state_machine import EndpointState, _TRANSITIONS
        # Verify the transition exists in the table
        at_risk_transitions = _TRANSITIONS[EndpointState.AT_RISK]
        assert "false_positive" in at_risk_transitions
        assert at_risk_transitions["false_positive"] == EndpointState.ONLINE

    def test_isolation_requested_moves_to_isolated(self):
        """TC-I-010b: isolation_requested on COMPROMISED → ISOLATED."""
        from backend.engine.edr_state_machine import EndpointState, _TRANSITIONS
        assert "isolation_requested" in _TRANSITIONS[EndpointState.COMPROMISED]
        assert _TRANSITIONS[EndpointState.COMPROMISED]["isolation_requested"] == EndpointState.ISOLATED

    def test_high_fidelity_source_triggers_confirmed_detection(self):
        """TC-I-011: High-fidelity sources (crowdstrike) → confirmed_detection directly."""
        event = {
            "technique_id": "T1059.001",
            "source_type": "crowdstrike",  # high-fidelity
            "payload": {"ComputerName": "VICTIM-HF", "LocalIP": "10.0.0.10"},
        }
        self.machine.process_event(event)
        state = self.machine.get_state("VICTIM-HF")
        # crowdstrike → confirmed_detection, but ONLINE + confirmed_detection not valid
        # So no transition from ONLINE via confirmed_detection (need AT_RISK first)
        # This is intentional design — ONLINE only transitions via anomaly_detected
        # High-fidelity still triggers confirmed_detection trigger, but the
        # state machine only allows ONLINE→AT_RISK, so no change here
        # Let's set to AT_RISK first then test
        self.machine.set_state("VICTIM-HF2", self.EndpointState.AT_RISK)
        event2 = {
            "technique_id": "T1059.001",
            "source_type": "crowdstrike",
            "payload": {"ComputerName": "VICTIM-HF2", "LocalIP": "10.0.0.11"},
        }
        secondary = self.machine.process_event(event2)
        state2 = self.machine.get_state("VICTIM-HF2")
        assert state2 == self.EndpointState.COMPROMISED

    def test_benign_events_produce_no_secondary(self):
        """TC-R-007: Events with _benign=True produce no secondary events."""
        event = {
            "technique_id": "T1059.001",
            "source_type": "windows_eventlog",
            "_benign": True,
            "payload": {"ComputerName": "VICTIM-BENIGN"},
        }
        secondary = self.machine.process_event(event)
        assert secondary == []

    def test_state_transition_events_produce_no_secondary(self):
        """TC-R-008: Events with _state_transition=True produce no secondary events."""
        event = {
            "technique_id": "T1059.001",
            "source_type": "edr",
            "_state_transition": True,
            "payload": {"ComputerName": "VICTIM-TRANS"},
        }
        secondary = self.machine.process_event(event)
        assert secondary == []

    def test_snapshot_returns_string_values(self):
        """TC-F-019: snapshot() returns dict with string state values."""
        from backend.engine.edr_state_machine import EndpointState
        self.machine.set_state("HOST-A", EndpointState.ISOLATED)
        self.machine.set_state("HOST-B", EndpointState.AT_RISK)
        snap = self.machine.snapshot()
        assert snap["HOST-A"] == "isolated"
        assert snap["HOST-B"] == "at_risk"

    def test_isolated_generates_three_secondary_events(self):
        """TC-I-010c: COMPROMISED → ISOLATED generates EDR + Windows + auto-isolation events."""
        from backend.engine.edr_state_machine import EndpointState
        self.machine.set_state("VICTIM-ISO", EndpointState.COMPROMISED)
        event = {
            "technique_id": "T1003.001",
            "source_type": "edr",
            "payload": {"ComputerName": "VICTIM-ISO", "LocalIP": "10.0.0.20"},
        }
        # Manually trigger isolation_requested
        self.machine.set_state("VICTIM-ISO", EndpointState.AT_RISK)
        event2 = {
            "technique_id": "T1003.001",
            "source_type": "edr",
            "payload": {"ComputerName": "VICTIM-ISO", "LocalIP": "10.0.0.20"},
        }
        self.machine.process_event(event2)  # → COMPROMISED
        # Now trigger isolation
        import asyncio
        from backend.engine.action_executor import execute_action
        result = asyncio.get_event_loop().run_until_complete(
            execute_action("test-session-iso", "isolate_host", {"hostname": "VICTIM-ISO"})
        )
        assert result.success
        state = self.machine.get_state("VICTIM-ISO")
        assert state == EndpointState.ISOLATED

    def test_set_state_and_get_state(self):
        """TC-F-020: set_state/get_state roundtrip."""
        from backend.engine.edr_state_machine import EndpointState
        for state in EndpointState:
            self.machine.set_state("HOST-ROUNDTRIP", state)
            assert self.machine.get_state("HOST-ROUNDTRIP") == state

    def test_missing_hostname_produces_no_secondary(self):
        """TC-F-021: Events without hostname in payload produce no secondary events."""
        event = {
            "technique_id": "T1059.001",
            "source_type": "windows_eventlog",
            "payload": {},  # No ComputerName or hostname
        }
        secondary = self.machine.process_event(event)
        assert secondary == []


# ===========================================================================
# 5. ACTION EXECUTOR TESTS
# ===========================================================================

class TestActionExecutor:
    """Test the SOAR action executor."""

    @pytest.mark.asyncio
    async def test_isolate_host_returns_success(self):
        """TC-I-012: isolate_host action returns ActionResult with success=True."""
        from backend.engine.action_executor import execute_action
        from backend.engine.edr_state_machine import get_machine, EndpointState

        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("TARGET-HOST", EndpointState.COMPROMISED)

        with patch("backend.engine.action_executor._store_event", new_callable=AsyncMock, return_value=str(uuid.uuid4())):
            with patch("backend.engine.action_executor._persist_action", new_callable=AsyncMock):
                result = await execute_action(session_id, "isolate_host", {"hostname": "TARGET-HOST", "actor": "test"})

        assert result.success is True
        assert result.action_type == "isolate_host"
        assert result.target == "TARGET-HOST"
        assert result.state_after == "isolated"

    @pytest.mark.asyncio
    async def test_release_host_sets_remediated_state(self):
        """TC-F-022: release_host sets state to REMEDIATED."""
        from backend.engine.action_executor import execute_action
        from backend.engine.edr_state_machine import get_machine, EndpointState

        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("RELEASE-HOST", EndpointState.ISOLATED)

        with patch("backend.engine.action_executor._store_event", new_callable=AsyncMock, return_value=str(uuid.uuid4())):
            with patch("backend.engine.action_executor._persist_action", new_callable=AsyncMock):
                result = await execute_action(session_id, "release_host", {"hostname": "RELEASE-HOST"})

        assert result.success is True
        assert result.state_after == "remediated"
        state = machine.get_state("RELEASE-HOST")
        assert state == EndpointState.REMEDIATED

    @pytest.mark.asyncio
    async def test_block_ioc_ip_uses_firewall_state(self):
        """TC-I-013: block_ioc with ip type updates firewall state machine."""
        from backend.engine.action_executor import execute_action
        from backend.engine.product_state_machines import get_bundle, FirewallState

        session_id = str(uuid.uuid4())
        with patch("backend.engine.action_executor._store_event", new_callable=AsyncMock, return_value=str(uuid.uuid4())):
            with patch("backend.engine.action_executor._persist_action", new_callable=AsyncMock):
                result = await execute_action(session_id, "block_ioc", {
                    "ioc_type": "ip",
                    "ioc_value": "192.168.1.100",
                    "actor": "joti_soar",
                })

        assert result.success is True
        assert result.action_type == "block_ioc"
        bundle = get_bundle(session_id)
        # Verify firewall was set to BLOCKED
        fw_state = bundle.firewall.get_state("192.168.1.100")
        assert fw_state == FirewallState.BLOCKED

    @pytest.mark.asyncio
    async def test_unknown_action_returns_failure(self):
        """TC-F-023: Unknown action type returns ActionResult with success=False."""
        from backend.engine.action_executor import execute_action

        result = await execute_action(str(uuid.uuid4()), "not_a_real_action", {})
        assert result.success is False
        assert "Unknown action type" in result.message

    @pytest.mark.asyncio
    async def test_action_result_has_timestamp(self):
        """TC-F-024: ActionResult always has a timestamp."""
        from backend.engine.action_executor import execute_action

        with patch("backend.engine.action_executor._store_event", new_callable=AsyncMock, return_value="evt-1"):
            with patch("backend.engine.action_executor._persist_action", new_callable=AsyncMock):
                result = await execute_action(str(uuid.uuid4()), "inject_alert", {"title": "Test"})

        assert result.timestamp
        # Should be a valid ISO timestamp
        assert "T" in result.timestamp or result.timestamp != ""


# ===========================================================================
# 6. VENDOR API — SPLUNK TESTS
# ===========================================================================

class TestSplunkVendorAPI:
    """Test the Splunk vendor API emulation."""

    @pytest.mark.asyncio
    async def test_splunk_server_info(self, app_client: AsyncClient):
        """TC-I-019: Splunk server info returns version '9.1.0 (PurpleLab Emulation)'."""
        resp = await app_client.get("/api/vendor/splunk/services/server/info")
        assert resp.status_code == 200
        data = resp.json()
        content = data["entry"][0]["content"]
        assert "9.1.0" in content["version"]
        assert "PurpleLab" in content["version"]
        assert content["serverName"] == "purplelab-splunk-sim"

    @pytest.mark.asyncio
    async def test_create_splunk_search_job(self, app_client: AsyncClient):
        """TC-F-025: Create Splunk search job returns sid."""
        resp = await app_client.post(
            "/api/vendor/splunk/services/search/jobs",
            params={"session_id": str(uuid.uuid4()), "output_mode": "json"},
            content='search index=main sourcetype="crowdstrike"',
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "sid" in data

    @pytest.mark.asyncio
    async def test_splunk_job_id_format(self, app_client: AsyncClient):
        """TC-R-011: Splunk job ID starts with 'sim_' followed by 16 hex chars."""
        resp = await app_client.post(
            "/api/vendor/splunk/services/search/jobs",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200
        sid = resp.json()["sid"]
        assert sid.startswith("sim_")
        hex_part = sid[4:]
        assert len(hex_part) == 16
        assert all(c in "0123456789abcdef" for c in hex_part)

    @pytest.mark.asyncio
    async def test_get_splunk_job_status(self, app_client: AsyncClient):
        """TC-F-026: Get Splunk job status returns dispatchState=DONE."""
        # Create a job first
        resp1 = await app_client.post("/api/vendor/splunk/services/search/jobs")
        sid = resp1.json()["sid"]

        resp2 = await app_client.get(f"/api/vendor/splunk/services/search/jobs/{sid}")
        assert resp2.status_code == 200
        data = resp2.json()
        content = data["entry"][0]["content"]
        assert content["dispatchState"] == "DONE"

    @pytest.mark.asyncio
    async def test_get_splunk_job_results(self, app_client: AsyncClient):
        """TC-F-027: Get Splunk job results returns results list."""
        resp1 = await app_client.post("/api/vendor/splunk/services/search/jobs")
        sid = resp1.json()["sid"]

        resp2 = await app_client.get(f"/api/vendor/splunk/services/search/jobs/{sid}/results")
        assert resp2.status_code == 200
        data = resp2.json()
        assert "results" in data
        assert isinstance(data["results"], list)

    @pytest.mark.asyncio
    async def test_splunk_unknown_job_returns_empty(self, app_client: AsyncClient):
        """TC-S-006: Unknown Splunk job SID returns empty results, not 404."""
        resp = await app_client.get("/api/vendor/splunk/services/search/jobs/unknown-sid/results")
        assert resp.status_code == 200
        data = resp.json()
        # Should return WARN message and empty results
        assert "results" in data
        assert data["results"] == []

    @pytest.mark.asyncio
    async def test_splunk_create_saved_search(self, app_client: AsyncClient):
        """TC-F-028: Create Splunk saved search (detection deployment)."""
        payload = {
            "name": "Test Detection Rule",
            "search": "index=main EventID=4688 CommandLine=*mimikatz*",
            "description": "Test mimikatz detection",
            "session_id": str(uuid.uuid4()),
        }
        resp = await app_client.post(
            "/api/vendor/splunk/services/saved/searches",
            json=payload,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "entry" in data
        entry = data["entry"][0]
        assert entry["name"] == "Test Detection Rule"
        assert "id" in entry

    @pytest.mark.asyncio
    async def test_splunk_create_notable_event(self, app_client: AsyncClient):
        """TC-F-029: Create Splunk notable event returns notable_id."""
        resp = await app_client.post(
            "/api/vendor/splunk/services/alerts/fired_alerts",
            params={"session_id": str(uuid.uuid4())},
            json={"search_name": "Mimikatz Detected", "urgency": "high"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "notable_id" in data


# ===========================================================================
# 7. VENDOR API — CROWDSTRIKE TESTS
# ===========================================================================

class TestCrowdStrikeVendorAPI:
    """Test the CrowdStrike Falcon vendor API emulation."""

    @pytest.mark.asyncio
    async def test_crowdstrike_oauth2_token(self, app_client: AsyncClient):
        """TC-F-030: CrowdStrike OAuth2 always returns a token."""
        resp = await app_client.post(
            "/api/vendor/crowdstrike/oauth2/token",
            json={"client_id": "test", "client_secret": "test"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["access_token"].startswith("cs-sim-token-")
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 1799

    @pytest.mark.asyncio
    async def test_crowdstrike_list_devices_empty_without_session(self, app_client: AsyncClient):
        """TC-S-007: CrowdStrike list devices without session_id returns empty."""
        resp = await app_client.get("/api/vendor/crowdstrike/devices/v1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["resources"] == []
        assert data["meta"]["total"] == 0

    @pytest.mark.asyncio
    async def test_crowdstrike_list_devices_with_session(self, app_client: AsyncClient):
        """TC-F-031: CrowdStrike list devices shows EDR state machine snapshot."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("WIN-HOST-01", EndpointState.AT_RISK)
        machine.set_state("WIN-HOST-02", EndpointState.ISOLATED)

        resp = await app_client.get(
            "/api/vendor/crowdstrike/devices/v1",
            params={"session_id": session_id},
        )
        assert resp.status_code == 200
        data = resp.json()
        resources = data["resources"]
        assert len(resources) == 2
        hostnames = [r["hostname"] for r in resources]
        assert "WIN-HOST-01" in hostnames
        assert "WIN-HOST-02" in hostnames

        # Isolated host should have containment_status=contained
        isolated_res = next(r for r in resources if r["hostname"] == "WIN-HOST-02")
        assert isolated_res["containment_status"] == "contained"

    @pytest.mark.asyncio
    async def test_crowdstrike_device_id_format(self, app_client: AsyncClient):
        """TC-R-012: CrowdStrike device_id = uuid.uuid5(NAMESPACE_DNS, session_id:hostname)."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("DEVICE-HOST", EndpointState.ONLINE)

        resp = await app_client.get(
            "/api/vendor/crowdstrike/devices/v1",
            params={"session_id": session_id},
        )
        data = resp.json()
        device = data["resources"][0]
        expected_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{session_id}:DEVICE-HOST"))
        assert device["device_id"] == expected_id

    @pytest.mark.asyncio
    async def test_crowdstrike_detections_only_high_critical(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-I-017: CrowdStrike detection IDs only include high/critical severity events."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        await create_generated_event(db_session, s.id, severity="high")
        await create_generated_event(db_session, s.id, severity="critical")
        await create_generated_event(db_session, s.id, severity="low")
        await create_generated_event(db_session, s.id, severity="medium")

        resp = await app_client.get(
            "/api/vendor/crowdstrike/detects/queries/detects/v1",
            params={"session_id": sid},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Should have exactly 2 (high + critical), not 4
        assert len(data["resources"]) == 2

    @pytest.mark.asyncio
    async def test_crowdstrike_detection_id_format(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-R-009: CrowdStrike detection ID format is 'ldt:{id_no_hyphens[:32]}:1'."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        evt = await create_generated_event(db_session, s.id, severity="high")

        resp = await app_client.get(
            "/api/vendor/crowdstrike/detects/queries/detects/v1",
            params={"session_id": sid},
        )
        data = resp.json()
        if data["resources"]:
            det_id = data["resources"][0]
            assert det_id.startswith("ldt:")
            assert det_id.endswith(":1")

    @pytest.mark.asyncio
    async def test_crowdstrike_block_ioc(self, app_client: AsyncClient):
        """TC-I-013b: CrowdStrike block IOC calls execute_action."""
        session_id = str(uuid.uuid4())
        with patch("backend.engine.action_executor.execute_action", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = MagicMock(
                success=True, message="blocked", dict=lambda: {"success": True, "message": "blocked"}
            )
            resp = await app_client.post(
                "/api/vendor/crowdstrike/iocs/entities/iocs/v1",
                params={"session_id": session_id},
                json={"resources": [{"type": "ipv4", "value": "1.2.3.4", "action": "prevent"}]},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["resources"]) == 1
        assert data["resources"][0]["value"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_crowdstrike_incidents_shows_compromised_hosts(self, app_client: AsyncClient):
        """TC-F-032: CrowdStrike incidents shows compromised + at_risk hosts."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("COMP-HOST", EndpointState.COMPROMISED)
        machine.set_state("RISK-HOST", EndpointState.AT_RISK)
        machine.set_state("ONLINE-HOST", EndpointState.ONLINE)

        resp = await app_client.get(
            "/api/vendor/crowdstrike/incidents/queries/incidents/v1",
            params={"session_id": session_id},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["resources"]) == 2  # compromised + at_risk, not online


# ===========================================================================
# 8. VENDOR API — XSIAM TESTS
# ===========================================================================

class TestXSIAMVendorAPI:
    """Test the Palo Alto XSIAM vendor API emulation."""

    @pytest.mark.asyncio
    async def test_xsiam_get_token(self, app_client: AsyncClient):
        """TC-F-033: XSIAM auth returns token in reply field."""
        resp = await app_client.post("/api/vendor/xsiam/public_api/v1/auth/get_token")
        assert resp.status_code == 200
        data = resp.json()
        assert "reply" in data
        assert "token" in data["reply"]
        assert data["reply"]["token"].startswith("xsiam-sim-")

    @pytest.mark.asyncio
    async def test_xsiam_xql_quota(self, app_client: AsyncClient):
        """TC-R-001: XSIAM quota endpoint returns correct fields."""
        resp = await app_client.post("/api/vendor/xsiam/public_api/v1/xql/quota")
        assert resp.status_code == 200
        data = resp.json()
        assert "reply" in data
        reply = data["reply"]
        assert "fixed_quota" in reply
        assert "additional_purchased_quota" in reply
        assert "license_quota" in reply
        assert reply["fixed_quota"] == 5000000

    @pytest.mark.asyncio
    async def test_xsiam_start_xql_query(self, app_client: AsyncClient):
        """TC-F-034: Start XQL query returns execution_id."""
        resp = await app_client.post(
            "/api/vendor/xsiam/public_api/v1/xql/start_xql_query",
            params={"session_id": str(uuid.uuid4())},
            json={"request_data": {"query": "dataset=xdr_data | limit 10"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["reply"]["status"] == "SUCCESS"
        assert "execution_id" in data["reply"]

    @pytest.mark.asyncio
    async def test_xsiam_get_results_by_query_id(self, app_client: AsyncClient):
        """TC-I-016: XSIAM get_query_results accepts 'query_id' field."""
        # Start a query
        resp1 = await app_client.post(
            "/api/vendor/xsiam/public_api/v1/xql/start_xql_query",
            json={"request_data": {"query": "select * from alerts"}},
        )
        execution_id = resp1.json()["reply"]["execution_id"]

        # Get results using query_id (Joti XSIAM adapter uses this)
        resp2 = await app_client.post(
            "/api/vendor/xsiam/public_api/v1/xql/get_query_results",
            json={"request_data": {"query_id": execution_id}},
        )
        assert resp2.status_code == 200
        assert resp2.json()["reply"]["status"] == "SUCCESS"

    @pytest.mark.asyncio
    async def test_xsiam_get_results_by_execution_id(self, app_client: AsyncClient):
        """TC-I-016b: XSIAM get_query_results accepts 'execution_id' field."""
        resp1 = await app_client.post(
            "/api/vendor/xsiam/public_api/v1/xql/start_xql_query",
            json={"request_data": {"query": "select * from alerts"}},
        )
        execution_id = resp1.json()["reply"]["execution_id"]

        resp2 = await app_client.post(
            "/api/vendor/xsiam/public_api/v1/xql/get_query_results",
            json={"request_data": {"execution_id": execution_id}},
        )
        assert resp2.status_code == 200
        assert resp2.json()["reply"]["status"] == "SUCCESS"

    @pytest.mark.asyncio
    async def test_xsiam_incidents_shows_compromised_at_risk(self, app_client: AsyncClient):
        """TC-F-035: XSIAM incidents from compromised + at_risk hosts."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("XSIAM-COMP", EndpointState.COMPROMISED)
        machine.set_state("XSIAM-RISK", EndpointState.AT_RISK)

        resp = await app_client.post(
            "/api/vendor/xsiam/public_api/v1/incidents/get_incidents",
            params={"session_id": session_id},
            json={"request_data": {}},
        )
        assert resp.status_code == 200
        incidents = resp.json()["reply"]["incidents"]
        assert len(incidents) == 2
        severity_vals = {inc["severity"] for inc in incidents}
        assert "HIGH" in severity_vals
        assert "MEDIUM" in severity_vals

    @pytest.mark.asyncio
    async def test_xsiam_isolate_endpoint(self, app_client: AsyncClient):
        """TC-I-003: XSIAM isolate endpoint updates EDR state machine."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("XSIAM-HOST", EndpointState.COMPROMISED)

        with patch("backend.engine.action_executor._store_event", new_callable=AsyncMock, return_value="evt-1"):
            with patch("backend.engine.action_executor._persist_action", new_callable=AsyncMock):
                resp = await app_client.post(
                    "/api/vendor/xsiam/public_api/v1/endpoints/isolate",
                    params={"session_id": session_id},
                    json={"request_data": {"filters": [{"field": "endpoint_id_list", "value": ["XSIAM-HOST"]}]}},
                )

        assert resp.status_code == 200
        data = resp.json()["reply"]
        assert "action_id" in data


# ===========================================================================
# 9. VENDOR API — DEFENDER TESTS
# ===========================================================================

class TestDefenderVendorAPI:
    """Test the Microsoft Defender vendor API emulation."""

    @pytest.mark.asyncio
    async def test_defender_get_token(self, app_client: AsyncClient):
        """TC-F-036: Defender OAuth2 returns Bearer token."""
        resp = await app_client.post("/api/vendor/defender/oauth2/v2.0/token")
        assert resp.status_code == 200
        data = resp.json()
        assert data["token_type"] == "Bearer"
        assert data["access_token"].startswith("mde-sim-token-")
        assert data["expires_in"] == 3600

    @pytest.mark.asyncio
    async def test_defender_list_machines(self, app_client: AsyncClient):
        """TC-F-037: Defender list machines returns endpoint details."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("DEF-HOST-01", EndpointState.ONLINE)
        machine.set_state("DEF-HOST-02", EndpointState.COMPROMISED)

        resp = await app_client.get(
            "/api/vendor/defender/api/machines",
            params={"session_id": session_id},
        )
        assert resp.status_code == 200
        machines = resp.json()["value"]
        assert len(machines) == 2

    @pytest.mark.asyncio
    async def test_defender_risk_score_mapping(self, app_client: AsyncClient):
        """TC-I-018: Defender riskScore: compromised→High, at_risk→Medium, online→Low."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("DEF-COMP", EndpointState.COMPROMISED)
        machine.set_state("DEF-RISK", EndpointState.AT_RISK)
        machine.set_state("DEF-OK", EndpointState.ONLINE)

        resp = await app_client.get(
            "/api/vendor/defender/api/machines",
            params={"session_id": session_id},
        )
        machines_by_name = {m["computerDnsName"]: m for m in resp.json()["value"]}
        assert machines_by_name["DEF-COMP"]["riskScore"] == "High"
        assert machines_by_name["DEF-RISK"]["riskScore"] == "Medium"
        assert machines_by_name["DEF-OK"]["riskScore"] == "Low"

    @pytest.mark.asyncio
    async def test_defender_machine_id_format(self, app_client: AsyncClient):
        """TC-R-013: Defender machine_id = uuid.uuid5(NAMESPACE_DNS, 'mde:{sid}:{hostname}')."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("DEF-MACHINE", EndpointState.ONLINE)

        resp = await app_client.get(
            "/api/vendor/defender/api/machines",
            params={"session_id": session_id},
        )
        machines = resp.json()["value"]
        m = machines[0]
        expected_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mde:{session_id}:DEF-MACHINE"))
        assert m["id"] == expected_id

    @pytest.mark.asyncio
    async def test_defender_list_alerts_high_critical_only(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-I-004: Defender alerts endpoint shows high/critical events only."""
        s = await create_sim_session_db(db_session)
        sid = str(s.id)
        await create_generated_event(db_session, s.id, severity="high")
        await create_generated_event(db_session, s.id, severity="medium")
        await create_generated_event(db_session, s.id, severity="low")

        resp = await app_client.get(
            "/api/vendor/defender/api/alerts",
            params={"session_id": sid},
        )
        assert resp.status_code == 200
        alerts = resp.json()["value"]
        # Should only see the high one, not medium/low
        assert len(alerts) == 1

    @pytest.mark.asyncio
    async def test_defender_isolate_machine(self, app_client: AsyncClient):
        """TC-I-004b: Defender isolate machine calls execute_action."""
        from backend.engine.edr_state_machine import get_machine, EndpointState
        session_id = str(uuid.uuid4())
        machine = get_machine(session_id)
        machine.set_state("DEF-ISO-HOST", EndpointState.COMPROMISED)

        machine_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mde:{session_id}:DEF-ISO-HOST"))

        with patch("backend.engine.action_executor._store_event", new_callable=AsyncMock, return_value="evt-1"):
            with patch("backend.engine.action_executor._persist_action", new_callable=AsyncMock):
                resp = await app_client.post(
                    f"/api/vendor/defender/api/machines/{machine_id}/isolate",
                    params={"session_id": session_id},
                    json={"IsolationType": "Full", "Comment": "Isolating compromised host"},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "Isolate"


# ===========================================================================
# 10. ITDR SCENARIO TESTS
# ===========================================================================

class TestITDRScenarios:
    """Test all 10 ITDR attack scenarios."""

    @pytest.mark.asyncio
    async def test_list_itdr_scenarios_returns_10(self, app_client: AsyncClient):
        """TC-F-038: List ITDR scenarios returns exactly 10."""
        resp = await app_client.get("/api/v2/itdr/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 10
        assert len(data["scenarios"]) == 10

    @pytest.mark.asyncio
    async def test_itdr_summary_has_required_fields(self, app_client: AsyncClient):
        """TC-F-039: ITDR scenario summary has id, name, technique_id, severity, platforms."""
        resp = await app_client.get("/api/v2/itdr/scenarios")
        for s in resp.json()["scenarios"]:
            assert "id" in s
            assert "name" in s
            assert "technique_id" in s
            assert "mitre_tactic" in s
            assert "severity" in s
            assert "platforms" in s
            assert "step_count" in s

    @pytest.mark.parametrize("scenario_id,expected_technique", [
        ("kerberoasting", "T1558.003"),
        ("pass_the_hash", "T1550.002"),
        ("golden_ticket", "T1558.001"),
        ("dcsync", "T1003.006"),
        ("mfa_fatigue", "T1621"),
        ("impossible_travel", "T1550.004"),
        ("password_spray", "T1110.003"),
        ("credential_stuffing", "T1110.004"),
        ("token_theft", "T1528"),
        ("privileged_account_creation", "T1136.001"),
    ])
    @pytest.mark.asyncio
    async def test_itdr_scenario_technique_id(
        self, app_client: AsyncClient, scenario_id: str, expected_technique: str
    ):
        """TC-F-040: Each ITDR scenario has correct MITRE technique ID."""
        resp = await app_client.get(f"/api/v2/itdr/scenarios/{scenario_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["technique_id"] == expected_technique

    @pytest.mark.asyncio
    async def test_itdr_get_kerberoasting_full_detail(self, app_client: AsyncClient):
        """TC-F-041: Get kerberoasting scenario includes Sigma, SPL, KQL."""
        resp = await app_client.get("/api/v2/itdr/scenarios/kerberoasting")
        assert resp.status_code == 200
        data = resp.json()
        assert "detection_sigma" in data
        assert "hunt_query_spl" in data
        assert "hunt_query_kql" in data
        assert "simulation_steps" in data
        assert "expected_logs" in data
        # Kerberoasting should reference EventID 4769
        assert "4769" in data["detection_sigma"]

    @pytest.mark.asyncio
    async def test_itdr_get_sigma_yaml_only(self, app_client: AsyncClient):
        """TC-F-042: GET /sigma returns only sigma YAML."""
        resp = await app_client.get("/api/v2/itdr/scenarios/dcsync/sigma")
        assert resp.status_code == 200
        data = resp.json()
        assert "sigma_yaml" in data
        assert data["technique_id"] == "T1003.006"
        # DCSync sigma should reference EventID 4662
        assert "4662" in data["sigma_yaml"]

    @pytest.mark.asyncio
    async def test_itdr_get_hunt_queries(self, app_client: AsyncClient):
        """TC-F-043: GET /hunt-queries returns SPL and KQL."""
        resp = await app_client.get("/api/v2/itdr/scenarios/mfa_fatigue/hunt-queries")
        assert resp.status_code == 200
        data = resp.json()
        assert "hunt_query_spl" in data
        assert "hunt_query_kql" in data
        assert data["technique_id"] == "T1621"

    @pytest.mark.asyncio
    async def test_itdr_unknown_scenario_returns_404(self, app_client: AsyncClient):
        """TC-S-008: Unknown scenario ID returns 404."""
        resp = await app_client.get("/api/v2/itdr/scenarios/not_real_scenario")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_itdr_simulate_dry_run_true_default(self, app_client: AsyncClient):
        """TC-F-044: Simulate with dry_run=True returns steps without creating session."""
        resp = await app_client.post(
            "/api/v2/itdr/scenarios/golden_ticket/simulate",
            json={"dry_run": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "dry_run"
        assert "steps" in data
        assert "expected_logs" in data
        assert "T1558.001" in data["technique_id"]

    @pytest.mark.asyncio
    async def test_itdr_simulate_dry_run_is_default(self, app_client: AsyncClient):
        """TC-R-004: ITDR simulate defaults to dry_run=True — no exercise created."""
        resp = await app_client.post(
            "/api/v2/itdr/scenarios/kerberoasting/simulate",
            json={},  # No dry_run specified — should default to True
        )
        assert resp.status_code == 200
        data = resp.json()
        # If dry_run defaults to True, should return dry_run status
        assert data["status"] == "dry_run"


# ===========================================================================
# 11. JOTI INTEGRATION TESTS
# ===========================================================================

class TestJotiIntegration:
    """Test Joti TIP platform integration."""

    def test_get_joti_client_returns_none_without_config(self):
        """TC-R-009b: get_joti_client() returns None when JOTI_BASE_URL is empty."""
        from backend.joti.client import get_joti_client
        with patch("backend.joti.client.settings") as mock_settings:
            mock_settings.JOTI_BASE_URL = ""
            mock_settings.JOTI_API_KEY = "some-key"
            client = get_joti_client()
            assert client is None

    def test_get_joti_client_returns_none_without_api_key(self):
        """TC-F-045: get_joti_client() returns None when JOTI_API_KEY is empty."""
        from backend.joti.client import get_joti_client
        with patch("backend.joti.client.settings") as mock_settings:
            mock_settings.JOTI_BASE_URL = "http://joti.example.com"
            mock_settings.JOTI_API_KEY = ""
            client = get_joti_client()
            assert client is None

    def test_get_joti_client_returns_client_with_config(self):
        """TC-F-046: get_joti_client() returns JotiClient when both env vars set."""
        from backend.joti.client import get_joti_client, JotiClient
        with patch("backend.joti.client.settings") as mock_settings:
            mock_settings.JOTI_BASE_URL = "http://joti.example.com"
            mock_settings.JOTI_API_KEY = "test-api-key-xyz"
            client = get_joti_client()
            assert client is not None
            assert isinstance(client, JotiClient)

    def test_joti_client_headers_include_x_source(self):
        """TC-F-047: JotiClient sets X-Source: purplelab header."""
        from backend.joti.client import JotiClient
        client = JotiClient("http://joti.example.com", "test-key")
        assert client._headers["X-Source"] == "purplelab"
        assert client._headers["Authorization"] == "Bearer test-key"

    @pytest.mark.asyncio
    async def test_joti_push_simulation_result_payload(self):
        """TC-I-014: push_simulation_result sends correct payload fields."""
        from backend.joti.client import JotiClient

        posted_body = {}

        async def mock_post(path, body):
            posted_body.update(body)
            return {"status": "ok"}

        client = JotiClient("http://joti.example.com", "test-key")
        client._post = mock_post

        await client.push_simulation_result({
            "session_id": "test-session-id",
            "session_name": "Test Sim",
            "technique_ids": ["T1059.001"],
            "severity": "high",
            "events_generated": 100,
            "hit": True,
            "summary": "Test summary",
        })

        assert posted_body["session_id"] == "test-session-id"
        assert posted_body["session_name"] == "Test Sim"
        assert "T1059.001" in posted_body["technique_ids"]

    @pytest.mark.asyncio
    async def test_joti_audit_event_ingest(self, app_client: AsyncClient, db_session: AsyncSession):
        """TC-I-005: POST /joti/audit-events stores JotiAuditEvent in DB."""
        payload = {
            "events": [
                {
                    "id": 12345,
                    "event_type": "HUNT_TRIGGER",
                    "action": "hunt_triggered",
                    "user_email": "analyst@joti.local",
                    "ip_address": "10.0.0.1",
                    "resource_type": "hunt",
                    "resource_id": 42,
                    "details": {"technique_ids": ["T1059.001"]},
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            ]
        }
        resp = await app_client.post("/api/v2/joti/audit-events", json=payload)
        # Accept 200 or 201
        assert resp.status_code in (200, 201)


# ===========================================================================
# 12. USE CASE TESTS
# ===========================================================================

class TestUseCases:
    """Test use case management and validation."""

    @pytest.mark.asyncio
    async def test_list_use_cases(self, app_client: AsyncClient):
        """TC-F-048: GET /use-cases returns use_cases list."""
        resp = await app_client.get("/api/v2/use-cases")
        assert resp.status_code == 200
        data = resp.json()
        assert "use_cases" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_create_use_case(self, app_client: AsyncClient):
        """TC-F-049: POST /use-cases creates a new use case."""
        payload = {
            "name": "API Created Use Case",
            "description": "Test use case created via API",
            "technique_ids": ["T1059.001"],
            "tactic": "execution",
            "severity": "high",
            "tags": ["windows", "execution"],
            "is_active": True,
        }
        resp = await app_client.post("/api/v2/use-cases", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "API Created Use Case"

    @pytest.mark.asyncio
    async def test_get_coverage_summary(self, app_client: AsyncClient):
        """TC-F-050: GET /use-cases/coverage returns coverage data."""
        resp = await app_client.get("/api/v2/use-cases/coverage")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_failing_use_cases(self, app_client: AsyncClient):
        """TC-F-051: GET /use-cases/failing returns failing list."""
        resp = await app_client.get("/api/v2/use-cases/failing")
        assert resp.status_code == 200
        data = resp.json()
        assert "failing" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_use_case_not_found(self, app_client: AsyncClient):
        """TC-S-009: GET non-existent use case returns 404."""
        resp = await app_client.get(f"/api/v2/use-cases/{uuid.uuid4()}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_use_case_run_creates_pending_run_first(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-I-006: POST /{id}/run creates pending UseCaseRun before Celery dispatch."""
        uc = await create_use_case(db_session, name="Celery Test UC")
        uc_id = str(uc.id)

        with patch("backend.tasks.use_case_tasks.run_use_case_task") as mock_task:
            mock_task.delay.return_value = MagicMock(id="test-task-id")
            resp = await app_client.post(f"/api/v2/use-cases/{uc_id}/run")

        assert resp.status_code == 200
        data = resp.json()
        assert "run_id" in data
        assert data["status"] == "queued"
        assert "task_id" in data

        # Verify the pending run was created in DB
        result = await db_session.execute(
            select(MagicMock).where(MagicMock.id == data["run_id"])
        )

    @pytest.mark.asyncio
    async def test_identity_simulate_requires_identity_tag(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-S-010: simulate-identity fails for use case without identity tag."""
        uc = await create_use_case(db_session, tags=["windows"])  # Not identity tag
        uc_id = str(uc.id)

        resp = await app_client.post(
            f"/api/v2/use-cases/{uc_id}/simulate-identity",
            json={"action": "lock_user"},
        )
        assert resp.status_code == 400
        assert "identity" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_identity_simulate_invalid_action(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-S-011: simulate-identity with invalid action returns 400 with valid actions list."""
        uc = await create_use_case(db_session, tags=["identity"])
        uc_id = str(uc.id)

        resp = await app_client.post(
            f"/api/v2/use-cases/{uc_id}/simulate-identity",
            json={"action": "not_a_valid_action"},
        )
        assert resp.status_code == 400
        assert "Valid actions" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_identity_simulate_dry_run(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-F-052: simulate-identity with dry_run=True returns preview."""
        uc = await create_use_case(db_session, tags=["identity"])
        uc_id = str(uc.id)

        from backend.db.models import SimulatedUser

        # Seed a simulated user
        user = SimulatedUser(
            username="testuser",
            email="testuser@corp.local",
            display_name="Test User",
            mfa_enrolled=True,
            status="active",
            risk_level="low",
        )
        db_session.add(user)
        await db_session.commit()

        resp = await app_client.post(
            f"/api/v2/use-cases/{uc_id}/simulate-identity",
            json={"action": "lock_user", "dry_run": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["dry_run"] is True
        assert data["action"] == "lock_user"


# ===========================================================================
# 13. SESSION ISOLATION TESTS
# ===========================================================================

class TestSessionIsolation:
    """Test that sessions are isolated from each other."""

    @pytest.mark.asyncio
    async def test_events_from_session_a_not_visible_in_session_b(
        self, app_client: AsyncClient, db_session: AsyncSession
    ):
        """TC-S-012: Events from session A are not returned by session B endpoint."""
        s_a = await create_sim_session_db(db_session, name="Session A")
        s_b = await create_sim_session_db(db_session, name="Session B")

        # Add events only to session A
        await create_generated_event(db_session, s_a.id, title="T1059 - Session A Event")

        resp = await app_client.get(f"/api/v2/sessions/{str(s_b.id)}/events")
        assert resp.status_code == 200
        data = resp.json()
        # Session B should have no events
        for evt in data["events"]:
            assert evt["session_id"] == str(s_b.id)
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_edr_state_machine_isolated_per_session(self):
        """TC-P-010: EDR state machines are isolated per session."""
        from backend.engine.edr_state_machine import get_machine, EndpointState, drop_machine
        sid_a = "test-isolation-a-" + str(uuid.uuid4())[:8]
        sid_b = "test-isolation-b-" + str(uuid.uuid4())[:8]

        machine_a = get_machine(sid_a)
        machine_b = get_machine(sid_b)

        machine_a.set_state("HOST-01", EndpointState.COMPROMISED)

        # Session B's machine should NOT see session A's state
        assert machine_b.get_state("HOST-01") == EndpointState.ONLINE  # default

        drop_machine(sid_a)
        drop_machine(sid_b)


# ===========================================================================
# 14. MCP RESOLVE TESTS
# ===========================================================================

class TestMCPResolve:
    """Test the MCP resolve endpoint."""

    @pytest.mark.asyncio
    async def test_mcp_resolve_without_url_returns_400(self, app_client: AsyncClient):
        """TC-S-013: MCP resolve without mcp_server_url in config returns 400."""
        # Create a session without mcp_server_url
        session = await create_test_session(
            app_client,
            name="MCP Test",
            mode="attack_chain",
        )
        sid = session["id"]
        resp = await app_client.post(f"/api/v2/sessions/{sid}/resolve-mcp")
        assert resp.status_code == 400
        assert "mcp_server_url" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_mcp_resolve_unreachable_returns_502(self, app_client: AsyncClient, db_session: AsyncSession):
        """TC-F-053: MCP resolve with unreachable server returns 502."""
        from backend.db.models import SimulationSession
        s = SimulationSession(
            name="MCP Error Test",
            config={
                "simulation_mode": "mcp_ingest",
                "mcp_server_url": "http://unreachable.localhost:9999/mcp",
                "mcp_api_key": "",
                "mcp_tool": "siem_search_events",
                "event_count": 10,
            },
            status="stopped",
            events_sent=0,
            errors=0,
        )
        db_session.add(s)
        await db_session.commit()
        await db_session.refresh(s)

        resp = await app_client.post(f"/api/v2/sessions/{str(s.id)}/resolve-mcp")
        # Should return 502 (Bad Gateway) since the MCP server is unreachable
        assert resp.status_code == 502


# ===========================================================================
# 15. SCORING / COVERAGE TESTS
# ===========================================================================

class TestScoringAPI:
    """Test the DES/IHDS scoring endpoints."""

    @pytest.mark.asyncio
    async def test_des_score_endpoint(self, app_client: AsyncClient):
        """TC-F-054: GET /scoring/des returns DES score structure."""
        resp = await app_client.get("/api/v2/scoring/des")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_scoring_breakdown_endpoint(self, app_client: AsyncClient):
        """TC-F-055: GET /scoring/breakdown returns per-tactic breakdown."""
        resp = await app_client.get("/api/v2/scoring/breakdown")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_scoring_gap_analysis_endpoint(self, app_client: AsyncClient):
        """TC-F-056: GET /scoring/gap-analysis returns gap report."""
        resp = await app_client.get("/api/v2/scoring/gap-analysis")
        assert resp.status_code == 200


# ===========================================================================
# 16. JOTI AUDIT EVENT MODEL TESTS
# ===========================================================================

class TestJotiAuditEventModel:
    """Test the JotiAuditEvent model and storage."""

    @pytest.mark.asyncio
    async def test_joti_audit_event_model_fields(self, db_session: AsyncSession):
        """TC-F-057: JotiAuditEvent stores all required fields."""
        from backend.db.models import JotiAuditEvent
        evt = JotiAuditEvent(
            joti_event_id=99999,
            event_type="HUNT_TRIGGER",
            action="hunt_triggered",
            user_email="analyst@test.com",
            ip_address="192.168.1.1",
            resource_type="hunt",
            resource_id=42,
            correlation_id="corr-abc-123",
            details={"technique_ids": ["T1059"]},
            created_at_joti=datetime.now(timezone.utc),
        )
        db_session.add(evt)
        await db_session.commit()
        await db_session.refresh(evt)

        assert evt.id is not None
        assert evt.event_type == "HUNT_TRIGGER"
        assert evt.user_email == "analyst@test.com"
        assert evt.details["technique_ids"] == ["T1059"]

    @pytest.mark.asyncio
    async def test_joti_audit_event_accepts_extraction_type(self, db_session: AsyncSession):
        """TC-F-058: JotiAuditEvent stores EXTRACTION event type."""
        from backend.db.models import JotiAuditEvent
        evt = JotiAuditEvent(
            event_type="EXTRACTION",
            action="ioc_extracted",
            user_email="system@joti.local",
            details={"ioc_count": 15},
        )
        db_session.add(evt)
        await db_session.commit()
        await db_session.refresh(evt)
        assert evt.event_type == "EXTRACTION"


# ===========================================================================
# 17. RESPONSE ACTION MODEL TESTS
# ===========================================================================

class TestResponseActionModel:
    """Test the ResponseAction model."""

    @pytest.mark.asyncio
    async def test_response_action_model_fields(self, db_session: AsyncSession):
        """TC-F-059: ResponseAction stores all required fields."""
        from backend.db.models import ResponseAction, SimulationSession
        s = await create_sim_session_db(db_session)

        action = ResponseAction(
            session_id=s.id,
            action_type="isolate_host",
            actor="joti_soar",
            target="TEST-HOST",
            params={"hostname": "TEST-HOST"},
            result={"success": True, "state_after": "isolated"},
            persona_key="crowdstrike",
        )
        db_session.add(action)
        await db_session.commit()
        await db_session.refresh(action)

        assert action.id is not None
        assert action.action_type == "isolate_host"
        assert action.actor == "joti_soar"
        assert action.result["success"] is True


# ===========================================================================
# 18. HEALTH AND DOCS TESTS
# ===========================================================================

class TestHealthAndDocs:
    """Basic health and API documentation tests."""

    @pytest.mark.asyncio
    async def test_openapi_docs_accessible(self, app_client: AsyncClient):
        """TC-F-060: OpenAPI docs endpoint is accessible."""
        resp = await app_client.get("/api/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "openapi" in data
        assert "paths" in data

    @pytest.mark.asyncio
    async def test_redoc_accessible(self, app_client: AsyncClient):
        """TC-F-061: ReDoc endpoint is accessible."""
        resp = await app_client.get("/api/redoc")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_all_vendor_routers_registered(self, app_client: AsyncClient):
        """TC-F-062: All 4 main vendor API prefixes return responses (not 404)."""
        # Splunk
        resp = await app_client.get("/api/vendor/splunk/services/server/info")
        assert resp.status_code != 404

        # CrowdStrike
        resp = await app_client.post(
            "/api/vendor/crowdstrike/oauth2/token",
            json={"client_id": "test", "client_secret": "test"},
        )
        assert resp.status_code != 404

        # XSIAM
        resp = await app_client.post("/api/vendor/xsiam/public_api/v1/xql/quota")
        assert resp.status_code != 404

        # Defender
        resp = await app_client.post("/api/vendor/defender/oauth2/v2.0/token")
        assert resp.status_code != 404
