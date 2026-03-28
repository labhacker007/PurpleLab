"""Integration test for full session lifecycle: create -> start -> events -> stop."""
import pytest


class TestSessionLifecycle:
    """End-to-end test of the session lifecycle through the API."""

    SESSION_PAYLOAD = {
        "name": "Lifecycle Integration Test",
        "products": [
            {
                "product_type": "splunk",
                "label": "Splunk SIEM",
                "config": {
                    "product_type": "splunk",
                    "target_url": "http://httpbin.org/post",
                    "webhook_token": "test-token",
                    "events_per_minute": 2.0,
                    "severity_weights": {"critical": 0.05, "high": 0.2, "medium": 0.5, "low": 0.25},
                    "enabled": True,
                },
            },
            {
                "product_type": "crowdstrike",
                "label": "CrowdStrike EDR",
                "config": {
                    "product_type": "crowdstrike",
                    "target_url": "http://httpbin.org/post",
                    "webhook_token": "test-token",
                    "events_per_minute": 1.0,
                    "severity_weights": {"critical": 0.1, "high": 0.3, "medium": 0.4, "low": 0.2},
                    "enabled": True,
                },
            },
        ],
        "targets": [
            {
                "label": "Test Joti",
                "base_url": "http://localhost:9999",
                "webhook_path": "/api/alerts/ingest/{token}",
            }
        ],
    }

    def test_full_lifecycle(self, client):
        # 1. Create session
        resp = client.post("/api/sessions", json=self.SESSION_PAYLOAD)
        assert resp.status_code == 200
        session = resp.json()
        session_id = session["session_id"]
        assert session["name"] == "Lifecycle Integration Test"
        assert len(session["products"]) == 2
        assert len(session["targets"]) == 1

        # 2. Verify it shows in list
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        sessions = resp.json()["sessions"]
        assert any(s["session_id"] == session_id for s in sessions)

        # 3. Start session
        resp = client.post(f"/api/sessions/{session_id}/start")
        assert resp.status_code == 200
        assert resp.json()["status"] == "started"

        # 4. Verify running state
        resp = client.get(f"/api/sessions/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["running"] is True

        # 5. Check events endpoint works (may be empty since events are async)
        resp = client.get(f"/api/sessions/{session_id}/events?limit=10")
        assert resp.status_code == 200
        assert "events" in resp.json()

        # 6. Stop session
        resp = client.post(f"/api/sessions/{session_id}/stop")
        assert resp.status_code == 200
        assert resp.json()["status"] == "stopped"

        # 7. Verify stopped state
        resp = client.get(f"/api/sessions/{session_id}")
        assert resp.status_code == 200
        assert resp.json()["running"] is False

        # 8. Delete session
        resp = client.delete(f"/api/sessions/{session_id}")
        assert resp.status_code == 200

        # 9. Verify deleted
        resp = client.get(f"/api/sessions/{session_id}")
        assert resp.status_code == 404

    def test_multiple_sessions_lifecycle(self, client):
        """Create two sessions, start both, stop one, verify independence."""
        ids = []
        for i in range(2):
            payload = {
                "name": f"Multi-session {i}",
                "products": [{
                    "product_type": "splunk",
                    "label": "Splunk",
                    "config": {
                        "product_type": "splunk",
                        "target_url": "http://test",
                        "events_per_minute": 1.0,
                        "severity_weights": {"critical": 0.05, "high": 0.2, "medium": 0.5, "low": 0.25},
                        "enabled": True,
                    },
                }],
                "targets": [{"label": "Target", "base_url": "http://localhost:9999"}],
            }
            resp = client.post("/api/sessions", json=payload)
            ids.append(resp.json()["session_id"])

        # Start both
        for sid in ids:
            client.post(f"/api/sessions/{sid}/start")

        # Stop first
        client.post(f"/api/sessions/{ids[0]}/stop")

        # Verify first stopped, second still running
        resp = client.get(f"/api/sessions/{ids[0]}")
        assert resp.json()["running"] is False

        resp = client.get(f"/api/sessions/{ids[1]}")
        assert resp.json()["running"] is True

        # Cleanup
        for sid in ids:
            client.post(f"/api/sessions/{sid}/stop")
            client.delete(f"/api/sessions/{sid}")
