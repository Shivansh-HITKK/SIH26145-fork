from pathlib import Path

from fastapi.testclient import TestClient

from sih_detector.api import ReplayManager, app


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "mode": "read_only_capture_and_replay"}


def test_scenario_endpoint_lists_jsonl_fixtures() -> None:
    client = TestClient(app)
    scenarios = client.get("/api/scenarios").json()["scenarios"]
    assert {"syn_flood", "dns_tunnelling", "beaconing"}.issubset(scenarios)


def test_live_interfaces_endpoint_returns_interface_names() -> None:
    client = TestClient(app)
    response = client.get("/api/live/interfaces")
    assert response.status_code == 200
    assert isinstance(response.json()["interfaces"], list)


def test_metrics_declares_data_provenance() -> None:
    client = TestClient(app)
    metrics = client.get("/api/metrics").json()
    assert metrics["data_provenance"] in {"none", "synthetic_fixture", "authorized_live_metadata"}
    assert set(metrics["capture_stats"]) == {
        "packets_seen",
        "flows_emitted",
        "dropped_packets",
        "error_count",
        "last_error",
    }


def test_unknown_scenario_is_rejected(tmp_path: Path) -> None:
    manager = ReplayManager(tmp_path)
    try:
        manager.start("missing", 1)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Unknown fixture should be rejected")


def test_read_and_control_tokens_have_separate_permissions(monkeypatch) -> None:
    monkeypatch.setenv("DETECTOR_READ_TOKEN", "read-secret")
    monkeypatch.setenv("DETECTOR_CONTROL_TOKEN", "control-secret")
    client = TestClient(app)

    assert client.get("/api/metrics").status_code == 401
    assert client.get("/api/metrics", headers={"Authorization": "Bearer read-secret"}).status_code == 200
    assert client.post(
        "/api/replay/stop", headers={"Authorization": "Bearer read-secret"}
    ).status_code == 403
    assert client.post(
        "/api/replay/start",
        headers={"Authorization": "Bearer control-secret"},
        json={"scenario": "missing", "speed": 1},
    ).status_code == 404
