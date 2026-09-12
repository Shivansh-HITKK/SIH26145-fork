import asyncio
from datetime import datetime, timezone

from sih_detector.explain import check_ollama, generate_explanation, template_explanation
from sih_detector.schemas import Alert, Evidence, Severity, ThreatClass


def sample_alert() -> Alert:
    return Alert(
        alert_id="alert-explain-1",
        timestamp=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
        flow_id="flow-explain",
        threat_class=ThreatClass.DDOS,
        severity=Severity.CRITICAL,
        confidence=0.98,
        source_ip="198.51.100.10",
        destination_ip="10.0.0.10",
        protocol="TCP",
        window_seconds=5,
        evidence=[
            Evidence(feature="packets_per_second", value=1000.0, reason="Rate exceeded threshold"),
            Evidence(feature="syn_ratio", value=1.0, reason="Most events contain SYN flags"),
        ],
        detector="syn_flood_v1",
        model_version="rules-v1",
    )


def test_template_explanation_is_deterministic() -> None:
    first = template_explanation(sample_alert())
    second = template_explanation(sample_alert())
    assert first == second
    assert "ddos" in first
    assert "198.51.100.10" in first
    assert "syn_flood_v1" in first


def test_generate_explanation_falls_back_to_template(monkeypatch) -> None:
    class FailingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, *args, **kwargs):
            raise OSError("ollama unreachable")

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FailingClient)
    result = None

    async def run() -> None:
        nonlocal result
        result = await generate_explanation(sample_alert(), timeout_seconds=0.1)

    asyncio.run(run())
    assert result is not None
    assert result.source == "template"
    assert result.explanation.startswith("This ddos alert")


def test_check_ollama_returns_false_when_unreachable(monkeypatch) -> None:
    class FailingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def get(self, *args, **kwargs):
            raise OSError("unreachable")

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", FailingClient)
    assert asyncio.run(check_ollama(timeout_seconds=0.1)) is False


def test_check_ollama_requires_configured_model(monkeypatch) -> None:
    class EmptyTagsClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def get(self, *args, **kwargs):
            class Response:
                status_code = 200

                def json(self):
                    return {"models": []}

            return Response()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", EmptyTagsClient)
    assert asyncio.run(check_ollama(model="qwen2.5:3b-instruct")) is False


def test_generate_explanation_uses_ollama_response(monkeypatch) -> None:
    class WorkingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, *args, **kwargs):
            class Response:
                def raise_for_status(self) -> None:
                    return None

                def json(self):
                    return {"response": "The traffic shows a high-confidence SYN flood."}

            return Response()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", WorkingClient)
    result = asyncio.run(generate_explanation(sample_alert(), timeout_seconds=0.1))
    assert result.source == "ollama"
    assert result.explanation == "The traffic shows a high-confidence SYN flood."
