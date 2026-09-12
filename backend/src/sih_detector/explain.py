"""Optional local LLM explanation layer (Ollama).

The detection result is always authoritative. This module only turns an
already-generated structured alert into a short analyst-friendly paragraph.
It never inspects raw payloads, never changes the classification, and the
dashboard shows a deterministic template when Ollama is unavailable.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

from .schemas import Alert

DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b-instruct")
DEFAULT_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "45"))

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst writing short incident explanations for a "
    "security operations dashboard. Use only the structured alert provided. "
    "Explain what happened, which evidence is most significant, and one concrete "
    "investigation step. Keep it under 90 words, plain language, no markdown."
)


def _sanitize_alert(alert: Alert) -> dict[str, Any]:
    """Build the minimal structured input for the model; no payloads or credentials."""
    return {
        "threat_class": alert.threat_class,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "protocol": alert.protocol,
        "detector": alert.detector,
        "evidence": [
            {"feature": item.feature, "value": item.value, "reason": item.reason}
            for item in alert.evidence
        ],
    }


def template_explanation(alert: Alert) -> str:
    """Deterministic fallback used when Ollama is unavailable or times out."""
    top = alert.evidence[0] if alert.evidence else None
    detail = f" The strongest signal is {top.feature} ({top.value})." if top else ""
    return (
        f"This {alert.threat_class.replace('_', ' ')} alert from {alert.source_ip} to "
        f"{alert.destination_ip} ({alert.protocol}) was raised by the {alert.detector} "
        f"detector with {round(alert.confidence * 100)}% confidence.{detail} "
        "Review the supporting evidence and investigate the source host."
    )


@dataclass(frozen=True)
class ExplanationResult:
    explanation: str
    source: str  # "ollama" | "template"


async def generate_explanation(
    alert: Alert,
    *,
    url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> ExplanationResult:
    """Request an explanation from a local Ollama instance, falling back to a template."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(
                f"{url}/api/generate",
                json={
                    "model": model,
                    "prompt": (
                        f"{SYSTEM_PROMPT}\n\n"
                        f"Alert JSON:\n{_sanitize_alert(alert)!s}\n\nExplanation:"
                    ),
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": 160},
                },
            )
            response.raise_for_status()
            payload = response.json()
            explanation = str(payload.get("response", "")).strip()
            if explanation:
                return ExplanationResult(explanation=explanation, source="ollama")
    except Exception:
        pass
    return ExplanationResult(explanation=template_explanation(alert), source="template")


async def check_ollama(
    *,
    url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
    timeout_seconds: float = 2.0,
) -> bool:
    """Check reachability and verify that the configured model is installed."""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(f"{url}/api/tags")
            if response.status_code != 200:
                return False
            payload = response.json()
            models = payload.get("models", [])
            return any(str(item.get("name", "")) in {model, f"{model}:latest"} for item in models)
    except Exception:
        return False


async def run_explainer_loop(
    queue: asyncio.Queue[Alert],
    on_result: Any,
    *,
    url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
) -> None:
    """Consume alerts from the queue and publish explanations as they complete."""
    while True:
        alert = await queue.get()
        try:
            result = await generate_explanation(alert, url=url, model=model)
            await on_result(alert.alert_id, result)
        except Exception:
            continue
