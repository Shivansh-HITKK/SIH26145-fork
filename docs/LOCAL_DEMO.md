# Local SIH demo

## What runs locally

```text
JSONL fixtures
     ↓
FastAPI replay manager
     ↓
Python read-only detectors
     ↓
WebSocket alert stream
     ↓
Next.js dashboard
```

Appwrite is optional. When configured, the API persists alerts to an Appwrite collection. The Next.js dashboard receives active alerts from the FastAPI WebSocket and shows Appwrite persistence status from `/api/metrics`; the local demo does not depend on Appwrite.

## Start with local processes

From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e 'backend[test]'
uvicorn sih_detector.api:app --app-dir backend/src --reload
```

In a second terminal:

```bash
cd frontend1
npm install
npm run dev
```

Open `http://localhost:5173`.

## Start with Docker Compose

```bash
docker compose up
```

Open `http://localhost:5173`.
The first startup downloads `qwen2.5:3b-instruct` into the persistent Ollama
volume; later starts reuse that model. Set `OLLAMA_MODEL` before startup to use
a different Ollama model.

## Demonstration flow

1. Open the dashboard.
2. Confirm the `Realtime connected` indicator (and the `Appwrite connected` chip when Appwrite is configured).
3. Select `syn_flood`, `port_scanning`, `dns_tunnelling`, `dga`, `beaconing`, `encrypted_session`, `exfiltration`, `udp_amplification`, or `slowloris`.
4. Choose a replay speed.
5. Start replay.
6. Watch event metrics and alerts update.
7. Select an alert row to inspect evidence.
8. Stop the replay if needed.
9. If trained, point out the active `ml-v1` model status and the `ml_prediction`/`ml_anomaly_score` evidence on an alert.
10. If Ollama is running, open an alert and watch the analyst explanation stream in.
11. Explain that the input is a simulated one-way stream and the detector never sends a response.

## API endpoints

- `GET /api/health`
- `GET /api/scenarios`
- `GET /api/live/interfaces`
- `GET /api/metrics`
- `GET /api/alerts?limit=100`
- `POST /api/replay/start`
- `POST /api/replay/stop`
- `WS /ws/alerts`

## Optional local ML models

The dashboard runs in rules-only mode without any setup. To enable model scoring:

```bash
python -m pip install -e 'backend[ml]'
PYTHONPATH=backend/src python3 -m sih_detector.cli --train --per-class 250
```

Restart the API; the metrics endpoint reports `model_status.available: true`, alerts gain `ml_prediction` and `ml_anomaly_score` evidence, and the dashboard note updates to show the active model version.

## Optional Appwrite persistence and realtime

Install the optional backend SDK and set the values in `.env`:

```bash
python -m pip install -e 'backend[appwrite]'
```

Backend values (persist alerts from the detection API):

```text
APPWRITE_ENDPOINT
APPWRITE_PROJECT_ID
APPWRITE_DATABASE_ID
APPWRITE_ALERTS_COLLECTION_ID
APPWRITE_API_KEY
```

Frontend values (Next.js dashboard and Auth.js):

```text
NEXT_PUBLIC_API_BASE_URL
AUTH_SECRET
AUTH_URL
AUTH_GOOGLE_ID
AUTH_GOOGLE_SECRET
```

Create an alerts collection whose attributes can accept the JSON fields in [the alert schema](ALERT_SCHEMA.md). Alerts are created with `document_id = alert_id`, so `$id` matches the alert. Keep Appwrite outside the simulated observed network path.

When Appwrite is enabled:

- `/api/metrics` reports `appwrite_status` with `enabled` and `persisted_count`.
- The dashboard shows whether Appwrite persistence is enabled; active alerts continue through the FastAPI WebSocket.
- Persistence failures are counted in `error_count` and shown as a banner; detection continues.

For collection attributes, permissions, and the server API key scope, see
[Appwrite deployment](APPWRITE_DEPLOYMENT.md).

## Optional local LLM explanations (Ollama)

Detection remains local and deterministic. Ollama only turns an already-generated structured alert into a short analyst paragraph.

```bash
# Docker Compose downloads the configured model automatically.
docker compose up
```

Compose uses `http://ollama:11434`; a host-installed Ollama should use
`http://127.0.0.1:11434`. Override with `OLLAMA_URL`, `OLLAMA_MODEL`, and
`OLLAMA_TIMEOUT_SECONDS` in `.env`.

Behavior:

- Alerts are broadcast immediately; explanations arrive asynchronously over the same WebSocket as `explained` messages and update the drawer in place.
- The drawer shows a spinner while an explanation is pending and a deterministic template whenever Ollama is unreachable or times out.
- `GET /api/explain/{alert_id}` generates an explanation on demand.
- The model receives only the sanitized structured alert (class, severity, confidence, hosts, protocol, evidence). No payloads, credentials, or instructions to take network actions.

It is not required to run detection or the demo.

## Verified end-to-end

An automated check exercises the full local demo against a live API and WebSocket stream:

- Health, scenario discovery, and status fields (`model_status`, `appwrite_status`, `ollama_status`).
- All nine fixtures replay and stream their expected threat class with valid evidence/confidence contracts.
- Concurrent replay starts are rejected (409) while a replay is running; unknown scenarios are rejected (404).
- `/api/explain/{alert_id}` returns a template explanation when Ollama is offline.
- The Vite dev proxy serves the dashboard and forwards `/api` and `/ws` to the API.
- The dashboard builds successfully and renders in a browser with the realtime indicator connected.

Note: starting a replay clears the previously stored alert buffer (the buffer holds the current replay's alerts), which is expected behavior.

## Troubleshooting

- `Connection refused`: start the FastAPI process on port 8000.
- No scenarios: run from the repository root so `data/fixtures` is found.
- Realtime disconnected: confirm the Next.js dev server is running and the API WebSocket endpoint is available.
- Appwrite errors: unset the Appwrite variables to use local-only mode, or check `APPWRITE_API_KEY`/collection permissions and confirm the collection attributes match the alert schema.
