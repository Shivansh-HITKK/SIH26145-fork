# Security constraints

## Passive-only operation

The detection engine must accept observed data but never communicate with the observed sources or destinations. There must be no probe, handshake completion, response packet, mitigation command, or inline blocking feature.

## No decryption

TLS and QUIC analysis uses metadata only, such as version, fingerprint, packet sizes, directions, timing, and flow behavior. Payloads are not decrypted or stored.

## Safe test traffic

Use fixture generation and isolated lab tools only. Do not target public hosts, campus infrastructure, production systems, or devices without authorization. Do not execute real malware.

## Application isolation

Appwrite, FastAPI, the dashboard, and the optional Ollama service belong to the application/control plane. They must not have a route into the simulated observed network. For the demo, keep all traffic sources local and controlled.

## Data minimization

Store derived metadata and alert evidence rather than raw payloads. Keep secrets in environment variables. Do not commit Appwrite credentials, model secrets, or private datasets.

## LLM boundary

The optional local LLM receives sanitized structured alerts only. It cannot change alert class, severity, confidence, or detector state. Generated text is advisory and must be labeled as an explanation.

## Authentication and authorization

FastAPI supports optional bearer-token authorization for the local control plane.
Keep `DETECTOR_CONTROL_TOKEN` server-side and use it only for trusted local
operators; it can start/stop replay and live capture. `DETECTOR_READ_TOKEN`
protects metrics, interfaces, alerts, incidents, and explanations. A control
token also grants read access. Health remains public, and when neither token is
configured the local development API remains open.

The current browser dashboard can send `NEXT_PUBLIC_DETECTOR_API_TOKEN` for a
single-user/local deployment. Do not expose a control token in a public or
multi-user browser bundle. For production, place the dashboard behind a
server-side proxy or session-aware gateway that keeps control credentials out
of client JavaScript, and map authenticated user roles to read/control access.

## Auditability

Record detector version, model version, replay scenario, timestamps, and benchmark settings so each result can be reproduced and explained.
