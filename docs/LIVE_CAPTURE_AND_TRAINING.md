# Live Capture and Real-Data Training

The detector can consume passive packet metadata from an authorized local interface. It does not send probes, complete handshakes, store payloads, or decrypt TLS/QUIC.

## Install optional dependencies

```bash
python -m pip install -e 'backend[live,ml]'
```

Live capture usually requires packet-capture privileges. Only capture interfaces and traffic you are authorized to monitor.
For a native Linux run, grant the process the required packet-capture capability
or run it in an authorized capture environment. The default Docker Compose demo
is intentionally not attached to the host network; use a separate deployment
with explicit `CAP_NET_RAW`/libpcap access and an approved interface when live
capture is required.

## Capture live metadata

Run the CLI from the repository root:

```bash
PYTHONPATH=backend/src python -m sih_detector.cli \
  --live \
  --interface eth0 \
  --capture-output data/live-events.jsonl
```

`--interface` may be omitted to use the platform default. A BPF filter can limit collection:

```bash
PYTHONPATH=backend/src python -m sih_detector.cli \
  --live --interface eth0 --bpf-filter 'tcp or udp' \
  --capture-output data/live-events.jsonl
```

The output is normalized `FlowEvent` JSONL containing timestamp, addresses, ports, protocol, packet length, TCP flags, DNS metadata, and inferred direction. Payload bytes are not written.

The dashboard labels this source as `AUTHORIZED LIVE DATA`. It must not be
reported as a real incident unless the interface is authorized and the
capture has been reviewed. Fixture replay is labelled `SYNTHETIC FIXTURE`.

Live metadata coverage is not identical to fixture coverage: DNS, rate,
fan-out, timing, byte-ratio, and TCP-completion detectors can operate from
normalized packets; encrypted-session anomaly detection requires TLS/QUIC
metadata extraction (fingerprints, versions, and packet-size sequences) that
must be validated on the target capture environment before claiming coverage.

## Train from unlabeled live traffic

Unlabeled traffic cannot train a supervised threat-class classifier honestly. It can train a benign/anomaly baseline when the capture is known to represent a clean period:

```bash
PYTHONPATH=backend/src python -m sih_detector.cli \
  --train-baseline data/live-events.jsonl \
  --model-dir models
```

This writes an Isolation Forest baseline and a `ml-baseline-v1` model metadata file. Rule detections remain the authoritative threat class; the baseline contributes anomaly evidence and confidence only.

Do not use a capture containing an incident as the benign baseline.

## Bootstrap when no dataset exists

For development only, the repository can materialize its existing labeled
scenario generators as a JSONL dataset and train from it:

```bash
PYTHONPATH=backend/src python -m sih_detector.cli \
  --build-bootstrap-dataset data/bootstrap-labeled-windows.jsonl \
  --per-class 50

PYTHONPATH=backend/src python -m sih_detector.cli \
  --train-labeled data/bootstrap-labeled-windows.jsonl \
  --model-dir models
```

This is useful for verifying the serving path, but it remains synthetic
bootstrap data and must not be presented as real-world model validation.

## Train a supervised model from labeled real observations

### Where to get public labeled data

Good starting points are public network-flow datasets that already contain
labels and CICFlowMeter-style columns:

- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CSE-CIC-IDS2018: https://www.unb.ca/cic/datasets/ids-2018.html
- UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset

Download the CSV files manually from the dataset publisher, keep them outside
Git, and verify their license and permitted use before training. Then import a
CICFlowMeter/CICIDS-style CSV:

```bash
PYTHONPATH=backend/src python -m sih_detector.cli \
  --import-flow-csv /path/to/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
  --flow-output data/public-labeled-windows.jsonl \
  --flow-window-size 32
```

The importer reports mapped labels, generated windows, and skipped unknown
labels. Review that report before training. Public dataset labels do not map
perfectly to this project's taxonomy; the mapping is intentionally explicit in
`backend/src/sih_detector/flow_dataset.py`.

For threat-class classification, provide operator-labeled windows in JSONL. Each line must have this shape:

```json
{"label":"benign","capture_id":"capture-2026-09-09-a","events":[{"timestamp":"2026-09-09T10:00:00Z","flow_id":"f-1","source_ip":"10.0.0.5","destination_ip":"1.1.1.1","source_port":42000,"destination_port":443,"protocol":"TCP","packets":4,"bytes":512,"direction":"outbound","connection_completed":true}]}
```

Supported labels are `benign`, `ddos`, `port_scanning`, `dns_tunnelling`, `dga`, `botnet_beaconing`, `encrypted_session_anomaly`, `data_exfiltration`, `udp_amplification`, and `slowloris`. Include multiple independent windows per class, including benign windows.

Train and evaluate with a held-out stratified split:

```bash
PYTHONPATH=backend/src python -m sih_detector.cli \
  --train-labeled data/labeled-real-windows.jsonl \
  --model-dir models
```

The command writes `threat_classifier.joblib`, `anomaly_detector.joblib`, and `model_meta.json` with version `ml-real-v1`. Include the same `capture_id` on every window from one independent capture. When capture IDs are present, evaluation holds out complete capture groups so windows from one capture cannot appear in both training and evaluation. Older inputs without capture IDs use a contiguous per-class holdout. The metadata records the input SHA-256, feature schema version, row/event counts, label counts, group count, and evaluation method. The reported accuracy is only valid for the labeled capture distribution; it is not a universal production accuracy claim.

## Run the API in live mode

Start the backend and dashboard as usual, then use the dashboard's **LIVE INTERFACE** field and **Start live capture** control. The equivalent API request is:

```bash
curl -X POST http://127.0.0.1:8000/api/live/start \
  -H 'Content-Type: application/json' \
  -d '{"interface":"eth0","bpf_filter":"ip or ip6"}'
```

The dashboard discovers locally visible interfaces through
`GET /api/live/interfaces` and sends both the selected interface and BPF filter
to `POST /api/live/start`. Capture counters (`packets_seen`, `flows_emitted`,
`dropped_packets`, and capture errors) are exposed in `/api/metrics` and the
dashboard status strip. The dashboard receives live alerts through
`WS /ws/alerts`. Stop capture with:

```bash
curl -X POST http://127.0.0.1:8000/api/replay/stop
```

The API metrics identify the source with `source_mode: "live"` and expose the selected interface. A live capture and fixture replay cannot run at the same time.

## Production validation checklist

- Collect representative traffic from an authorized environment.
- Label windows with independent analyst or incident evidence.
- Keep time-separated train, validation, and test captures.
- Measure precision, recall, false-positive rate, and detection latency by environment.
- Retrain when protocols, applications, or network baselines change.
- Keep raw packet captures outside the application unless retention is explicitly approved.

## Real-data acceptance gate

Before replacing the demo model artifacts, record these values for each
environment and time-split holdout:

- rows imported, rows skipped, windows written, and labels by class;
- train/validation/test time ranges with no overlapping flow IDs;
- per-class precision, recall, F1, support, and false-positive rate;
- p50/p95 detection latency and sustained event rate;
- the exact importer mapping, feature version, model version, and command;
- whether the capture contains encrypted metadata only and no payload bytes.

Do not publish a model or metric table if a class has no independent holdout,
if labels were inferred from the same rule output being evaluated, or if the
capture is not authorized. Keep downloaded public datasets and live captures
outside Git; only commit reproducible commands and aggregate reports.
