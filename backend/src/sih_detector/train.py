"""Train the optional local scikit-learn models on labeled observation windows.

The built-in generator remains available for deterministic tests and demos.
Production-style training accepts operator-labeled real observation windows;
all features are still computed from metadata-only ``FlowEvent`` records.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .features import extract_window_features
from .model import CLASS_LABELS, FEATURE_NAMES, DEFAULT_MODEL_DIR
from .replay import read_events
from .schemas import FlowEvent


def _event(
    index: int,
    base: datetime,
    *,
    source_ip: str,
    destination_ip: str,
    destination_port: int,
    protocol: str = "TCP",
    packets: int = 1,
    bytes_sent: int = 64,
    direction: str = "outbound",
    syn: bool = False,
    completed: bool | None = None,
    dns_query: str | None = None,
    dns_record_type: str | None = None,
    tls_fingerprint: str | None = None,
    tls_version: str | None = None,
    tls_packet_sizes: list[int] | None = None,
) -> FlowEvent:
    return FlowEvent(
        timestamp=base + timedelta(seconds=index),
        flow_id=f"syn-{index:04d}",
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=40000 + index,
        destination_port=destination_port,
        protocol=protocol,
        packets=packets,
        bytes=bytes_sent,
        direction=direction,  # type: ignore[arg-type]
        tcp_flags=["SYN"] if syn else [],
        connection_completed=completed,
        dns_query=dns_query,
        dns_record_type=dns_record_type,
        tls_fingerprint=tls_fingerprint,
        tls_version=tls_version,
        tls_packet_sizes=tls_packet_sizes or [],
    )


LABEL_POOL = "abcdefghijklmnopqrstuvwxyz0123456789"


def _random_label(rng: random.Random, length: int) -> str:
    return "".join(rng.choice(LABEL_POOL) for _ in range(length))


def _sample_benign(rng: random.Random, base: datetime) -> list[FlowEvent]:
    events: list[FlowEvent] = []
    for index in range(10):
        port = rng.choice([443, 80, 53])
        # Realistic contamination: some benign windows contain lookalike signals
        # (long unique subdomains, several distinct ports) so classes are not
        # trivially separable and precision/recall are meaningful.
        dns_query = "www.example.test"
        if rng.random() < 0.15:
            dns_query = f"{_random_label(rng, 26)}.cdn.example.test"
        events.append(
            _event(
                index,
                base,
                source_ip="10.0.0.8",
                destination_ip="203.0.113.10",
                destination_port=port if rng.random() > 0.2 else rng.randint(1024, 65535),
                packets=rng.randint(1, 3),
                bytes_sent=rng.randint(64, 512),
                completed=True,
                dns_query=dns_query if port == 53 else None,
                tls_fingerprint="ja3-common-a" if rng.random() < 0.4 else None,
                tls_version="TLS1.3" if rng.random() < 0.4 else None,
            )
        )
    return events


def _sample_ddos(rng: random.Random, base: datetime) -> list[FlowEvent]:
    events: list[FlowEvent] = []
    for index in range(10):
        events.append(
            _event(
                index,
                base,
                source_ip=f"198.51.100.{rng.randint(2, 254)}",
                destination_ip="10.0.0.10",
                destination_port=80,
                packets=rng.randint(5, 25),
                bytes_sent=rng.randint(40, 80),
                syn=True,
                completed=rng.random() < 0.1,  # a few completions add realism
            )
        )
    return events


def _sample_port_scan(rng: random.Random, base: datetime) -> list[FlowEvent]:
    return [
        _event(
            index,
            base,
            source_ip="10.0.0.91",
            destination_ip="10.0.0.53",
            destination_port=rng.randint(1, 1024),
            completed=rng.random() < 0.2,  # occasional successes
        )
        for index in range(10)
    ]


def _sample_dns_tunnelling(rng: random.Random, base: datetime) -> list[FlowEvent]:
    events: list[FlowEvent] = []
    for index in range(10):
        label = _random_label(rng, rng.randint(28, 42))
        if rng.random() < 0.2:  # some queries use shorter, less extreme labels
            label = _random_label(rng, rng.randint(12, 18))
        events.append(
            _event(
                index,
                base,
                source_ip="10.0.0.21",
                destination_ip="8.8.8.8",
                destination_port=53,
                protocol="UDP",
                dns_query=f"{label}.tunnel.example.test",
                dns_record_type="TXT",
            )
        )
    return events


def _sample_dga(rng: random.Random, base: datetime) -> list[FlowEvent]:
    events: list[FlowEvent] = []
    for index in range(10):
        label = _random_label(rng, rng.randint(12, 22))
        if rng.random() < 0.2:  # some dictionary-like labels for confusion
            label = rng.choice(["login", "update", "verify", "secure", "account", "status"])
        events.append(
            _event(
                index,
                base,
                source_ip="10.0.0.21",
                destination_ip="8.8.8.8",
                destination_port=53,
                protocol="UDP",
                dns_query=f"{label}.example.test",
                dns_record_type="A",
            )
        )
    return events


def _sample_beaconing(rng: random.Random, base: datetime) -> list[FlowEvent]:
    interval = rng.choice([20, 30, 45, 60])
    events: list[FlowEvent] = []
    for index in range(8):
        # jitter makes periodicity imperfect like a real C2 channel
        jitter = rng.uniform(0.8, 1.2)
        events.append(
            _event(
                index,
                base + timedelta(seconds=index * interval * jitter),
                source_ip="10.0.0.31",
                destination_ip="203.0.113.44",
                destination_port=443,
                packets=rng.randint(1, 2),
                bytes_sent=64,
                completed=True,
            )
        )
    return events


def _sample_encrypted(rng: random.Random, base: datetime) -> list[FlowEvent]:
    events: list[FlowEvent] = []
    for index in range(8):
        events.append(
            _event(
                index,
                base,
                source_ip="10.0.0.41",
                destination_ip="203.0.113.77",
                destination_port=443,
                completed=True,
                tls_fingerprint=f"ja4-rare-{rng.randint(100, 999)}",
                tls_version=rng.choice(["TLS1.0", "TLS1.1", "TLS1.3"]),
                tls_packet_sizes=[64, 64, 128, 64, 64],
            )
        )
    return events


def _sample_exfiltration(rng: random.Random, base: datetime) -> list[FlowEvent]:
    events: list[FlowEvent] = []
    for index in range(10):
        events.append(
            _event(
                index,
                base,
                source_ip="10.0.0.61",
                destination_ip="203.0.113.88",
                destination_port=443,
                packets=rng.randint(8, 20),
                bytes_sent=rng.randint(80_000, 200_000),
                completed=True,
                tls_fingerprint="ja3-common-b",
                tls_version="TLS1.3",
            )
        )
    return events


def _sample_udp_amplification(rng: random.Random, base: datetime) -> list[FlowEvent]:
    return [
        _event(
            index,
            base + timedelta(seconds=index * 0.1),
            source_ip=f"198.51.100.{rng.randint(2, 254)}",
            destination_ip="10.0.0.53",
            destination_port=53,
            protocol="UDP",
            packets=rng.randint(40, 60),
            bytes_sent=rng.randint(2500, 3500),
        )
        for index in range(12)
    ]


def _sample_slowloris(rng: random.Random, base: datetime) -> list[FlowEvent]:
    return [
        _event(
            index,
            base + timedelta(seconds=index * 3),
            source_ip="10.0.0.81",
            destination_ip="10.0.0.10",
            destination_port=80,
            protocol="TCP",
            packets=2,
            bytes_sent=128,
            completed=False,
        )
        for index in range(10)
    ]


SAMPLE_GENERATORS = {
    "benign": _sample_benign,
    "ddos": _sample_ddos,
    "port_scanning": _sample_port_scan,
    "dns_tunnelling": _sample_dns_tunnelling,
    "dga": _sample_dga,
    "botnet_beaconing": _sample_beaconing,
    "encrypted_session_anomaly": _sample_encrypted,
    "data_exfiltration": _sample_exfiltration,
    "udp_amplification": _sample_udp_amplification,
    "slowloris": _sample_slowloris,
}

FIXTURE_LABELS = {
    "syn_flood": "ddos",
    "port_scanning": "port_scanning",
    "dns_tunnelling": "dns_tunnelling",
    "dga": "dga",
    "beaconing": "botnet_beaconing",
    "encrypted_session": "encrypted_session_anomaly",
    "exfiltration": "data_exfiltration",
    "udp_amplification": "udp_amplification",
    "slowloris": "slowloris",
}


FEATURE_SCHEMA_VERSION = "window-features-v1"


def _file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_bootstrap_dataset(output_path: str | Path, per_class: int = 50, seed: int = 42) -> dict[str, object]:
    """Write a labeled bootstrap dataset from the deterministic scenario generators.

    This is a development fallback for environments without authorized real
    captures. It is deliberately marked as fixture data in the output metadata.
    """
    rng = random.Random(seed)
    base = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
    rows: list[str] = []
    for label, generator in SAMPLE_GENERATORS.items():
        for index in range(per_class):
            events = generator(rng, base + timedelta(minutes=index))
            row = {"label": label, "events": [event.model_dump(mode="json") for event in events]}
            rows.append(json.dumps(row))
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return {
        "output_path": str(output),
        "windows": len(rows),
        "source": "fixture_bootstrap",
        "sha256": _file_sha256(output),
    }


def generate_dataset(per_class: int = 200, seed: int = 42) -> tuple[list[list[float]], list[str]]:
    """Generate labeled feature vectors; one sample per synthetic window."""
    rng = random.Random(seed)
    base = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
    vectors: list[list[float]] = []
    labels: list[str] = []
    for label, generator in SAMPLE_GENERATORS.items():
        for _ in range(per_class):
            events = generator(rng, base)
            features = extract_window_features(events, window_seconds=5.0)
            vectors.append([float(features.model_dump()[name]) for name in FEATURE_NAMES])
            labels.append(label)
    return vectors, labels


def train_and_save(
    output_dir: str | Path = DEFAULT_MODEL_DIR,
    per_class: int = 200,
    seed: int = 42,
    eval_seed: int | None = None,
    eval_per_class: int | None = None,
) -> dict[str, object]:
    """Train classifier and anomaly detector, save artifacts, and return metrics.

    Evaluation is scenario-separated: the evaluation set is generated with a
    different random seed (``eval_seed``) than the training set, so the model
    is measured against windows it never saw during training. No train/test
    split of the same generated windows is used.
    """
    try:
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        from sklearn.metrics import (
            accuracy_score,
            classification_report,
            precision_recall_fscore_support,
        )
    except ImportError as exc:
        raise RuntimeError(
            "scikit-learn is not installed. Install it with: python -m pip install -e 'backend[ml]'"
        ) from exc

    if eval_seed is None:
        eval_seed = seed + 1000  # disjoint scenario family by default
    if eval_per_class is None:
        eval_per_class = per_class

    train_vectors, train_labels = generate_dataset(per_class=per_class, seed=seed)
    eval_vectors, eval_labels = generate_dataset(per_class=eval_per_class, seed=eval_seed)

    # n_jobs=1 keeps inference single-process: multiprocessing pools would be
    # spawned and torn down on every single-event prediction, dominating latency.
    # Tree counts are sized for fast per-alert inference on a laptop.
    classifier = RandomForestClassifier(n_estimators=40, max_depth=12, random_state=seed, n_jobs=1)
    classifier.fit(train_vectors, train_labels)
    predictions = classifier.predict(eval_vectors)
    accuracy = float(accuracy_score(eval_labels, predictions))
    report = classification_report(eval_labels, predictions, zero_division=0)

    labels = sorted(set(eval_labels))
    precision, recall, f1, _support = precision_recall_fscore_support(
        eval_labels, predictions, labels=labels, zero_division=0
    )
    per_class_metrics = {
        label: {
            "precision": round(float(precision[index]), 4),
            "recall": round(float(recall[index]), 4),
            "f1": round(float(f1[index]), 4),
        }
        for index, label in enumerate(labels)
    }

    benign_indices = [index for index, label in enumerate(train_labels) if label == "benign"]
    benign_vectors = [train_vectors[index] for index in benign_indices]
    anomaly_detector = IsolationForest(n_estimators=40, contamination=0.05, random_state=seed, n_jobs=1)
    anomaly_detector.fit(benign_vectors)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(classifier, output_dir / "threat_classifier.joblib")
    joblib.dump(anomaly_detector, output_dir / "anomaly_detector.joblib")
    meta = {
        "version": "ml-v1",
        "class_labels": CLASS_LABELS,
        "feature_names": FEATURE_NAMES,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "training_source": "synthetic_generator",
        "training_mode": "synthetic_scenario_separated",
        "dataset_sha256": None,
        "dataset_rows": per_class * len(CLASS_LABELS),
        "samples_per_class": per_class,
        "eval_samples_per_class": eval_per_class,
        "seed": seed,
        "eval_seed": eval_seed,
        "eval_accuracy": round(accuracy, 4),
        "per_class_metrics": per_class_metrics,
    }
    (output_dir / "model_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    return {
        "output_dir": str(output_dir),
        "accuracy": round(accuracy, 4),
        "classification_report": report,
        "per_class_metrics": per_class_metrics,
        "trained_on": per_class * len(CLASS_LABELS),
        "evaluated_on": eval_per_class * len(CLASS_LABELS),
        "eval_seed": eval_seed,
        "version": meta["version"],
    }


def _load_labeled_windows(path: str | Path) -> tuple[list[list[float]], list[str], dict[str, object]]:
    """Load real labeled windows from JSONL without accepting raw payloads.

    Each line must contain ``{"label": "...", "events": [{...}]}``, where
    each event follows the normalized FlowEvent schema.
    """
    vectors: list[list[float]] = []
    labels: list[str] = []
    groups: list[str] = []
    event_count = 0
    label_counts: Counter[str] = Counter()
    explicit_groups = False
    allowed = set(SAMPLE_GENERATORS)
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                label = str(row["label"])
                events = [FlowEvent.model_validate(item) for item in row["events"]]
                group_value = row.get("capture_id") or row.get("source_capture")
                group = str(group_value) if group_value else f"row:{line_number}"
                explicit_groups = explicit_groups or bool(group_value)
                if label not in allowed or not events:
                    raise ValueError("label must be a supported class and events must be non-empty")
            except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid labeled window at {path}:{line_number}: {exc}") from exc
            features = extract_window_features(events, window_seconds=30.0)
            vectors.append([float(features.model_dump()[name]) for name in FEATURE_NAMES])
            labels.append(label)
            groups.append(group)
            event_count += len(events)
            label_counts[label] += 1
    if len(set(labels)) < 2:
        raise ValueError("At least two labeled classes are required for supervised training")
    return vectors, labels, {
        "rows": len(labels),
        "events": event_count,
        "label_counts": dict(sorted(label_counts.items())),
        "groups": groups,
        "group_count": len(set(groups)),
        "explicit_groups": explicit_groups,
    }


def train_from_labeled_jsonl(
    input_path: str | Path,
    output_dir: str | Path = DEFAULT_MODEL_DIR,
    seed: int = 42,
    test_size: float = 0.2,
    training_mode: str = "operator_labeled_real_observations",
) -> dict[str, object]:
    """Train production artifacts from operator-labeled real observations."""
    try:
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        from sklearn.metrics import accuracy_score, classification_report
    except ImportError as exc:
        raise RuntimeError(
            "scikit-learn is not installed. Install it with: python -m pip install -e 'backend[ml]'"
        ) from exc

    vectors, labels, dataset_stats = _load_labeled_windows(input_path)
    if not 0 < test_size < 1:
        raise ValueError("test_size must be between 0 and 1")
    # Keep the final windows of each class out of training. This is less
    # optimistic than randomly splitting adjacent flows from the same capture.
    train_vectors: list[list[float]] = []
    test_vectors: list[list[float]] = []
    train_labels: list[str] = []
    test_labels: list[str] = []
    groups = dataset_stats["groups"]
    assert isinstance(groups, list)
    use_capture_groups = bool(dataset_stats["explicit_groups"])
    for label in sorted(set(labels)):
        class_indices = [index for index, item_label in enumerate(labels) if item_label == label]
        if use_capture_groups:
            class_groups = list(dict.fromkeys(groups[index] for index in class_indices))
            holdout_groups = max(1, int(len(class_groups) * test_size))
            if len(class_groups) - holdout_groups < 1:
                raise ValueError(f"Class {label!r} needs at least two capture groups")
            test_group_set = set(class_groups[-holdout_groups:])
            train_indices = [index for index in class_indices if groups[index] not in test_group_set]
            test_indices = [index for index in class_indices if groups[index] in test_group_set]
        else:
            holdout = max(1, int(len(class_indices) * test_size))
            if len(class_indices) - holdout < 1:
                raise ValueError(f"Class {label!r} needs at least two labeled windows")
            train_indices = class_indices[:-holdout]
            test_indices = class_indices[-holdout:]
        train_vectors.extend(vectors[index] for index in train_indices)
        train_labels.extend([label] * len(train_indices))
        test_vectors.extend(vectors[index] for index in test_indices)
        test_labels.extend([label] * len(test_indices))
    classifier = RandomForestClassifier(n_estimators=120, max_depth=16, random_state=seed, n_jobs=1)
    classifier.fit(train_vectors, train_labels)
    predictions = classifier.predict(test_vectors)
    benign_vectors = [vector for vector, label in zip(train_vectors, train_labels) if label == "benign"]
    if not benign_vectors:
        raise ValueError("Labeled training data must include benign windows for anomaly scoring")
    anomaly_detector = IsolationForest(n_estimators=120, contamination=0.05, random_state=seed, n_jobs=1)
    anomaly_detector.fit(benign_vectors)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(classifier, output_dir / "threat_classifier.joblib")
    joblib.dump(anomaly_detector, output_dir / "anomaly_detector.joblib")
    version = "ml-bootstrap-v1" if training_mode == "fixture_bootstrap" else "ml-real-v1"
    meta = {
        "version": version,
        "class_labels": sorted(set(labels)),
        "feature_names": FEATURE_NAMES,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "training_source": str(input_path),
        "training_mode": training_mode,
        "dataset_sha256": _file_sha256(input_path),
        "dataset_rows": dataset_stats["rows"],
        "dataset_events": dataset_stats["events"],
        "dataset_label_counts": dataset_stats["label_counts"],
        "dataset_group_count": dataset_stats["group_count"],
        "seed": seed,
        "evaluation_accuracy": round(float(accuracy_score(test_labels, predictions)), 4),
        "evaluation_method": (
            "capture_group_holdout" if use_capture_groups else "contiguous_per_class_holdout"
        ),
    }
    (output_dir / "model_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return {
        "output_dir": str(output_dir),
        "trained_on": len(train_labels),
        "evaluated_on": len(test_labels),
        "accuracy": meta["evaluation_accuracy"],
        "classification_report": classification_report(test_labels, predictions, zero_division=0),
        "version": meta["version"],
        "dataset_sha256": meta["dataset_sha256"],
    }


def train_baseline_from_jsonl(
    input_path: str | Path,
    output_dir: str | Path = DEFAULT_MODEL_DIR,
    window_size: int = 64,
) -> dict[str, object]:
    """Train only an anomaly baseline from unlabeled live observations.

    Unlabeled traffic cannot teach a supervised classifier which threat class
    is correct, so this mode deliberately saves no classifier predictions.
    """
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        raise RuntimeError(
            "scikit-learn is not installed. Install it with: python -m pip install -e 'backend[ml]'"
        ) from exc

    events = list(read_events(input_path))
    if len(events) < window_size:
        raise ValueError(f"At least {window_size} normalized events are required for baseline training")
    vectors = [
        [
            float(features.model_dump()[name])
            for name in FEATURE_NAMES
        ]
        for index in range(0, len(events) - window_size + 1, window_size)
        for features in [extract_window_features(events[index : index + window_size], 30.0)]
    ]
    detector = IsolationForest(n_estimators=120, contamination=0.05, random_state=42, n_jobs=1)
    detector.fit(vectors)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(None, output_dir / "threat_classifier.joblib")
    joblib.dump(detector, output_dir / "anomaly_detector.joblib")
    meta = {
        "version": "ml-baseline-v1",
        "class_labels": CLASS_LABELS,
        "feature_names": FEATURE_NAMES,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "training_source": str(input_path),
        "training_mode": "unlabeled_live_anomaly_baseline",
        "dataset_sha256": _file_sha256(input_path),
        "dataset_events": len(events),
        "dataset_windows": len(vectors),
        "windows": len(vectors),
    }
    (output_dir / "model_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return {
        "output_dir": str(output_dir),
        "trained_on": len(events),
        "windows": len(vectors),
        "version": meta["version"],
        "dataset_sha256": meta["dataset_sha256"],
    }
