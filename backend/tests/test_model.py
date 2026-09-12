from datetime import datetime, timedelta, timezone
import json

from sih_detector.features import extract_window_features
from sih_detector.model import FEATURE_NAMES, features_to_vector, load_scorer
from sih_detector.schemas import FlowEvent, ThreatClass
from sih_detector.train import generate_dataset, train_and_save, train_baseline_from_jsonl, train_from_labeled_jsonl

BASE_TIME = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)


def ddos_window() -> list[FlowEvent]:
    return [
        FlowEvent(
            timestamp=BASE_TIME + timedelta(seconds=index),
            flow_id=f"ml-{index}",
            source_ip=f"198.51.100.{index + 2}",
            destination_ip="10.0.0.10",
            source_port=40000 + index,
            destination_port=80,
            protocol="TCP",
            packets=20,
            bytes=64,
            tcp_flags=["SYN"],
            connection_completed=False,
        )
        for index in range(10)
    ]


def test_window_features_cover_all_model_fields() -> None:
    features = extract_window_features(ddos_window(), window_seconds=5.0)
    vector = features_to_vector(features)
    assert len(vector) == len(FEATURE_NAMES)
    assert all(isinstance(value, float) for value in vector)
    assert features.syn_ratio == 1.0
    assert features.unique_sources == 10
    assert features.periodicity_score == 1.0


def test_training_returns_usable_artifacts(tmp_path) -> None:
    result = train_and_save(output_dir=tmp_path, per_class=20, seed=7)
    assert result["accuracy"] >= 0.8
    assert (tmp_path / "threat_classifier.joblib").is_file()
    assert (tmp_path / "anomaly_detector.joblib").is_file()
    assert (tmp_path / "model_meta.json").is_file()

    scorer = load_scorer(tmp_path)
    assert scorer is not None
    ml_result = scorer.score(extract_window_features(ddos_window(), window_seconds=5.0))
    assert ml_result.available
    assert ml_result.threat_class == ThreatClass.DDOS
    assert ml_result.confidence >= 0.5


def test_training_reports_per_class_metrics_on_separated_scenarios(tmp_path) -> None:
    result = train_and_save(output_dir=tmp_path, per_class=15, seed=11, eval_seed=12, eval_per_class=10)
    metrics = result["per_class_metrics"]
    assert set(metrics) == set(
        [
            "benign",
            "ddos",
            "port_scanning",
            "dns_tunnelling",
            "dga",
            "botnet_beaconing",
            "encrypted_session_anomaly",
            "data_exfiltration",
            "udp_amplification",
            "slowloris",
        ]
    )
    for label, values in metrics.items():
        assert 0 <= values["precision"] <= 1
        assert 0 <= values["recall"] <= 1
        assert 0 <= values["f1"] <= 1
    assert result["eval_seed"] == 12
    assert result["evaluated_on"] == 10 * 10
    # Scenario-separated accuracy on separable synthetic classes stays strong.
    assert result["accuracy"] >= 0.8


def test_generated_dataset_has_all_classes() -> None:
    vectors, labels = generate_dataset(per_class=10, seed=3)
    assert len(vectors) == len(labels) == 100
    assert set(labels) == {
        "benign",
        "ddos",
        "port_scanning",
        "dns_tunnelling",
        "dga",
        "botnet_beaconing",
        "encrypted_session_anomaly",
        "data_exfiltration",
        "udp_amplification",
        "slowloris",
    }


def test_real_labeled_windows_train_classifier(tmp_path) -> None:
    dataset = tmp_path / "labeled.jsonl"
    rows = []
    for label, window in [("benign", ddos_window()), ("ddos", ddos_window())]:
        rows.extend({"label": label, "events": [event.model_dump(mode="json") for event in window]} for _ in range(5))
    dataset.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    result = train_from_labeled_jsonl(dataset, output_dir=tmp_path / "models")
    assert result["version"] == "ml-real-v1"
    assert (tmp_path / "models" / "model_meta.json").is_file()
    metadata = json.loads((tmp_path / "models" / "model_meta.json").read_text(encoding="utf-8"))
    assert metadata["feature_schema_version"] == "window-features-v1"
    assert metadata["dataset_sha256"]
    assert metadata["dataset_rows"] == 10
    assert metadata["dataset_events"] == 100


def test_real_training_holds_out_capture_groups(tmp_path) -> None:
    dataset = tmp_path / "grouped-labeled.jsonl"
    rows = []
    for label in ("benign", "ddos"):
        for group_index in range(4):
            rows.append(
                {
                    "label": label,
                    "capture_id": f"{label}-capture-{group_index}",
                    "events": [event.model_dump(mode="json") for event in ddos_window()],
                }
            )
    dataset.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    result = train_from_labeled_jsonl(dataset, output_dir=tmp_path / "models")
    metadata = json.loads((tmp_path / "models" / "model_meta.json").read_text(encoding="utf-8"))

    assert result["version"] == "ml-real-v1"
    assert metadata["evaluation_method"] == "capture_group_holdout"
    assert metadata["dataset_group_count"] == 8
    assert metadata["dataset_rows"] == 8


def test_unlabeled_live_events_train_anomaly_baseline(tmp_path) -> None:
    dataset = tmp_path / "live.jsonl"
    events = ddos_window() * 7
    dataset.write_text("\n".join(event.model_dump_json() for event in events) + "\n", encoding="utf-8")

    result = train_baseline_from_jsonl(dataset, output_dir=tmp_path / "models", window_size=10)
    assert result["version"] == "ml-baseline-v1"
    assert load_scorer(tmp_path / "models") is not None
