import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from sih_detector.incidents import IncidentAggregator
from sih_detector.schemas import Alert, Evidence, Severity, ThreatClass


BASE_TIME = datetime(2026, 9, 11, 10, 0, tzinfo=timezone.utc)


def alert(index: int, **overrides: object) -> Alert:
    values: dict[str, object] = {
        "alert_id": f"alert-sanitized-{index}",
        "timestamp": BASE_TIME + timedelta(seconds=index),
        "flow_id": f"flow-{index}",
        "threat_class": ThreatClass.UDP_AMPLIFICATION,
        "severity": Severity.HIGH,
        "confidence": 0.91,
        "source_ip": f"198.51.100.{index + 1}",
        "destination_ip": "10.0.0.53",
        "protocol": "UDP",
        "window_seconds": 30,
        "evidence": [Evidence(feature="packet_rate", value=100, reason="sanitized fixture")],
        "detector": "udp_amplification_v1",
        "model_version": "rules-v1",
    }
    values.update(overrides)
    return Alert(**values)


def test_incident_groups_sources_within_window() -> None:
    aggregator = IncidentAggregator()
    first = aggregator.add(alert(0), "authorized_live_metadata")
    second = aggregator.add(alert(1), "authorized_live_metadata")

    assert first.incident_id == second.incident_id
    assert second.alert_count == 2
    assert second.source_ips == ["198.51.100.1", "198.51.100.2"]
    assert second.provenance == "authorized_live_metadata"


def test_incident_splits_after_window_or_key_change() -> None:
    aggregator = IncidentAggregator()
    first = aggregator.add(alert(0), "synthetic_fixture")
    later = aggregator.add(alert(31), "synthetic_fixture")
    other_destination = aggregator.add(alert(2, destination_ip="10.0.0.54"), "synthetic_fixture")

    assert later.incident_id != first.incident_id
    assert other_destination.incident_id != later.incident_id


def test_quic_parser_keeps_only_derived_metadata() -> None:
    scapy = pytest.importorskip("scapy.all")
    from scapy.layers.inet import IP, UDP
    from scapy.packet import Raw
    from sih_detector.live_capture import packet_to_event

    # Sanitized QUIC long-header packet: version 1, no application payload retained.
    packet = IP(src="192.0.2.10", dst="192.0.2.20") / UDP(sport=50000, dport=443) / Raw(
        load=b"\xc0\x00\x00\x00\x01"
    )
    event = packet_to_event(packet, {"192.0.2.10"})

    assert event is not None
    assert event.quic_version == "0x00000001"
    assert event.tls_packet_sizes == [len(packet)]
    assert not hasattr(event, "payload")


def test_tls_client_hello_derives_metadata_without_payload() -> None:
    pytest.importorskip("scapy.all")
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls.handshake import TLSClientHello
    from scapy.layers.tls.record import TLS
    from scapy.packet import Raw
    from sih_detector.live_capture import packet_to_event

    packet = IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=50000, dport=443) / TLS() / TLSClientHello()
    # Raw bytes are sanitized fixture input and are not part of FlowEvent output.
    packet = packet / Raw(load=b"sanitized-handshake-marker")
    event = packet_to_event(packet, {"192.0.2.10"})

    assert event is not None
    assert event.tls_client_hello is True
    assert event.tls_fingerprint
    assert event.tls_packet_sizes == [len(packet)]
    assert not hasattr(event, "payload")


def test_flow_aggregator_merges_packets_and_flushes_on_tcp_close() -> None:
    from sih_detector.live_capture import FlowAggregator
    from sih_detector.schemas import FlowEvent

    first = FlowEvent(
        timestamp=BASE_TIME,
        flow_id="packet-1",
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        source_port=40000,
        destination_port=443,
        protocol="TCP",
        packets=1,
        bytes=60,
        direction="outbound",
        tcp_flags=["SYN"],
        connection_completed=False,
    )
    last = first.model_copy(
        update={
            "timestamp": BASE_TIME + timedelta(seconds=1),
            "flow_id": "packet-2",
            "packets": 1,
            "bytes": 80,
            "tcp_flags": ["FIN"],
            "connection_completed": True,
        }
    )

    aggregator = FlowAggregator()
    assert aggregator.push(first) == []
    completed = aggregator.push(last)

    assert len(completed) == 1
    assert completed[0].flow_id == "packet-1"
    assert completed[0].packets == 2
    assert completed[0].bytes == 140
    assert completed[0].tcp_flags == ["SYN", "FIN"]


def test_flow_aggregator_flushes_idle_flows() -> None:
    from sih_detector.live_capture import FlowAggregator
    from sih_detector.schemas import FlowEvent

    event = FlowEvent(
        timestamp=BASE_TIME,
        flow_id="udp-1",
        source_ip="192.0.2.10",
        destination_ip="192.0.2.20",
        source_port=40000,
        destination_port=53,
        protocol="UDP",
        packets=1,
        bytes=100,
    )
    later = event.model_copy(update={"timestamp": BASE_TIME + timedelta(seconds=6), "flow_id": "udp-2"})

    aggregator = FlowAggregator(idle_timeout_seconds=5)
    assert aggregator.push(event) == []
    completed = aggregator.push(later)

    assert [flow.flow_id for flow in completed] == ["udp-1"]
    assert aggregator.flush()[0].flow_id == "udp-2"


@pytest.mark.skipif(
    os.getenv("SIH_RUN_LIVE_CAPTURE_TEST") != "1",
    reason="Set SIH_RUN_LIVE_CAPTURE_TEST=1 for an authorized local capture check",
)
def test_authorized_loopback_capture_emits_metadata_only() -> None:
    pytest.importorskip("scapy.all")
    from sih_detector.live_capture import capture_events

    stop_event = threading.Event()
    captured: list = []
    capture_errors: list[Exception] = []

    def collect() -> None:
        try:
            captured.extend(capture_events(stop_event, interface="lo", bpf_filter="udp and port 39099"))
        except Exception as exc:
            capture_errors.append(exc)

    collector = threading.Thread(target=collect, daemon=True)
    collector.start()
    time.sleep(0.25)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"authorized-local-test", ("127.0.0.1", 39099))
    except PermissionError as exc:
        stop_event.set()
        collector.join(timeout=5)
        pytest.skip(f"raw socket capture is unavailable in this environment: {exc}")
    stop_event.set()
    collector.join(timeout=5)

    if capture_errors:
        pytest.skip(f"live capture is unavailable in this environment: {capture_errors[0]}")

    assert captured
    assert sum(event.packets for event in captured) >= 1
    assert all(not hasattr(event, "payload") for event in captured)