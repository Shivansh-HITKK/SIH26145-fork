"""Passive packet capture adapter for authorized local interfaces.

Only packet metadata is converted into FlowEvent objects. Payload bytes are
never stored or sent anywhere; the adapter is intentionally read-only.
"""

from __future__ import annotations

import queue
import socket
import threading
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TypeAlias
from uuid import uuid4
import hashlib

from .schemas import FlowEvent


FlowKey: TypeAlias = tuple[str, str, int, int, str]


@dataclass
class _BufferedFlow:
    event: FlowEvent
    last_seen: datetime


class CaptureStats:
    """Thread-safe counters for packet capture health and backpressure."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._packets_seen = 0
        self._flows_emitted = 0
        self._dropped_packets = 0
        self._error_count = 0
        self._last_error: str | None = None

    def packet_seen(self) -> None:
        with self._lock:
            self._packets_seen += 1

    def flow_emitted(self) -> None:
        with self._lock:
            self._flows_emitted += 1

    def packet_dropped(self) -> None:
        with self._lock:
            self._dropped_packets += 1

    def error(self, message: str) -> None:
        with self._lock:
            self._error_count += 1
            self._last_error = message

    def snapshot(self) -> dict[str, int | str | None]:
        with self._lock:
            return {
                "packets_seen": self._packets_seen,
                "flows_emitted": self._flows_emitted,
                "dropped_packets": self._dropped_packets,
                "error_count": self._error_count,
                "last_error": self._last_error,
            }


def list_interfaces() -> list[str]:
    """Return locally visible interface names without opening a capture."""
    try:
        return sorted({name for _index, name in socket.if_nameindex()})
    except OSError:
        return []


class FlowAggregator:
    """Bounded metadata-only aggregation for packets from one live capture."""

    def __init__(self, idle_timeout_seconds: float = 5.0, max_flows: int = 10_000) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive")
        if max_flows < 1:
            raise ValueError("max_flows must be positive")
        self.idle_timeout = timedelta(seconds=idle_timeout_seconds)
        self.max_flows = max_flows
        self._flows: dict[FlowKey, _BufferedFlow] = {}

    @staticmethod
    def _key(event: FlowEvent) -> FlowKey:
        return (
            event.source_ip,
            event.destination_ip,
            event.source_port,
            event.destination_port,
            event.protocol.upper(),
        )

    @staticmethod
    def _merge(current: FlowEvent, incoming: FlowEvent) -> FlowEvent:
        flags = list(dict.fromkeys([*current.tcp_flags, *incoming.tcp_flags]))
        packet_sizes = [*current.tls_packet_sizes, *incoming.tls_packet_sizes][-32:]
        direction = current.direction if current.direction == incoming.direction else "unknown"
        return current.model_copy(
            update={
                "timestamp": max(current.timestamp, incoming.timestamp),
                "packets": current.packets + incoming.packets,
                "bytes": current.bytes + incoming.bytes,
                "direction": direction,
                "tcp_flags": flags,
                "connection_completed": (
                    True
                    if current.connection_completed is True or incoming.connection_completed is True
                    else False
                    if current.connection_completed is False or incoming.connection_completed is False
                    else None
                ),
                "dns_query": incoming.dns_query or current.dns_query,
                "dns_record_type": incoming.dns_record_type or current.dns_record_type,
                "tls_fingerprint": incoming.tls_fingerprint or current.tls_fingerprint,
                "tls_version": incoming.tls_version or current.tls_version,
                "tls_client_hello": current.tls_client_hello or incoming.tls_client_hello,
                "tls_server_hello": current.tls_server_hello or incoming.tls_server_hello,
                "quic_version": incoming.quic_version or current.quic_version,
                "tls_packet_sizes": packet_sizes,
            }
        )

    def push(self, event: FlowEvent) -> list[FlowEvent]:
        """Add one packet event and return flows completed by timeout or TCP close."""
        completed: list[FlowEvent] = []
        cutoff = event.timestamp - self.idle_timeout
        for key, buffered in list(self._flows.items()):
            if buffered.last_seen < cutoff:
                completed.append(buffered.event)
                del self._flows[key]

        key = self._key(event)
        buffered = self._flows.get(key)
        if buffered is None:
            self._flows[key] = _BufferedFlow(event=event, last_seen=event.timestamp)
        else:
            buffered.event = self._merge(buffered.event, event)
            buffered.last_seen = event.timestamp

        if event.connection_completed is True or {"FIN", "RST"}.intersection(event.tcp_flags):
            completed.append(self._flows.pop(key).event)

        while len(self._flows) > self.max_flows:
            oldest_key = min(self._flows, key=lambda item: self._flows[item].last_seen)
            completed.append(self._flows.pop(oldest_key).event)
        return completed

    def flush(self) -> list[FlowEvent]:
        """Complete and return all buffered flows, for a clean capture stop."""
        completed = [buffered.event for buffered in self._flows.values()]
        self._flows.clear()
        return completed


def _tls_quic_metadata(packet: object, protocol: str) -> dict[str, object]:
    """Derive handshake metadata transiently; never return or persist payload bytes."""
    result: dict[str, object] = {
        "tls_fingerprint": None,
        "tls_version": None,
        "tls_client_hello": False,
        "tls_server_hello": False,
        "quic_version": None,
        "tls_packet_sizes": [],
    }
    if protocol == "TCP":
        try:
            from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
            from scapy.layers.tls.record import TLS

            if packet.haslayer(TLSClientHello):
                hello = packet[TLSClientHello]
                result["tls_client_hello"] = True
                result["tls_version"] = str(getattr(hello, "version", None) or "unknown")
                # JA3-style input uses handshake metadata only; values are not retained.
                ciphers = ",".join(str(item) for item in (getattr(hello, "ciphers", None) or []))
                extensions = ",".join(str(item) for item in (getattr(hello, "ext", None) or []))
                result["tls_fingerprint"] = hashlib.md5(f"{result['tls_version']},{ciphers},{extensions}".encode(), usedforsecurity=False).hexdigest()
            if packet.haslayer(TLSServerHello):
                hello = packet[TLSServerHello]
                result["tls_server_hello"] = True
                result["tls_version"] = str(getattr(hello, "version", None) or result["tls_version"] or "unknown")
            if packet.haslayer(TLS):
                result["tls_packet_sizes"] = [len(packet)]
        except (ImportError, IndexError, AttributeError, TypeError, ValueError):
            pass
    elif protocol == "UDP":
        try:
            transport = packet["UDP"]
            raw = bytes(transport.payload)
            if len(raw) >= 5 and raw[0] & 0x80:
                result["quic_version"] = f"0x{int.from_bytes(raw[1:5], 'big'):08x}"
                result["tls_packet_sizes"] = [len(packet)]
        except (KeyError, IndexError, TypeError, ValueError):
            pass
    return result


def _local_addresses() -> set[str]:
    """Return local addresses used to infer event direction."""
    import socket

    addresses = {"127.0.0.1", "::1"}
    hostname = socket.gethostname()
    for family, _kind, _proto, _canonname, sockaddr in socket.getaddrinfo(hostname, None):
        if family == socket.AF_INET:
            addresses.add(sockaddr[0])
        elif family == socket.AF_INET6:
            addresses.add(sockaddr[0].split("%", 1)[0])
    return addresses


def packet_to_event(packet: object, local_addresses: set[str] | None = None) -> FlowEvent | None:
    """Convert one Scapy IP packet into metadata-only normalized flow data."""
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if packet is None or not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return None

    network = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    source_ip = str(network.src)
    destination_ip = str(network.dst)
    protocol = "ip"
    source_port = 0
    destination_port = 0
    tcp_flags: list[str] = []
    completed: bool | None = None

    if packet.haslayer(TCP):
        transport = packet[TCP]
        protocol = "TCP"
        source_port = int(transport.sport)
        destination_port = int(transport.dport)
        flags = str(transport.flags)
        flag_names = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH"}
        tcp_flags = [name for flag, name in flag_names.items() if flag in flags]
        if "F" in flags or "R" in flags:
            completed = True
        elif "S" in flags and "A" not in flags:
            completed = False
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        protocol = "UDP"
        source_port = int(transport.sport)
        destination_port = int(transport.dport)

    encrypted = _tls_quic_metadata(packet, protocol)

    dns_query = None
    dns_record_type = None
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        question = packet[DNSQR]
        raw_name = bytes(question.qname).rstrip(b".")
        dns_query = raw_name.decode("utf-8", errors="replace")
        record_types = {1: "A", 28: "AAAA", 5: "CNAME", 16: "TXT", 65: "HTTPS"}
        dns_record_type = record_types.get(int(question.qtype), str(question.qtype))

    addresses = local_addresses or set()
    if source_ip in addresses:
        direction = "outbound"
    elif destination_ip in addresses:
        direction = "inbound"
    else:
        direction = "unknown"

    timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
    flow_id = f"live_{uuid4().hex}"
    return FlowEvent(
        timestamp=timestamp,
        flow_id=flow_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packets=1,
        bytes=len(packet),
        direction=direction,
        tcp_flags=tcp_flags,
        connection_completed=completed,
        dns_query=dns_query,
        dns_record_type=dns_record_type,
        **encrypted,
    )


def capture_events(
    stop_event: threading.Event,
    interface: str | None = None,
    bpf_filter: str = "ip or ip6",
    stats: CaptureStats | None = None,
) -> Iterator[FlowEvent]:
    """Yield passive events from an authorized interface until stopped."""
    try:
        from scapy.all import AsyncSniffer
    except ImportError as exc:
        raise RuntimeError(
            "Live capture requires Scapy. Install it with: "
            "python -m pip install -e 'backend[live]'"
        ) from exc

    events: queue.Queue[FlowEvent] = queue.Queue(maxsize=4096)
    encrypted_flow_sizes: dict[FlowKey, deque[int]] = {}
    aggregator = FlowAggregator()
    local_addresses = _local_addresses()

    def on_packet(packet: object) -> None:
        if stats is not None:
            stats.packet_seen()
        try:
            event = packet_to_event(packet, local_addresses)
        except Exception as exc:
            if stats is not None:
                stats.error(f"Packet metadata parsing failed: {exc}")
            return
        if event is None:
            return
        flow_key = (
            event.source_ip,
            event.destination_ip,
            event.source_port,
            event.destination_port,
            event.protocol,
        )
        is_encrypted = bool(event.tls_client_hello or event.tls_server_hello or event.quic_version)
        if is_encrypted:
            encrypted_flow_sizes.setdefault(flow_key, deque(maxlen=32))
        if flow_key in encrypted_flow_sizes:
            sizes = encrypted_flow_sizes[flow_key]
            sizes.append(event.bytes)
            event = event.model_copy(update={"tls_packet_sizes": list(sizes)})
        try:
            events.put_nowait(event)
        except queue.Full:
            # Preserve bounded memory under packet bursts; the detector remains live.
            if stats is not None:
                stats.packet_dropped()

    try:
        sniffer = AsyncSniffer(
            iface=interface or None,
            filter=bpf_filter,
            prn=on_packet,
            store=False,
        )
        sniffer.start()
    except Exception as exc:
        if stats is not None:
            stats.error(str(exc))
        raise RuntimeError(f"Unable to start capture on {interface or 'default interface'}: {exc}") from exc
    try:
        while not stop_event.is_set():
            try:
                event = events.get(timeout=0.25)
                for flow in aggregator.push(event):
                    if stats is not None:
                        stats.flow_emitted()
                    yield flow
            except queue.Empty:
                continue
    finally:
        if sniffer.running:
            sniffer.stop()

    while True:
        try:
            event = events.get_nowait()
        except queue.Empty:
            break
        for flow in aggregator.push(event):
            if stats is not None:
                stats.flow_emitted()
            yield flow
    for flow in aggregator.flush():
        if stats is not None:
            stats.flow_emitted()
        yield flow
