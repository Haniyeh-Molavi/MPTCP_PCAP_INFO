from __future__ import annotations

import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

try:
    from protocol_layer.ethernet import stream_pcap_packets
    from protocol_layer.mptcp_level import compute_mptcp_token, parse_mptcp_packet
except ImportError:
    from ethernet import stream_pcap_packets
    from mptcp_level import compute_mptcp_token, parse_mptcp_packet


def _tcp_options(packet_bytes: bytes) -> bytes | None:
    """Return TCP options from an Ethernet or Linux cooked IPv4/IPv6 frame."""
    if len(packet_bytes) < 34:
        return None

    eth_type = int.from_bytes(packet_bytes[12:14], "big")
    ip_offset = 14
    if eth_type in (0x8100, 0x88A8) and len(packet_bytes) >= 18:
        eth_type = int.from_bytes(packet_bytes[16:18], "big")
        ip_offset = 18
    if eth_type not in (0x0800, 0x86DD) and len(packet_bytes) >= 16:
        sll_type = int.from_bytes(packet_bytes[14:16], "big")
        if sll_type in (0x0800, 0x86DD):
            eth_type = sll_type
            ip_offset = 16

    ip_data = packet_bytes[ip_offset:]
    if eth_type == 0x0800:
        if len(ip_data) < 20 or (ip_data[0] >> 4) != 4 or ip_data[9] != 6:
            return None
        ip_header_length = (ip_data[0] & 0x0F) * 4
    elif eth_type == 0x86DD:
        if len(ip_data) < 40 or (ip_data[0] >> 4) != 6 or ip_data[6] != 6:
            return None
        ip_header_length = 40
    else:
        return None

    tcp_data = ip_data[ip_header_length:]
    if len(tcp_data) < 20:
        return None
    tcp_header_length = (tcp_data[12] >> 4) * 4
    if tcp_header_length < 20 or len(tcp_data) < tcp_header_length:
        return None
    return tcp_data[20:tcp_header_length]


def _mptcp_subtypes(packet_bytes: bytes) -> tuple[set[int], int, bytes | None]:
    """Return MPTCP subtypes, removed address IDs, and an MP_JOIN token."""
    options = _tcp_options(packet_bytes)
    if options is None:
        return set(), 0, None

    subtypes: set[int] = set()
    removed_addresses = 0
    join_token = None
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 1 >= len(options):
            break
        length = options[index + 1]
        if length < 2 or index + length > len(options):
            break
        if kind == 30:
            value = options[index + 2 : index + length]
            if value:
                subtype = value[0] >> 4
                subtypes.add(subtype)
                if subtype == 1 and len(value) >= 5:
                    join_token = value[1:5]
                if subtype == 4:
                    removed_addresses += max(len(value) - 1, 0)
        index += length
    return subtypes, removed_addresses, join_token


def _subflow_key(parsed: dict) -> tuple[tuple[str, int], tuple[str, int]]:
    return tuple(sorted((
        (parsed["src_ip"], parsed["sport"]),
        (parsed["dst_ip"], parsed["dport"]),
    )))


def _path_key(parsed: dict) -> tuple[str, str]:
    return tuple(sorted((parsed["src_ip"], parsed["dst_ip"])))


def _active_statistics(intervals: list[tuple[float, float]]) -> tuple[int, float]:
    """Calculate maximum and time-weighted average concurrent subflows."""
    if not intervals:
        return 0, 0.0

    events: list[tuple[float, int]] = []
    for start, end in intervals:
        events.append((start, 1))
        events.append((end, -1))
    events.sort(key=lambda event: (event[0], event[1]))

    active = 0
    maximum = 0
    active_area = 0.0
    previous = events[0][0]
    for timestamp, delta in events:
        active_area += active * max(timestamp - previous, 0.0)
        active += delta
        maximum = max(maximum, active)
        previous = timestamp

    capture_duration = max(events[-1][0] - events[0][0], 0.0)
    if capture_duration == 0:
        return maximum, float(maximum)
    return maximum, active_area / capture_duration


def extract_path_usage_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """Extract path and subflow usage features into one row per MPTCP connection."""
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_path_usage.csv")
    else:
        output_path = Path(output_csv_path).expanduser().resolve()
        csv_path = (
            output_path / f"{pcap_path.stem}_path_usage.csv"
            if output_path.is_dir() or output_path.suffix == ""
            else output_path
        )
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    connection_subflows: dict[str, dict[tuple[tuple[str, int], tuple[str, int]], list[float]]] = defaultdict(lambda: defaultdict(list))
    connection_paths: dict[str, set[tuple[str, str]]] = defaultdict(set)
    connection_events: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    subflow_to_connection: dict[tuple[tuple[str, int], tuple[str, int]], str] = {}
    token_to_connection: dict[bytes, str] = {}
    next_connection_id = 1
    packet_count = 0
    start_time = time.perf_counter()

    for timestamp, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mptcp_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        subflow_key = _subflow_key(parsed)
        subtypes, removed_count, join_token = _mptcp_subtypes(packet_bytes)

        connection_id = subflow_to_connection.get(subflow_key)
        if connection_id is None:
            connection_token = None
            if parsed.get("sender_key"):
                connection_token = compute_mptcp_token(parsed["sender_key"])
            elif parsed.get("receiver_key"):
                connection_token = compute_mptcp_token(parsed["receiver_key"])
            elif join_token:
                connection_token = f"0x{join_token.hex().upper()}"

            if connection_token:
                connection_id = token_to_connection.get(connection_token)
                if connection_id is None:
                    connection_id = f"conn_{next_connection_id}"
                    next_connection_id += 1
                    token_to_connection[connection_token] = connection_id
            else:
                connection_id = f"conn_{next_connection_id}"
                next_connection_id += 1

            subflow_to_connection[subflow_key] = connection_id

        connection_subflows[connection_id][subflow_key].append(timestamp)
        connection_paths[connection_id].add(_path_key(parsed))
        events = connection_events[connection_id]
        events[0] += 1 if 1 in subtypes else 0
        events[1] += 1 if 3 in subtypes else 0
        events[2] += removed_count

        if limit_packets is not None and packet_count >= limit_packets:
            break

    headers = [
        "PCAP File",
        "MPTCP Connection ID",
        "Number of Subflows",
        "Maximum Active Subflows",
        "Average Active Subflows",
        "Number of Paths Used",
        "Number of Address Changes",
        "Number of MP_JOIN Events",
        "Number of ADD_ADDR Events",
        "Number of REMOVE_ADDR Events",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        for connection_id in sorted(connection_subflows):
            intervals = [
                (timestamps[0], timestamps[-1])
                for timestamps in connection_subflows[connection_id].values()
            ]
            maximum_active, average_active = _active_statistics(intervals)
            mp_join_events, add_addr_events, remove_addr_events = connection_events[connection_id]
            writer.writerow([
                pcap_path.name,
                connection_id,
                len(connection_subflows[connection_id]),
                maximum_active,
                f"{average_active:.6f}",
                len(connection_paths[connection_id]),
                add_addr_events + remove_addr_events,
                mp_join_events,
                add_addr_events,
                remove_addr_events,
            ])

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "connection_count": len(connection_subflows),
        "subflow_count": sum(len(subflows) for subflows in connection_subflows.values()),
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
    }