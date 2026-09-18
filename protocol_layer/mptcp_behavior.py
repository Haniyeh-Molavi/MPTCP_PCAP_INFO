from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

try:
    from protocol_layer.ethernet import DEFAULT_LINK_SPEED_BPS, parse_link_speed, stream_pcap_packets
    from protocol_layer.mptcp_level import compute_mptcp_token, parse_mptcp_packet, pcap_file_id
except ImportError:
    try:
        from ethernet import DEFAULT_LINK_SPEED_BPS, parse_link_speed, stream_pcap_packets
        from mptcp_level import compute_mptcp_token, parse_mptcp_packet, pcap_file_id
    except ImportError:
        import dpkt

        DEFAULT_LINK_SPEED_BPS = 1_000_000_000

        def parse_link_speed(value: str) -> float:
            value = value.strip().upper()
            if value.endswith("G"):
                return float(value[:-1]) * 1_000_000_000
            if value.endswith("M"):
                return float(value[:-1]) * 1_000_000
            if value.endswith("K"):
                return float(value[:-1]) * 1_000
            try:
                return float(value)
            except ValueError:
                return DEFAULT_LINK_SPEED_BPS

        def stream_pcap_packets(file_path: Path | str):
            with open(file_path, "rb") as f:
                reader = dpkt.pcap.Reader(f)
                for ts, pkt in reader:
                    yield float(ts), pkt

        def parse_mptcp_packet(packet_bytes: bytes):
            return None

        def compute_mptcp_token(key_bytes: bytes) -> str:
            return ""

        def pcap_file_id(pcap_path: Path | str) -> int:
            raise RuntimeError("PCAP file ID parser is unavailable")


PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


def _canonical_subflow_key(src_ip: str, sport: int, dst_ip: str, dport: int) -> tuple[str, int, str, int]:
    endpoint_a = (src_ip, sport)
    endpoint_b = (dst_ip, dport)
    return tuple(sorted((endpoint_a, endpoint_b)))


def _path_key(src_ip: str, dst_ip: str) -> tuple[str, str]:
    return (src_ip, dst_ip)


def _format_mapping(mapping: dict[str, float]) -> str:
    return ";".join(f"{key}={value:.6f}" for key, value in sorted(mapping.items()))


def _extract_mp_fail_packet(packet_bytes: bytes):
    """Extract MP_FAIL metadata from packet bytes if present."""
    frame_len = len(packet_bytes)
    if frame_len < 54:
        return None

    eth_type = (packet_bytes[12] << 8) | packet_bytes[13]
    ip_offset = 14

    if eth_type in (0x8100, 0x88A8) and frame_len >= 18:
        inner_type = (packet_bytes[16] << 8) | packet_bytes[17]
        ip_offset = 18
        if inner_type in (0x8100, 0x88A8) and frame_len >= 22:
            eth_type = (packet_bytes[20] << 8) | packet_bytes[21]
            ip_offset = 22
        else:
            eth_type = inner_type

    if eth_type not in (0x0800, 0x86DD) and frame_len >= 16:
        sll_proto = (packet_bytes[14] << 8) | packet_bytes[15]
        if sll_proto in (0x0800, 0x86DD):
            eth_type = sll_proto
            ip_offset = 16

    if eth_type == 0x0800:
        ip_data = packet_bytes[ip_offset:]
        if len(ip_data) < 20 or (ip_data[0] >> 4) != 4 or ip_data[9] != 6:
            return None
        ip_header_length = (ip_data[0] & 0x0F) * 4
        src_ip = f"{ip_data[12]}.{ip_data[13]}.{ip_data[14]}.{ip_data[15]}"
        dst_ip = f"{ip_data[16]}.{ip_data[17]}.{ip_data[18]}.{ip_data[19]}"
        tcp_data = ip_data[ip_header_length:]
    elif eth_type == 0x86DD:
        ip_data = packet_bytes[ip_offset:]
        if len(ip_data) < 40 or (ip_data[0] >> 4) != 6 or ip_data[6] != 6:
            return None
        src_ip = f"{ip_data[8]:x}:{ip_data[9]:x}..."
        dst_ip = f"{ip_data[24]:x}:{ip_data[25]:x}..."
        tcp_data = ip_data[40:]
    else:
        return None

    if len(tcp_data) < 20:
        return None

    data_offset = (tcp_data[12] >> 4) * 4
    if data_offset <= 20 or len(tcp_data) < data_offset:
        return None

    options_bytes = tcp_data[20:data_offset]
    i = 0
    while i < len(options_bytes):
        kind = options_bytes[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(options_bytes):
            break

        length = options_bytes[i + 1]
        if length < 2 or i + length > len(options_bytes):
            break

        if kind == 30:
            value = options_bytes[i + 2 : i + length]
            if len(value) >= 1 and (value[0] >> 4) == 6 and len(value) >= 5:
                return {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "sport": (tcp_data[0] << 8) | tcp_data[1],
                    "dport": (tcp_data[2] << 8) | tcp_data[3],
                    "failure_sequence_number": int.from_bytes(value[1:5], "big"),
                }

        i += length

    return None


class PathState:
    def __init__(self, src_ip: str, dst_ip: str, first_ts: float) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.bytes = 0
        self.packets = 0

    def update(self, ts: float, frame_len: int) -> None:
        self.packets += 1
        self.bytes += max(frame_len, 0)
        self.last_ts = max(self.last_ts, ts)


class ConnectionState:
    def __init__(self, connection_id: str, start_ts: float) -> None:
        self.connection_id = connection_id
        self.start_ts = start_ts
        self.end_ts = start_ts
        self.total_bytes = 0
        self.total_packets = 0
        self.subflow_keys: set[tuple[str, int, str, int]] = set()
        self.path_states: dict[tuple[str, str], PathState] = {}
        self.path_switch_count = 0
        self.last_path_key: tuple[str, str] | None = None
        self.max_active_paths = 0
        self.failures: list[dict] = []
        self.join_events: list[dict] = []

    def update(self, ts: float, parsed: dict, fail_event: dict | None) -> None:
        self.total_packets += 1
        self.end_ts = max(self.end_ts, ts)

        subflow_key = _canonical_subflow_key(parsed["src_ip"], parsed["sport"], parsed["dst_ip"], parsed["dport"])
        self.subflow_keys.add(subflow_key)

        path_key = _path_key(parsed["src_ip"], parsed["dst_ip"])
        if path_key not in self.path_states:
            self.path_states[path_key] = PathState(parsed["src_ip"], parsed["dst_ip"], ts)

        self.path_states[path_key].update(ts, parsed.get("frame_len", 0))
        self.total_bytes += parsed.get("frame_len", 0)

        if self.last_path_key is not None and path_key != self.last_path_key:
            self.path_switch_count += 1
        self.last_path_key = path_key

        self.max_active_paths = max(self.max_active_paths, len(self.path_states))

        if fail_event is not None:
            self.failures.append(
                {
                    "ts": ts,
                    "path_key": _path_key(fail_event["src_ip"], fail_event["dst_ip"]),
                    "failure_sequence_number": fail_event.get("failure_sequence_number"),
                }
            )

        if parsed.get("join_token"):
            self.join_events.append(
                {
                    "ts": ts,
                    "path_key": path_key,
                    "join_token": parsed.get("join_token"),
                }
            )


class MPTCPBehaviorEvaluator:
    def __init__(self, link_speed_bps: float = DEFAULT_LINK_SPEED_BPS) -> None:
        self.link_speed_bps = float(link_speed_bps)
        self.subflow_to_conn: dict[tuple[str, int, str, int], str] = {}
        self.connections: dict[str, ConnectionState] = {}
        self.default_conn_id = "default_mptcp"
        self.packet_count = 0

    def _resolve_connection_id(self, parsed: dict) -> str:
        subflow_key = _canonical_subflow_key(parsed["src_ip"], parsed["sport"], parsed["dst_ip"], parsed["dport"])
        conn_id = self.subflow_to_conn.get(subflow_key)
        if conn_id is not None:
            return conn_id

        sender_key = parsed.get("sender_key")
        receiver_key = parsed.get("receiver_key")
        if sender_key:
            conn_id = compute_mptcp_token(sender_key)
        elif receiver_key:
            conn_id = compute_mptcp_token(receiver_key)
        else:
            conn_id = self.default_conn_id

        self.subflow_to_conn[subflow_key] = conn_id
        return conn_id

    def evaluate_packet(self, ts: float, parsed: dict, fail_event: dict | None) -> None:
        self.packet_count += 1
        conn_id = self._resolve_connection_id(parsed)
        if conn_id not in self.connections:
            self.connections[conn_id] = ConnectionState(conn_id, ts)
        self.connections[conn_id].update(ts, parsed, fail_event)

    def _compute_recovery_metrics(self, conn: ConnectionState) -> tuple[float, float, float]:
        if not conn.failures:
            return 0.0, 0.0, 0.0

        failures = sorted(conn.failures, key=lambda item: item["ts"])
        joins = sorted(conn.join_events, key=lambda item: item["ts"])

        delays: list[float] = []
        first_delay = 0.0

        for failure in failures:
            failure_ts = failure["ts"]
            failure_path = failure["path_key"]
            recovery_ts = None

            for join in joins:
                if join["ts"] < failure_ts:
                    continue
                if join["path_key"] == failure_path:
                    recovery_ts = join["ts"]
                    break

            if recovery_ts is None:
                for join in joins:
                    if join["ts"] >= failure_ts:
                        recovery_ts = join["ts"]
                        break

            if recovery_ts is None:
                continue

            delay = max(recovery_ts - failure_ts, 0.0)
            delays.append(delay)
            if first_delay == 0.0:
                first_delay = delay

        if not delays:
            return 0.0, 0.0, 0.0

        return first_delay, (sum(delays) / len(delays)), max(delays)

    def build_rows(self) -> list[dict]:
        rows: list[dict] = []
        for conn_id, conn in sorted(self.connections.items()):
            duration = max(conn.end_ts - conn.start_ts, 0.0)
            if duration <= 0:
                duration = 1e-6

            path_bytes: dict[str, int] = {
                f"{src_ip}->{dst_ip}": state.bytes
                for (src_ip, dst_ip), state in conn.path_states.items()
            }
            total_bytes = sum(path_bytes.values())

            traffic_distribution: dict[str, float] = {}
            for path_name, path_value in path_bytes.items():
                traffic_distribution[path_name] = (path_value / total_bytes) if total_bytes else 0.0

            path_lifetimes: dict[str, float] = {}
            for (src_ip, dst_ip), state in conn.path_states.items():
                path_name = f"{src_ip}->{dst_ip}"
                path_lifetimes[path_name] = max(state.last_ts - state.first_ts, 0.0)

            path_utilization: dict[str, float] = {}
            for (src_ip, dst_ip), state in conn.path_states.items():
                path_name = f"{src_ip}->{dst_ip}"
                path_capacity = self.link_speed_bps * max(path_lifetimes[path_name], duration)
                path_utilization[path_name] = (state.bytes / path_capacity) if path_capacity > 0 else 0.0

            jfi = 0.0
            if path_bytes:
                xi_values = list(path_bytes.values())
                numerator = sum(xi_values) ** 2
                denominator = len(xi_values) * sum(x * x for x in xi_values)
                jfi = numerator / denominator if denominator > 0 else 0.0

            dominant_path_percentage = 0.0
            if total_bytes > 0:
                dominant_path_percentage = (max(path_bytes.values()) / total_bytes) * 100.0

            failover_time, recovery_time, path_rejoin_delay = self._compute_recovery_metrics(conn)

            rows.append(
                {
                    "PCAP File": 0,
                    "MPTCP Connection ID": conn_id,
                    "start_time": conn.start_ts,
                    "end_time": conn.end_ts,
                    "duration": duration,
                    "number_of_subflows": len(conn.subflow_keys),
                    "number_of_paths": len(conn.path_states),
                    "active_path_count": conn.max_active_paths,
                    "path_switching_count": conn.path_switch_count,
                    "path_switching_rate": conn.path_switch_count / duration if duration > 0 else 0.0,
                    "traffic_distribution_ratio": _format_mapping(traffic_distribution),
                    "load_balancing_ratio": _format_mapping(traffic_distribution),
                    "jain_fairness_index": jfi,
                    "dominant_path_percentage": dominant_path_percentage,
                    "path_utilization": _format_mapping(path_utilization),
                    "path_lifetime": _format_mapping(path_lifetimes),
                    "failover_time": failover_time,
                    "recovery_time": recovery_time,
                    "path_rejoin_delay": path_rejoin_delay,
                }
            )

        return rows


def extract_mptcp_behavior_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
    link_speed_bps: float = DEFAULT_LINK_SPEED_BPS,
) -> dict:
    """Extract per-MPTCP connection behavior metrics and save them to CSV."""
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_mptcp_behavior.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_mptcp_behavior.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    evaluator = MPTCPBehaviorEvaluator(link_speed_bps=link_speed_bps)
    packet_count = 0
    skipped_non_mptcp = 0
    t_start = time.perf_counter()

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mptcp_packet(packet_bytes)
        if parsed is None:
            skipped_non_mptcp += 1
            continue

        fail_event = _extract_mp_fail_packet(packet_bytes)
        evaluator.evaluate_packet(ts, parsed, fail_event)
        packet_count += 1

        if limit_packets is not None and packet_count >= limit_packets:
            break

    rows = evaluator.build_rows()
    for row in rows:
        row["PCAP File"] = pcap_file_id(pcap_path)

    fieldnames = [
        "PCAP File",
        "MPTCP Connection ID",
        "start_time",
        "end_time",
        "duration",
        "number_of_subflows",
        "number_of_paths",
        "active_path_count",
        "path_switching_count",
        "path_switching_rate",
        "traffic_distribution_ratio",
        "load_balancing_ratio",
        "jain_fairness_index",
        "dominant_path_percentage",
        "path_utilization",
        "path_lifetime",
        "failover_time",
        "recovery_time",
        "path_rejoin_delay",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    elapsed = max(time.perf_counter() - t_start, 1e-9)
    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "skipped_non_mptcp": skipped_non_mptcp,
        "connections": len(rows),
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": elapsed,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract per-MPTCP connection behavior metrics into CSV."
    )
    parser.add_argument("input", help="PCAP file or folder containing PCAP files.")
    parser.add_argument("--output-dir", "-o", default=None, help="Optional directory to save CSV files.")
    parser.add_argument("--limit", "-l", type=int, default=None, help="Maximum number of packets to process per file.")
    parser.add_argument("--link-speed", default="1G", help="Optional interface link speed (e.g. 100M, 1G, 10G).")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if input_path.is_file():
        pcap_files = [input_path]
    elif input_path.is_dir():
        pcap_files = sorted(
            p for p in input_path.rglob("*") if p.is_file() and p.suffix.lower() in PCAP_EXTENSIONS
        )
    else:
        print(f"Error: Path does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    link_speed_bps = parse_link_speed(args.link_speed)

    for pcap in pcap_files:
        result = extract_mptcp_behavior_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
            link_speed_bps=link_speed_bps,
        )
        print(
            f"Processed {pcap.name}: {result['connections']} connections -> {Path(result['csv_file']).name}"
        )
