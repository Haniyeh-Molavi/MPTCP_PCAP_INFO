from __future__ import annotations

import csv
import math
import sys
import time
from pathlib import Path

# Ensure workspace root is in sys.path
_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

try:
    from protocol_layer.ethernet import stream_pcap_packets
    from protocol_layer.mptcp_level import compute_mptcp_token, parse_mptcp_packet
except ImportError:
    try:
        from ethernet import stream_pcap_packets
        from mptcp_level import compute_mptcp_token, parse_mptcp_packet
    except ImportError:
        import dpkt

        def stream_pcap_packets(file_path: Path | str):
            with open(file_path, "rb") as f:
                reader = dpkt.pcap.Reader(f)
                for ts, pkt in reader:
                    yield float(ts), pkt

        def parse_mptcp_packet(packet_bytes: bytes):
            return None

        def compute_mptcp_token(key_bytes: bytes) -> str:
            return ""


PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


class SubflowState:
    """Aggregate stats for one subflow within an MPTCP connection."""

    def __init__(self, connection_id: str, src_ip: str, dst_ip: str, sport: int, dport: int, first_ts: float):
        self.connection_id = connection_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.first_ts = first_ts
        self.last_ts = first_ts
        self.packet_count = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.retransmissions = 0
        self.congestion_events = 0
        self.goodput_bytes = 0
        self.seen_dsns: set[int] = set()
        self.sent_dsn_times: dict[int, float] = {}
        self.rtt_samples: list[float] = []

    def update(self, parsed: dict, ts: float) -> None:
        self.packet_count += 1
        self.last_ts = ts

        packet_is_forward = (
            parsed["src_ip"] == self.src_ip
            and parsed["sport"] == self.sport
            and parsed["dst_ip"] == self.dst_ip
            and parsed["dport"] == self.dport
        )

        if packet_is_forward:
            self.bytes_sent += parsed.get("frame_len", 0)
        else:
            self.bytes_received += parsed.get("frame_len", 0)

        dsn = parsed.get("dsn")
        data_len = parsed.get("data_len", 0)
        if dsn is not None:
            if dsn in self.seen_dsns:
                self.retransmissions += 1
                self.congestion_events += 1
            else:
                self.seen_dsns.add(dsn)
                self.goodput_bytes += max(data_len, 0)
            self.sent_dsn_times[dsn] = ts

        data_ack = parsed.get("data_ack")
        if data_ack is not None and data_ack in self.sent_dsn_times:
            sent_ts = self.sent_dsn_times.pop(data_ack)
            rtt = max(ts - sent_ts, 0.0)
            self.rtt_samples.append(rtt)


def _canonical_subflow_key(src_ip: str, sport: int, dst_ip: str, dport: int) -> tuple[str, int, str, int]:
    endpoint_a = (src_ip, sport)
    endpoint_b = (dst_ip, dport)
    return tuple(sorted((endpoint_a, endpoint_b)))  # type: ignore[return-value]


def _resolve_connection_id(parsed: dict, known_connections: dict[str, str], next_connection_index: int) -> tuple[str, int]:
    sender_key = parsed.get("sender_key")
    receiver_key = parsed.get("receiver_key")

    if sender_key:
        conn_id = compute_mptcp_token(sender_key)
        if conn_id:
            known_connections[conn_id] = conn_id
            return conn_id, next_connection_index

    if receiver_key:
        conn_id = compute_mptcp_token(receiver_key)
        if conn_id:
            known_connections[conn_id] = conn_id
            return conn_id, next_connection_index

    default_conn_id = f"conn_{next_connection_index}"
    known_connections[default_conn_id] = default_conn_id
    return default_conn_id, next_connection_index + 1


def _subflow_id(connection_id: str, src_ip: str, sport: int, dst_ip: str, dport: int) -> str:
    return f"{connection_id}:{src_ip}:{sport}->{dst_ip}:{dport}"


def extract_subflow_level_statistics_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """
    Extract per-subflow MPTCP statistics from a PCAP and save the result as
    '<pcap_stem>_subflows.csv'.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_subflows.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_subflows.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    subflows: dict[tuple[str, tuple[str, int, str, int]], SubflowState] = {}
    connection_ids: dict[str, str] = {}
    ip_to_conn: dict[tuple[str, int, str, int], str] = {}
    next_connection_index = 1
    packet_count = 0
    t_start = time.perf_counter()
    first_ts_seen = None
    last_ts_seen = None

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mptcp_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        if first_ts_seen is None:
            first_ts_seen = ts
        last_ts_seen = ts

        # Resolve or create a connection ID for this packet.
        subflow_key = _canonical_subflow_key(parsed["src_ip"], parsed["sport"], parsed["dst_ip"], parsed["dport"])
        endpoint_key = (parsed["src_ip"], parsed["sport"], parsed["dst_ip"], parsed["dport"])
        connection_id = ip_to_conn.get(subflow_key)

        if connection_id is None:
            connection_id, next_connection_index = _resolve_connection_id(parsed, connection_ids, next_connection_index)
            ip_to_conn[subflow_key] = connection_id

        state_key = (connection_id, subflow_key)
        state = subflows.get(state_key)
        if state is None:
            state = SubflowState(
                connection_id=connection_id,
                src_ip=parsed["src_ip"],
                dst_ip=parsed["dst_ip"],
                sport=parsed["sport"],
                dport=parsed["dport"],
                first_ts=ts,
            )
            subflows[state_key] = state

        state.update(parsed, ts)

        if limit_packets is not None and packet_count >= limit_packets:
            break

    rows = []
    for (connection_id, _), state in sorted(subflows.items(), key=lambda item: (item[0][0], item[1].src_ip, item[1].dst_ip, item[1].sport, item[1].dport)):
        lifetime = max(state.last_ts - state.first_ts, 0.0)
        duration = max(lifetime, 1e-6)

        if state.rtt_samples:
            mean_rtt = sum(state.rtt_samples) / len(state.rtt_samples)
            rtt_variance = sum((sample - mean_rtt) ** 2 for sample in state.rtt_samples) / len(state.rtt_samples)
            if len(state.rtt_samples) > 1:
                jitter = sum(abs(state.rtt_samples[i] - state.rtt_samples[i - 1]) for i in range(1, len(state.rtt_samples))) / (len(state.rtt_samples) - 1)
            else:
                jitter = 0.0
        else:
            mean_rtt = 0.0
            rtt_variance = 0.0
            jitter = 0.0

        throughput = (state.bytes_sent + state.bytes_received) / duration
        goodput = state.goodput_bytes / duration
        loss_rate = state.retransmissions / max(state.packet_count, 1)
        utilization_ratio = throughput / 1_000_000.0

        rows.append(
            {
                "pcap_file": pcap_path.name,
                "mptcp_connection_id": connection_id,
                "subflow_id": _subflow_id(connection_id, state.src_ip, state.sport, state.dst_ip, state.dport),
                "source_ip": state.src_ip,
                "destination_ip": state.dst_ip,
                "source_port": state.sport,
                "destination_port": state.dport,
                "rtt": mean_rtt,
                "rtt_variance": rtt_variance,
                "jitter": jitter,
                "loss_rate": loss_rate,
                "retransmissions": state.retransmissions,
                "congestion_events": state.congestion_events,
                "bytes_sent": state.bytes_sent,
                "bytes_received": state.bytes_received,
                "packet_count": state.packet_count,
                "throughput": throughput,
                "goodput": goodput,
                "utilization_ratio": utilization_ratio,
                "lifetime": lifetime,
                "idle_time": 0.0,
                "active_time": lifetime,
            }
        )

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "MPTCP Connection ID",
            "Subflow ID",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "RTT",
            "RTT Variance",
            "Jitter",
            "Loss Rate",
            "Retransmissions",
            "Congestion Events",
            "Bytes Sent",
            "Bytes Received",
            "Packet Count",
            "Throughput",
            "Goodput",
            "Utilization Ratio",
            "Lifetime",
            "Idle Time",
            "Active Time",
        ])

        for row in rows:
            writer.writerow([
                row["pcap_file"],
                row["mptcp_connection_id"],
                row["subflow_id"],
                row["source_ip"],
                row["destination_ip"],
                row["source_port"],
                row["destination_port"],
                f"{row['rtt']:.6f}",
                f"{row['rtt_variance']:.6f}",
                f"{row['jitter']:.6f}",
                f"{row['loss_rate']:.6f}",
                row["retransmissions"],
                row["congestion_events"],
                row["bytes_sent"],
                row["bytes_received"],
                row["packet_count"],
                f"{row['throughput']:.6f}",
                f"{row['goodput']:.6f}",
                f"{row['utilization_ratio']:.6f}",
                f"{row['lifetime']:.6f}",
                f"{row['idle_time']:.6f}",
                f"{row['active_time']:.6f}",
            ])

    elapsed = max(time.perf_counter() - t_start, 1e-9)
    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "subflow_count": len(rows),
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": elapsed,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract per-subflow MPTCP statistics from one or more PCAP files into CSV."
    )
    parser.add_argument("input", help="PCAP file or folder containing PCAP files.")
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help="Optional directory to save CSV files (default: alongside the source PCAP).",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=None,
        help="Maximum number of packets to process per file.",
    )
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()

    if input_path.is_file():
        paths = [input_path]
    elif input_path.is_dir():
        paths = sorted(
            p for p in input_path.rglob("*") if p.is_file() and p.suffix.lower() in PCAP_EXTENSIONS
        )
    else:
        raise FileNotFoundError(f"Input path not found: {input_path}")

    for pcap_path in paths:
        extract_subflow_level_statistics_to_csv(
            pcap_path=pcap_path,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )


if __name__ == "__main__":
    main()
