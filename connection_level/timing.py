from __future__ import annotations

import csv
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
        from protocol_layer.ethernet import stream_pcap_packets
        from protocol_layer.mptcp_level import compute_mptcp_token, parse_mptcp_packet
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


class ConnectionTimingState:
    def __init__(self, connection_id: str, start_ts: float) -> None:
        self.connection_id = connection_id
        self.connection_start_time = start_ts
        self.connection_end_time = start_ts
        self.first_data_time: float | None = None
        self.last_data_time: float | None = None

    def update(self, ts: float, parsed: dict) -> None:
        self.connection_end_time = max(self.connection_end_time, ts)

        data_len = parsed.get("data_len", 0) or 0
        if data_len > 0:
            if self.first_data_time is None:
                self.first_data_time = ts
            self.last_data_time = ts


def _resolve_connection_id(parsed: dict, token_to_conn: dict[str, str], endpoint_to_conn: dict[tuple[str, int, str, int], str], next_index: int) -> tuple[str, int]:
    sender_key = parsed.get("sender_key")
    receiver_key = parsed.get("receiver_key")

    if sender_key:
        token = compute_mptcp_token(sender_key)
        if token:
            if token not in token_to_conn:
                token_to_conn[token] = token
            return token, next_index

    if receiver_key:
        token = compute_mptcp_token(receiver_key)
        if token:
            if token not in token_to_conn:
                token_to_conn[token] = token
            return token, next_index

    endpoint_key = (
        parsed["src_ip"],
        parsed["sport"],
        parsed["dst_ip"],
        parsed["dport"],
    )
    existing = endpoint_to_conn.get(endpoint_key)
    if existing:
        return existing, next_index

    new_conn_id = f"conn_{next_index}"
    endpoint_to_conn[endpoint_key] = new_conn_id
    return new_conn_id, next_index + 1


def extract_connection_timing_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """
    Extract per-connection timing metrics from a PCAP file and save the result as
    '<pcap_stem>_connection_timing.csv'.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_connection_timing.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_connection_timing.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    connections: dict[str, ConnectionTimingState] = {}
    token_to_conn: dict[str, str] = {}
    endpoint_to_conn: dict[tuple[str, int, str, int], str] = {}
    next_index = 1
    packet_count = 0
    t_start = time.perf_counter()

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mptcp_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1

        endpoint_key = (
            parsed["src_ip"],
            parsed["sport"],
            parsed["dst_ip"],
            parsed["dport"],
        )

        conn_id, next_index = _resolve_connection_id(
            parsed=parsed,
            token_to_conn=token_to_conn,
            endpoint_to_conn=endpoint_to_conn,
            next_index=next_index,
        )

        if conn_id not in connections:
            connections[conn_id] = ConnectionTimingState(connection_id=conn_id, start_ts=ts)

        state = connections[conn_id]
        state.update(ts, parsed)
        endpoint_to_conn[endpoint_key] = conn_id

        if limit_packets is not None and packet_count >= limit_packets:
            break

    rows = []
    for state in sorted(connections.values(), key=lambda item: (item.connection_start_time, item.connection_id)):
        connection_duration = max(state.connection_end_time - state.connection_start_time, 0.0)
        first_data_time = state.first_data_time if state.first_data_time is not None else ""
        last_data_time = state.last_data_time if state.last_data_time is not None else ""
        data_transfer_duration = ""
        if state.first_data_time is not None and state.last_data_time is not None:
            data_transfer_duration = max(state.last_data_time - state.first_data_time, 0.0)

        rows.append(
            {
                "pcap_file": pcap_path.name,
                "mptcp_connection_id": state.connection_id,
                "connection_start_time": f"{state.connection_start_time:.6f}",
                "connection_end_time": f"{state.connection_end_time:.6f}",
                "connection_duration": f"{connection_duration:.6f}",
                "first_data_time": f"{first_data_time:.6f}" if first_data_time != "" else "",
                "last_data_time": f"{last_data_time:.6f}" if last_data_time != "" else "",
                "data_transfer_duration": f"{data_transfer_duration:.6f}" if data_transfer_duration != "" else "",
            }
        )

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "MPTCP Connection ID",
            "Connection Start Time",
            "Connection End Time",
            "Connection Duration",
            "First Data Time",
            "Last Data Time",
            "Data Transfer Duration",
        ])

        for row in rows:
            writer.writerow([
                row["pcap_file"],
                row["mptcp_connection_id"],
                row["connection_start_time"],
                row["connection_end_time"],
                row["connection_duration"],
                row["first_data_time"],
                row["last_data_time"],
                row["data_transfer_duration"],
            ])

    elapsed = max(time.perf_counter() - t_start, 1e-9)
    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "connection_count": len(rows),
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": elapsed,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract per-connection timing metrics from one or more PCAP files into CSV."
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
        pcap_files = [input_path]
    elif input_path.is_dir():
        pcap_files = sorted(
            p for p in input_path.rglob("*") if p.is_file() and p.suffix.lower() in PCAP_EXTENSIONS
        )
    else:
        print(f"Error: Path does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)

    if not pcap_files:
        print(f"No PCAP files found in: {input_path}")
        return

    for pcap in pcap_files:
        result = extract_connection_timing_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Processed {pcap.name}: {result['connection_count']} connection(s) -> {result['csv_file']}"
        )


if __name__ == "__main__":
    main()
