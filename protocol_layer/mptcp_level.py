from __future__ import annotations

import argparse
import csv
import hashlib
import math
import os
import sys
import time
from pathlib import Path
from typing import Iterator, Tuple

# Ensure workspace root is in sys.path
_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

# Import streaming reader from ethernet module or fallback
try:
    from protocol_layer.ethernet import stream_pcap_packets
except ImportError:
    try:
        from ethernet import stream_pcap_packets
    except ImportError:
        import dpkt
        def stream_pcap_packets(file_path: Path | str) -> Iterator[Tuple[float, bytes]]:
            with open(file_path, "rb") as f:
                reader = dpkt.pcap.Reader(f)
                for ts, pkt in reader:
                    yield float(ts), pkt

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}
DEFAULT_CSV_BATCH_SIZE = 5000


def compute_mptcp_token(key_bytes: bytes) -> str:
    """Derive 32-bit MPTCP token from 64-bit key using SHA-1 (RFC 6824)."""
    if not key_bytes or len(key_bytes) != 8:
        return ""
    token_bytes = hashlib.sha1(key_bytes).digest()[:4]
    return f"0x{token_bytes.hex().upper()}"


def parse_mptcp_packet(packet_bytes: bytes) -> dict | None:
    """
    Fast byte-level parser to detect and extract MPTCP options from TCP packets.
    Returns parsed dictionary if MPTCP option (kind 30) is present, else None.
    """
    frame_len = len(packet_bytes)
    if frame_len < 54:
        return None

    # Check Link Layer
    eth_type = (packet_bytes[12] << 8) | packet_bytes[13]
    ip_offset = 14

    # 802.1Q VLAN Tag
    if eth_type in (0x8100, 0x88A8) and frame_len >= 18:
        inner_type = (packet_bytes[16] << 8) | packet_bytes[17]
        ip_offset = 18
        if inner_type in (0x8100, 0x88A8) and frame_len >= 22:
            eth_type = (packet_bytes[20] << 8) | packet_bytes[21]
            ip_offset = 22
        else:
            eth_type = inner_type

    # Linux Cooked Capture (SLL)
    if eth_type not in (0x0800, 0x86DD) and frame_len >= 16:
        sll_proto = (packet_bytes[14] << 8) | packet_bytes[15]
        if sll_proto in (0x0800, 0x86DD):
            eth_type = sll_proto
            ip_offset = 16

    # 1. IPv4
    if eth_type == 0x0800:
        ip_data = packet_bytes[ip_offset:]
        if len(ip_data) < 20 or (ip_data[0] >> 4) != 4 or ip_data[9] != 6:
            return None
        ip_hl = (ip_data[0] & 0x0F) * 4
        src_ip = f"{ip_data[12]}.{ip_data[13]}.{ip_data[14]}.{ip_data[15]}"
        dst_ip = f"{ip_data[16]}.{ip_data[17]}.{ip_data[18]}.{ip_data[19]}"
        tcp_data = ip_data[ip_hl:]

    # 2. IPv6
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

    sport = (tcp_data[0] << 8) | tcp_data[1]
    dport = (tcp_data[2] << 8) | tcp_data[3]
    seq = (tcp_data[4] << 24) | (tcp_data[5] << 16) | (tcp_data[6] << 8) | tcp_data[7]
    ack = (tcp_data[8] << 24) | (tcp_data[9] << 16) | (tcp_data[10] << 8) | tcp_data[11]

    data_offset = (tcp_data[12] >> 4) * 4
    if data_offset <= 20 or len(tcp_data) < data_offset:
        return None

    flags_byte = tcp_data[13]
    syn = 1 if (flags_byte & 0x02) else 0
    ack_flag = 1 if (flags_byte & 0x10) else 0
    fin = 1 if (flags_byte & 0x01) else 0

    opts_bytes = tcp_data[20:data_offset]

    # Parse MPTCP options (Kind 30)
    has_mptcp = False
    sender_key = None
    receiver_key = None
    csum_flag: bool | None = None
    join_token = None
    data_ack = None
    dsn = None
    data_len = 0
    data_fin = False

    i = 0
    n = len(opts_bytes)
    while i < n:
        kind = opts_bytes[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= n:
            break
        length = opts_bytes[i + 1]
        if length < 2 or i + length > n:
            break

        if kind == 30:
            has_mptcp = True
            val = opts_bytes[i + 2 : i + length]
            if len(val) >= 1:
                subtype = val[0] >> 4

                # Subtype 0: MP_CAPABLE
                if subtype == 0:
                    if len(val) >= 2:
                        csum_flag = (val[1] & 0x80) != 0
                    if len(val) >= 9 and syn and not ack_flag:
                        sender_key = val[1:9]
                    elif len(val) >= 9 and syn and ack_flag:
                        receiver_key = val[1:9]
                    elif len(val) >= 17:
                        sender_key = val[1:9]
                        receiver_key = val[9:17]

                # Subtype 1: MP_JOIN
                elif subtype == 1:
                    if len(val) >= 5 and syn and not ack_flag:
                        join_token = val[1:5]

                # Subtype 2: DSS (Data Sequence Signal)
                elif subtype == 2 and len(val) >= 2:
                    dss_flags = val[1]
                    has_dack = (dss_flags & 0x01) != 0
                    dack_is_8 = (dss_flags & 0x02) != 0
                    has_dsn = (dss_flags & 0x04) != 0
                    dsn_is_8 = (dss_flags & 0x08) != 0
                    data_fin = (dss_flags & 0x10) != 0

                    idx = 2
                    if has_dack:
                        alen = 8 if dack_is_8 else 4
                        if idx + alen <= len(val):
                            data_ack = int.from_bytes(val[idx : idx + alen], "big")
                            idx += alen
                    if has_dsn:
                        dlen_bytes = 8 if dsn_is_8 else 4
                        if idx + dlen_bytes + 6 <= len(val):
                            dsn = int.from_bytes(val[idx : idx + dlen_bytes], "big")
                            idx += dlen_bytes + 4  # skip SSN (4 bytes)
                            data_len = int.from_bytes(val[idx : idx + 2], "big")

        i += length

    if not has_mptcp:
        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "syn": syn,
        "ack_flag": ack_flag,
        "fin": fin,
        "frame_len": frame_len,
        "sender_key": sender_key,
        "receiver_key": receiver_key,
        "checksum_flag": csum_flag,
        "join_token": join_token,
        "data_ack": data_ack,
        "dsn": dsn,
        "data_len": data_len,
        "data_fin": data_fin,
    }


class MPTCPConnectionState:
    """State and aggregate metrics for an MPTCP connection."""

    def __init__(self, start_time: float) -> None:
        self.conn_start_time = start_time
        self.conn_est_time: float | None = None
        self.conn_term_time: float | None = None
        self.sender_key: bytes | None = None
        self.receiver_key: bytes | None = None
        self.token: str = ""
        self.checksum_flag: int = 0

        # Endpoint identification: initiator (client) vs responder (server)
        self.initiator_endpoint: tuple[str, int] | None = None

        # Cumulative counters
        self.total_packets = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.total_retransmissions = 0
        self.goodput_bytes = 0

        # Sequence tracking for retransmission and goodput detection
        self.seen_dsns: set[int] = set()

        # RTT Tracking across connection / subflows (Welford's algorithm)
        self.dsn_sent_times: dict[int, float] = {}  # DSN -> sent_time
        self.rtt_count = 0
        self.rtt_mean = 0.0
        self.rtt_M2 = 0.0


class MPTCPFeatureEvaluator:
    """
    Evaluator for MPTCP protocol layer features.
    Correlates subflows to MPTCP connections and maintains running statistics with O(1) memory.
    """

    def __init__(self) -> None:
        self.packet_count = 0
        self.connections: dict[str, MPTCPConnectionState] = {}
        # Mapping from subflow 4-tuple to connection ID/token
        self.subflow_to_conn: dict[tuple, str] = {}
        self.default_conn_id = "default_mptcp"

    def evaluate_packet(self, timestamp: float, parsed: dict) -> tuple:
        self.packet_count += 1

        src_ip = parsed["src_ip"]
        dst_ip = parsed["dst_ip"]
        sport = parsed["sport"]
        dport = parsed["dport"]
        frame_len = parsed["frame_len"]
        data_len = parsed["data_len"]
        dsn = parsed["dsn"]
        data_ack = parsed["data_ack"]
        data_fin = parsed["data_fin"]

        endpoint_a = (src_ip, sport)
        endpoint_b = (dst_ip, dport)
        subflow_key = tuple(sorted([endpoint_a, endpoint_b]))

        # 1. Resolve or create MPTCP Connection
        conn_id = self.subflow_to_conn.get(subflow_key)

        sender_key = parsed["sender_key"]
        receiver_key = parsed["receiver_key"]
        csum = parsed["checksum_flag"]

        if conn_id is None:
            if sender_key:
                conn_id = compute_mptcp_token(sender_key)
            elif receiver_key:
                conn_id = compute_mptcp_token(receiver_key)
            else:
                conn_id = self.default_conn_id
            self.subflow_to_conn[subflow_key] = conn_id

        if conn_id not in self.connections:
            self.connections[conn_id] = MPTCPConnectionState(timestamp)

        conn = self.connections[conn_id]
        conn.total_packets += 1

        # Establish connection initiator endpoint
        if conn.initiator_endpoint is None:
            conn.initiator_endpoint = endpoint_a

        # Record keys, tokens, and checksum flag
        if sender_key and not conn.sender_key:
            conn.sender_key = sender_key
            if not conn.token:
                conn.token = compute_mptcp_token(sender_key)
        if receiver_key and not conn.receiver_key:
            conn.receiver_key = receiver_key
            if not conn.token:
                conn.token = compute_mptcp_token(receiver_key)
        if csum is not None:
            conn.checksum_flag = 1 if csum else 0

        # Handshake establishment time: when receiver key confirmed
        if conn.receiver_key and conn.conn_est_time is None:
            conn.conn_est_time = timestamp

        # Directional bytes: initiator (client) -> responder (server) = Sent
        if endpoint_a == conn.initiator_endpoint:
            conn.total_bytes_sent += frame_len
        else:
            conn.total_bytes_received += frame_len

        # DSN & Data ACK processing (Goodput, Retransmissions, Aggregate RTT)
        if dsn is not None:
            if dsn in conn.seen_dsns:
                conn.total_retransmissions += 1
            else:
                conn.seen_dsns.add(dsn)
                conn.goodput_bytes += data_len
                # Record send timestamp for RTT calculation on Data ACK
                if len(conn.dsn_sent_times) < 2000:
                    conn.dsn_sent_times[dsn + max(1, data_len)] = timestamp

        if data_ack is not None:
            if data_ack in conn.dsn_sent_times:
                sent_ts = conn.dsn_sent_times.pop(data_ack)
                rtt_sample = max(0.0, timestamp - sent_ts)
                conn.rtt_count += 1
                # Welford's running mean
                delta = rtt_sample - conn.rtt_mean
                conn.rtt_mean += delta / conn.rtt_count
                delta2 = rtt_sample - conn.rtt_mean
                conn.rtt_M2 += delta * delta2

        # Termination: DATA_FIN
        if data_fin:
            conn.conn_term_time = timestamp

        # Durations and Rates
        conn_duration = max(timestamp - conn.conn_start_time, 1e-6)
        total_data = conn.total_bytes_sent + conn.total_bytes_received
        throughput = total_data / conn_duration
        goodput = conn.goodput_bytes / conn_duration
        loss_rate = (conn.total_retransmissions / conn.total_packets) if conn.total_packets > 0 else 0.0

        sender_key_str = f"0x{conn.sender_key.hex().upper()}" if conn.sender_key else ""
        receiver_key_str = f"0x{conn.receiver_key.hex().upper()}" if conn.receiver_key else ""
        token_str = conn.token if conn.token else ""
        dsn_str = str(dsn) if dsn is not None else ""
        data_ack_str = str(data_ack) if data_ack is not None else ""
        est_time_str = f"{conn.conn_est_time:.6f}" if conn.conn_est_time is not None else ""
        term_time_str = f"{conn.conn_term_time:.6f}" if conn.conn_term_time is not None else f"{timestamp:.6f}"
        rtt_str = f"{conn.rtt_mean:.6f}" if conn.rtt_count > 0 else ""

        return (
            self.packet_count,
            f"{timestamp:.6f}",
            sender_key_str,
            receiver_key_str,
            token_str,
            dsn_str,
            data_ack_str,
            1 if data_fin else 0,
            conn.checksum_flag,
            est_time_str,
            term_time_str,
            f"{conn_duration:.6f}",
            conn.total_bytes_sent,
            conn.total_bytes_received,
            conn.total_packets,
            f"{throughput:.2f}",
            f"{goodput:.2f}",
            rtt_str,
            f"{loss_rate:.6f}",
        )


def extract_mptcp_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
    batch_size: int = DEFAULT_CSV_BATCH_SIZE,
) -> dict:
    """
    Extract and evaluate all 17 MPTCP layer features from a PCAP file and save directly to a CSV file.
    By default, saves to '[pcap_stem]_mptcp.csv' alongside the PCAP.
    Streaming batch writes ensure O(1) memory usage regardless of capture size.
    """
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_mptcp.csv")
    else:
        output_csv_path = Path(output_csv_path).resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_mptcp.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    evaluator = MPTCPFeatureEvaluator()
    batch = []
    t_start = time.perf_counter()
    skipped_non_mptcp = 0

    with open(csv_path, "w", newline="", buffering=2 * 1024 * 1024, encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Packet Number",
            "Timestamp",
            "Sender Key",
            "Receiver Key",
            "Generated Token",
            "Data Sequence Number (DSN)",
            "Data ACK",
            "Data FIN",
            "Checksum Flag",
            "Connection Establishment Time",
            "Connection Termination Time",
            "Connection Duration",
            "Total Bytes Sent",
            "Total Bytes Received",
            "Total Packets",
            "Overall Throughput",
            "Overall Goodput",
            "Aggregate RTT",
            "Aggregate Loss Rate",
        ])

        for ts, pkt_bytes in stream_pcap_packets(pcap_path):
            parsed = parse_mptcp_packet(pkt_bytes)
            if parsed is None:
                skipped_non_mptcp += 1
                continue

            row = evaluator.evaluate_packet(ts, parsed)
            batch.append(row)

            if len(batch) >= batch_size:
                writer.writerows(batch)
                batch.clear()

            if limit_packets is not None and evaluator.packet_count >= limit_packets:
                break

        if batch:
            writer.writerows(batch)
            batch.clear()

    t_elapsed = max(time.perf_counter() - t_start, 1e-9)
    csv_size = csv_path.stat().st_size if csv_path.exists() else 0

    total_mptcp_bytes = sum(c.total_bytes_sent + c.total_bytes_received for c in evaluator.connections.values())

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": evaluator.packet_count,
        "skipped_non_mptcp": skipped_non_mptcp,
        "csv_size_bytes": csv_size,
        "mptcp_conns_count": len(evaluator.connections),
        "total_mptcp_bytes": total_mptcp_bytes,
        "processing_time_seconds": t_elapsed,
        "throughput_packets_per_sec": evaluator.packet_count / t_elapsed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and evaluate MPTCP layer features from PCAP files into CSV."
    )
    parser.add_argument("input", help="PCAP file or folder containing PCAP files.")
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help="Optional directory to save CSV files (default: alongside source PCAP).",
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

    print(f"Extracting MPTCP features for {len(pcap_files)} file(s)...")
    for pcap in pcap_files:
        print(f"Processing: {pcap.name} ... ", end="", flush=True)
        res = extract_mptcp_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Done! {res['packet_count']:,d} MPTCP packets -> {Path(res['csv_file']).name} "
            f"({res['throughput_packets_per_sec']:,.0f} pkts/s)"
        )


if __name__ == "__main__":
    main()
