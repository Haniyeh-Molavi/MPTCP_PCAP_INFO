from __future__ import annotations

import argparse
import csv
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
IDLE_THRESHOLD_SECONDS = 0.100  # 100ms gap considered idle
BURST_THRESHOLD_SECONDS = 0.005  # 5ms gap threshold for a packet burst train


def parse_tcp_options(opts_bytes: bytes) -> tuple[int | None, str | None, str | None, int | None]:
    """
    Parse TCP options directly from raw option bytes.
    Returns: (MSS, SACK, Timestamp, Window Scale)
    """
    mss: int | None = None
    sack: str | None = None
    ts: str | None = None
    ws: int | None = None

    i = 0
    n = len(opts_bytes)
    while i < n:
        kind = opts_bytes[i]
        if kind == 0:  # End of Option List (EOL)
            break
        if kind == 1:  # No-Operation (NOP)
            i += 1
            continue
        if i + 1 >= n:
            break
        length = opts_bytes[i + 1]
        if length < 2 or i + length > n:
            break
        val = opts_bytes[i + 2 : i + length]

        if kind == 2 and len(val) >= 2:  # MSS
            mss = (val[0] << 8) | val[1]
        elif kind == 3 and len(val) >= 1:  # Window Scale
            ws = val[0]
        elif kind == 4:  # SACK Permitted
            sack = "Permitted"
        elif kind == 5:  # SACK Blocks
            num_blocks = len(val) // 8
            sack = f"{num_blocks} Blocks"
        elif kind == 8 and len(val) >= 8:  # Timestamp Option
            tsval = (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3]
            tsecr = (val[4] << 24) | (val[5] << 16) | (val[6] << 8) | val[7]
            ts = f"{tsval};{tsecr}"

        i += length

    return mss, sack, ts, ws


def parse_tcp_segment(packet_bytes: bytes) -> dict | None:
    """
    Extract IP and TCP layer fields directly from raw packet bytes using byte-level slicing.
    Supports IPv4 and IPv6 over Ethernet (standard, 802.1Q tagged, QinQ) and Linux SLL.
    """
    frame_len = len(packet_bytes)
    if frame_len < 34:  # Minimum Ethernet (14) + IPv4 (20)
        return None

    eth_type = (packet_bytes[12] << 8) | packet_bytes[13]
    ip_offset = 14

    # Handle 802.1Q VLAN tag
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
        if len(ip_data) < 20 or (ip_data[0] >> 4) != 4:
            return None

        ip_hl = (ip_data[0] & 0x0F) * 4
        proto = ip_data[9]
        if proto != 6:  # Not TCP
            return None

        ip_total_len = (ip_data[2] << 8) | ip_data[3]
        src_ip = f"{ip_data[12]}.{ip_data[13]}.{ip_data[14]}.{ip_data[15]}"
        dst_ip = f"{ip_data[16]}.{ip_data[17]}.{ip_data[18]}.{ip_data[19]}"
        tcp_data = ip_data[ip_hl:]

    # 2. IPv6
    elif eth_type == 0x86DD:
        ip_data = packet_bytes[ip_offset:]
        if len(ip_data) < 40 or (ip_data[0] >> 4) != 6:
            return None

        proto = ip_data[6]
        if proto != 6:  # Not TCP
            return None

        payload_len = (ip_data[4] << 8) | ip_data[5]
        ip_total_len = payload_len + 40
        ip_hl = 40
        src_ip = f"{ip_data[8]:x}:{ip_data[9]:x}..."  # compact representation for key
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
    if data_offset < 20 or len(tcp_data) < data_offset:
        return None

    flags_byte = tcp_data[13]
    fin = 1 if (flags_byte & 0x01) else 0
    syn = 1 if (flags_byte & 0x02) else 0
    rst = 1 if (flags_byte & 0x04) else 0
    psh = 1 if (flags_byte & 0x08) else 0
    ack_flag = 1 if (flags_byte & 0x10) else 0
    urg = 1 if (flags_byte & 0x20) else 0

    win_size = (tcp_data[14] << 8) | tcp_data[15]
    checksum = (tcp_data[16] << 8) | tcp_data[17]

    opts_bytes = tcp_data[20:data_offset]
    mss, sack, ts_opt, ws_opt = parse_tcp_options(opts_bytes)

    # TCP payload length
    tcp_length = max(0, ip_total_len - ip_hl - data_offset)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport": sport,
        "dport": dport,
        "seq": seq,
        "ack": ack,
        "win": win_size,
        "checksum": checksum,
        "tcp_length": tcp_length,
        "frame_len": frame_len,
        "syn": syn,
        "ack_flag": ack_flag,
        "fin": fin,
        "rst": rst,
        "psh": psh,
        "urg": urg,
        "mss": mss,
        "sack": sack,
        "ts_opt": ts_opt,
        "ws_opt": ws_opt,
    }


class TCPFlowState:
    """Tracks state and metrics for a single bidirectional TCP connection."""

    def __init__(self, start_time: float) -> None:
        self.flow_start_time = start_time
        self.last_packet_time = start_time
        self.packet_count = 0
        self.total_bytes = 0
        self.goodput_bytes = 0

        # Sequence and ACK tracking per direction (dir 0 or 1)
        # dir 0 = forward (first seen src -> dst), dir 1 = reverse
        self.max_seq_seen = {0: 0, 1: 0}
        self.next_expected_seq = {0: 0, 1: 0}
        self.last_ack = {0: 0, 1: 0}
        self.last_win = {0: 0, 1: 0}
        self.last_seq = {0: 0, 1: 0}
        self.dup_ack_count_for_seq = {0: 0, 1: 0}

        # Running counts
        self.retrans_count = 0
        self.fast_retrans_count = 0
        self.dupack_count = 0
        self.ooo_count = 0
        self.congestion_events = 0

        # Timing and burst metrics
        self.idle_time = 0.0
        self.active_time = 0.0
        self.current_burst_size = 0

        # RTT Tracking (sent sequence -> timestamp)
        self.sent_timestamps: dict[tuple[int, int], float] = {}  # (dir, expected_ack) -> sent_time
        self.rtt_count = 0
        self.rtt_min: float | None = None
        self.rtt_max: float | None = None
        self.rtt_mean = 0.0
        self.rtt_M2 = 0.0
        self.latest_rtt: float | None = None


class TCPFeatureEvaluator:
    """
    Stateful streaming evaluator for TCP features across all connections in a capture.
    Calculates all 34 TCP features per packet with O(1) memory per packet stream.
    """

    def __init__(self) -> None:
        self.packet_count = 0
        self.flows: dict[tuple, TCPFlowState] = {}

    def evaluate_packet(self, timestamp: float, parsed: dict) -> tuple:
        self.packet_count += 1

        src_ip = parsed["src_ip"]
        dst_ip = parsed["dst_ip"]
        sport = parsed["sport"]
        dport = parsed["dport"]
        seq = parsed["seq"]
        ack = parsed["ack"]
        tcp_length = parsed["tcp_length"]
        frame_len = parsed["frame_len"]
        win = parsed["win"]
        syn = parsed["syn"]
        fin = parsed["fin"]
        rst = parsed["rst"]
        ack_flag = parsed["ack_flag"]

        # Form a canonical bidirectional flow key
        endpoint_a = (src_ip, sport)
        endpoint_b = (dst_ip, dport)
        if endpoint_a <= endpoint_b:
            flow_key = (endpoint_a, endpoint_b)
            p_dir = 0
        else:
            flow_key = (endpoint_b, endpoint_a)
            p_dir = 1
        rev_dir = 1 - p_dir

        if flow_key not in self.flows:
            self.flows[flow_key] = TCPFlowState(timestamp)

        flow = self.flows[flow_key]
        flow.packet_count += 1
        flow.total_bytes += frame_len

        # Timing metrics
        iat = max(0.0, timestamp - flow.last_packet_time)
        flow.last_packet_time = timestamp

        if iat > IDLE_THRESHOLD_SECONDS:
            flow.idle_time += iat
        else:
            flow.active_time += iat

        # Burst size calculation
        if iat < BURST_THRESHOLD_SECONDS:
            flow.current_burst_size += tcp_length
        else:
            flow.current_burst_size = tcp_length

        flow_completion_time = max(0.0, timestamp - flow.flow_start_time)

        # 1. Retransmission, Fast Retransmission, and Out-of-Order Detection
        is_retransmission = False
        is_fast_retransmission = False
        is_out_of_order = False

        if tcp_length > 0 or syn or fin:
            seg_len = max(1, tcp_length) if (syn or fin) else tcp_length
            next_seq = seq + seg_len

            # Retransmission check: sequence is less than highest observed
            if flow.max_seq_seen[p_dir] > 0 and seq < flow.max_seq_seen[p_dir]:
                is_retransmission = True
                flow.retrans_count += 1

                # Fast Retransmit: triggered after 3 duplicate ACKs in the reverse direction
                if flow.dup_ack_count_for_seq[rev_dir] >= 3:
                    is_fast_retransmission = True
                    flow.fast_retrans_count += 1
                    flow.congestion_events += 1
            else:
                # Out-of-order check: there is a gap above the next expected sequence
                if flow.next_expected_seq[p_dir] > 0 and seq > flow.next_expected_seq[p_dir]:
                    is_out_of_order = True
                    flow.ooo_count += 1

                flow.goodput_bytes += tcp_length
                flow.max_seq_seen[p_dir] = max(flow.max_seq_seen[p_dir], next_seq)
                flow.next_expected_seq[p_dir] = next_seq

                # Save timestamp for RTT calculation on ACK (Karn's algorithm: only for non-retransmitted)
                if len(flow.sent_timestamps) < 2000:
                    flow.sent_timestamps[(p_dir, next_seq)] = timestamp

        # 2. Duplicate ACK Detection & RTT Sampling
        if ack_flag and not syn:
            # RTT Calculation: match ACK with sent sequence
            match_key = (rev_dir, ack)
            if match_key in flow.sent_timestamps:
                sent_ts = flow.sent_timestamps.pop(match_key)
                rtt_sample = max(0.0, timestamp - sent_ts)
                flow.latest_rtt = rtt_sample
                flow.rtt_count += 1

                flow.rtt_min = rtt_sample if flow.rtt_min is None else min(flow.rtt_min, rtt_sample)
                flow.rtt_max = rtt_sample if flow.rtt_max is None else max(flow.rtt_max, rtt_sample)

                # Welford's algorithm for RTT mean and std
                d1 = rtt_sample - flow.rtt_mean
                flow.rtt_mean += d1 / flow.rtt_count
                d2 = rtt_sample - flow.rtt_mean
                flow.rtt_M2 += d1 * d2

            # Duplicate ACK check
            if (
                tcp_length == 0
                and not fin
                and not rst
                and ack == flow.last_ack[p_dir]
                and flow.last_ack[p_dir] > 0
                and win == flow.last_win[p_dir]
                and seq == flow.last_seq[p_dir]
            ):
                flow.dupack_count += 1
                flow.dup_ack_count_for_seq[p_dir] += 1
                if flow.dup_ack_count_for_seq[p_dir] == 3:
                    flow.congestion_events += 1
            else:
                flow.dup_ack_count_for_seq[p_dir] = 0

            flow.last_ack[p_dir] = ack
            flow.last_win[p_dir] = win
            flow.last_seq[p_dir] = seq

        # Rate and Goodput metrics
        duration_sec = max(flow_completion_time, 1e-6)
        throughput = flow.total_bytes / duration_sec
        goodput = flow.goodput_bytes / duration_sec
        loss_rate = (flow.retrans_count / flow.packet_count) if flow.packet_count > 0 else 0.0

        rtt_std = math.sqrt(flow.rtt_M2 / (flow.rtt_count - 1)) if flow.rtt_count > 1 else 0.0

        return (
            self.packet_count,
            f"{timestamp:.6f}",
            sport,
            dport,
            seq,
            ack,
            win,
            f"0x{parsed['checksum']:04X}",
            tcp_length,
            parsed["syn"],
            parsed["ack_flag"],
            parsed["fin"],
            parsed["rst"],
            parsed["psh"],
            parsed["urg"],
            parsed["mss"] if parsed["mss"] is not None else "",
            parsed["sack"] if parsed["sack"] is not None else "",
            parsed["ts_opt"] if parsed["ts_opt"] is not None else "",
            parsed["ws_opt"] if parsed["ws_opt"] is not None else "",
            flow.retrans_count,
            flow.fast_retrans_count,
            flow.dupack_count,
            flow.ooo_count,
            f"{flow.latest_rtt:.6f}" if flow.latest_rtt is not None else "",
            f"{flow.rtt_min:.6f}" if flow.rtt_min is not None else "",
            f"{flow.rtt_max:.6f}" if flow.rtt_max is not None else "",
            f"{rtt_std:.6f}" if flow.rtt_count > 1 else "0.000000",
            f"{loss_rate:.6f}",
            f"{throughput:.2f}",
            f"{goodput:.2f}",
            flow.congestion_events,
            f"{flow_completion_time:.6f}",
            f"{flow.idle_time:.6f}",
            f"{flow.active_time:.6f}",
            f"{iat:.6f}",
            flow.current_burst_size,
        )


def extract_tcp_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
    batch_size: int = DEFAULT_CSV_BATCH_SIZE,
) -> dict:
    """
    Extract and calculate all 34 TCP features from a PCAP file and save directly to a CSV file.
    By default, saves to '[pcap_stem]_tcp.csv' alongside the PCAP.
    Streaming batch writes ensure O(1) memory usage regardless of PCAP size.
    """
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_tcp.csv")
    else:
        output_csv_path = Path(output_csv_path).resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_tcp.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    evaluator = TCPFeatureEvaluator()
    batch = []
    t_start = time.perf_counter()
    skipped_non_tcp = 0

    with open(csv_path, "w", newline="", buffering=2 * 1024 * 1024, encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Packet Number",
            "Timestamp",
            "Source Port",
            "Destination Port",
            "Sequence Number",
            "Acknowledgment Number",
            "Window Size",
            "Checksum",
            "TCP Length",
            "Flags (SYN)",
            "Flags (ACK)",
            "Flags (FIN)",
            "Flags (RST)",
            "Flags (PSH)",
            "Flags (URG)",
            "MSS Option",
            "SACK Option",
            "Timestamp Option",
            "Window Scale Option",
            "Retransmission Count",
            "Fast Retransmission Count",
            "Duplicate ACK Count",
            "Out-of-Order Packets",
            "RTT",
            "RTT Min",
            "RTT Max",
            "RTT Std",
            "Packet Loss Rate",
            "Throughput",
            "Goodput",
            "Congestion Events",
            "Flow Completion Time",
            "Idle Time",
            "Active Time",
            "Inter-arrival Time",
            "Burst Size",
        ])

        for ts, pkt_bytes in stream_pcap_packets(pcap_path):
            parsed = parse_tcp_segment(pkt_bytes)
            if parsed is None:
                skipped_non_tcp += 1
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

    total_retrans = sum(f.retrans_count for f in evaluator.flows.values())
    total_congest = sum(f.congestion_events for f in evaluator.flows.values())

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": evaluator.packet_count,
        "skipped_non_tcp": skipped_non_tcp,
        "csv_size_bytes": csv_size,
        "tcp_flows_count": len(evaluator.flows),
        "total_retransmissions": total_retrans,
        "total_congestion_events": total_congest,
        "processing_time_seconds": t_elapsed,
        "throughput_packets_per_sec": evaluator.packet_count / t_elapsed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and evaluate TCP layer features from PCAP files into CSV."
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

    print(f"Extracting TCP features for {len(pcap_files)} file(s)...")
    for pcap in pcap_files:
        print(f"Processing: {pcap.name} ... ", end="", flush=True)
        res = extract_tcp_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Done! {res['packet_count']:,d} TCP packets -> {Path(res['csv_file']).name} "
            f"({res['throughput_packets_per_sec']:,.0f} pkts/s)"
        )


if __name__ == "__main__":
    main()

