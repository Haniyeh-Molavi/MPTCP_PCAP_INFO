from __future__ import annotations

import argparse
import csv
import os
import socket
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


def parse_ip_packet(packet_bytes: bytes) -> dict | None:
    """
    Extract IP Layer features directly from raw packet bytes using byte-level slicing
    for maximum throughput and zero object-allocation overhead.
    Supports IPv4 and IPv6 over Ethernet (standard, 802.1Q tagged, QinQ) and Linux SLL.
    """
    frame_len = len(packet_bytes)
    if frame_len < 14:
        return None

    # Check Link Layer
    eth_type = (packet_bytes[12] << 8) | packet_bytes[13]
    ip_offset = 14

    # Handle 802.1Q VLAN tag
    if eth_type in (0x8100, 0x88A8) and frame_len >= 18:
        inner_type = (packet_bytes[16] << 8) | packet_bytes[17]
        ip_offset = 18
        # QinQ double tagging
        if inner_type in (0x8100, 0x88A8) and frame_len >= 22:
            eth_type = (packet_bytes[20] << 8) | packet_bytes[21]
            ip_offset = 22
        else:
            eth_type = inner_type

    # Linux Cooked Capture (SLL) fallback
    if eth_type not in (0x0800, 0x86DD) and frame_len >= 16:
        # SLL protocol field is at bytes 14-15
        sll_proto = (packet_bytes[14] << 8) | packet_bytes[15]
        if sll_proto in (0x0800, 0x86DD):
            eth_type = sll_proto
            ip_offset = 16

    # 1. Handle IPv4
    if eth_type == 0x0800:
        ip_data = packet_bytes[ip_offset:]
        if len(ip_data) < 20:
            return None

        v_hl = ip_data[0]
        if (v_hl >> 4) != 4:
            return None

        header_len = (v_hl & 0x0F) * 4
        dscp_tos = ip_data[1]
        total_len = (ip_data[2] << 8) | ip_data[3]
        ident = (ip_data[4] << 8) | ip_data[5]

        # Flags & Fragment Offset
        flags_offset = (ip_data[6] << 8) | ip_data[7]
        df = (flags_offset & 0x4000) != 0
        mf = (flags_offset & 0x2000) != 0
        if df and mf:
            flags_str = "DF,MF"
        elif df:
            flags_str = "DF"
        elif mf:
            flags_str = "MF"
        else:
            flags_str = "None"

        frag_offset = (flags_offset & 0x1FFF) * 8
        ttl = ip_data[8]
        proto = ip_data[9]

        src_ip = f"{ip_data[12]}.{ip_data[13]}.{ip_data[14]}.{ip_data[15]}"
        dst_ip = f"{ip_data[16]}.{ip_data[17]}.{ip_data[18]}.{ip_data[19]}"

        return {
            "version": 4,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ttl": ttl,
            "dscp_tos": dscp_tos,
            "protocol": proto,
            "ident": ident,
            "frag_offset": frag_offset,
            "frag_flags": flags_str,
            "header_len": header_len,
            "total_len": total_len,
        }

    # 2. Handle IPv6
    if eth_type == 0x86DD:
        ip_data = packet_bytes[ip_offset:]
        if len(ip_data) < 40:
            return None

        if (ip_data[0] >> 4) != 6:
            return None

        dscp_tos = ((ip_data[0] & 0x0F) << 4) | (ip_data[1] >> 4)
        payload_len = (ip_data[4] << 8) | ip_data[5]
        proto = ip_data[6]
        hop_limit = ip_data[7]

        try:
            src_ip = socket.inet_ntop(socket.AF_INET6, ip_data[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip_data[24:40])
        except (ValueError, OSError):
            src_ip = "::"
            dst_ip = "::"

        return {
            "version": 6,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ttl": hop_limit,
            "dscp_tos": dscp_tos,
            "protocol": proto,
            "ident": 0,
            "frag_offset": 0,
            "frag_flags": "None",
            "header_len": 40,
            "total_len": payload_len + 40,
        }

    return None


class IPFeatureEvaluator:
    """
    Stateful streaming evaluator for IP layer features across a capture.
    Maintains O(1) memory running statistics:
      - Packet Rate
      - Byte Rate
      - Flow Duration
      - Unique IP Count
      - Path Count
      - TTL Mean
      - TTL Variance (via Welford's algorithm)
    """

    def __init__(self) -> None:
        self.packet_count: int = 0
        self.total_ip_bytes: int = 0
        self.first_timestamp: float | None = None
        self.last_timestamp: float | None = None

        # Running flow duration tracker: key = (min(src, dst), max(src, dst), proto)
        self.flow_start_times: dict[tuple, float] = {}

        # Distinct tracking
        self.unique_ips: set[str] = set()
        self.unique_paths: set[tuple[str, str]] = set()

        # Running Welford's algorithm for TTL mean and variance
        self.ttl_mean: float = 0.0
        self.ttl_M2: float = 0.0

    def evaluate_packet(
        self, timestamp: float, parsed_ip: dict
    ) -> tuple[
        int,
        str,
        str,
        str,
        int,
        int,
        int,
        int,
        int,
        str,
        int,
        int,
        str,
        str,
        str,
        int,
        int,
        str,
        str,
    ]:
        """
        Update running state and return formatted row of 17 features:
        (
            Packet Number, Timestamp, Source IP, Destination IP,
            TTL / Hop Limit, DSCP/TOS, Protocol Number, Identification,
            Fragment Offset, Fragment Flags, Header Length, Total Length,
            Packet Rate, Byte Rate, Flow Duration, Unique IP Count, Path Count,
            TTL Mean, TTL Variance
        )
        """
        self.packet_count += 1
        src_ip = parsed_ip["src_ip"]
        dst_ip = parsed_ip["dst_ip"]
        ttl = parsed_ip["ttl"]
        total_len = parsed_ip["total_len"]
        proto = parsed_ip["protocol"]

        self.total_ip_bytes += total_len

        if self.first_timestamp is None:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp

        elapsed = timestamp - self.first_timestamp
        packet_rate = (self.packet_count / elapsed) if elapsed > 0 else 0.0
        byte_rate = (self.total_ip_bytes / elapsed) if elapsed > 0 else 0.0

        # Flow duration tracking
        flow_key = (min(src_ip, dst_ip), max(src_ip, dst_ip), proto)
        if flow_key not in self.flow_start_times:
            self.flow_start_times[flow_key] = timestamp
            flow_duration = 0.0
        else:
            flow_duration = max(0.0, timestamp - self.flow_start_times[flow_key])

        # Distinct IPs and directed paths
        self.unique_ips.add(src_ip)
        self.unique_ips.add(dst_ip)
        self.unique_paths.add((src_ip, dst_ip))

        # Welford's algorithm for TTL mean and variance
        delta = ttl - self.ttl_mean
        self.ttl_mean += delta / self.packet_count
        delta2 = ttl - self.ttl_mean
        self.ttl_M2 += delta * delta2
        ttl_variance = (self.ttl_M2 / (self.packet_count - 1)) if self.packet_count > 1 else 0.0

        return (
            self.packet_count,
            f"{timestamp:.6f}",
            src_ip,
            dst_ip,
            ttl,
            parsed_ip["dscp_tos"],
            proto,
            parsed_ip["ident"],
            parsed_ip["frag_offset"],
            parsed_ip["frag_flags"],
            parsed_ip["header_len"],
            total_len,
            f"{packet_rate:.2f}",
            f"{byte_rate:.2f}",
            f"{flow_duration:.6f}",
            len(self.unique_ips),
            len(self.unique_paths),
            f"{self.ttl_mean:.2f}",
            f"{ttl_variance:.2f}",
        )


def extract_ip_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
    batch_size: int = DEFAULT_CSV_BATCH_SIZE,
) -> dict:
    """
    Extract and calculate all 17 IP features from a PCAP file and save directly to a CSV file.
    By default, saves to '[pcap_stem]_ip.csv' alongside the PCAP.
    Streaming batch writes ensure O(1) memory usage regardless of file size.
    """
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_ip.csv")
    else:
        output_csv_path = Path(output_csv_path).resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_ip.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    evaluator = IPFeatureEvaluator()
    batch = []
    t_start = time.perf_counter()
    skipped_non_ip = 0

    with open(csv_path, "w", newline="", buffering=2 * 1024 * 1024, encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Packet Number",
            "Timestamp",
            "Source IP",
            "Destination IP",
            "TTL / Hop Limit",
            "DSCP/TOS",
            "Protocol Number",
            "Identification",
            "Fragment Offset",
            "Fragment Flags",
            "Header Length",
            "Total Length",
            "Packet Rate",
            "Byte Rate",
            "Flow Duration",
            "Unique IP Count",
            "Path Count",
            "TTL Mean",
            "TTL Variance",
        ])

        for ts, pkt_bytes in stream_pcap_packets(pcap_path):
            parsed_ip = parse_ip_packet(pkt_bytes)
            if parsed_ip is None:
                skipped_non_ip += 1
                continue

            row = evaluator.evaluate_packet(ts, parsed_ip)
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

    final_variance = (evaluator.ttl_M2 / (evaluator.packet_count - 1)) if evaluator.packet_count > 1 else 0.0

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": evaluator.packet_count,
        "skipped_non_ip": skipped_non_ip,
        "total_ip_bytes": evaluator.total_ip_bytes,
        "csv_size_bytes": csv_size,
        "unique_ip_count": len(evaluator.unique_ips),
        "path_count": len(evaluator.unique_paths),
        "ttl_mean": evaluator.ttl_mean,
        "ttl_variance": final_variance,
        "first_timestamp": evaluator.first_timestamp,
        "last_timestamp": evaluator.last_timestamp,
        "processing_time_seconds": t_elapsed,
        "throughput_packets_per_sec": evaluator.packet_count / t_elapsed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and evaluate IP features from PCAP files into CSV."
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

    print(f"Extracting IP features for {len(pcap_files)} file(s)...")
    for pcap in pcap_files:
        print(f"Processing: {pcap.name} ... ", end="", flush=True)
        res = extract_ip_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Done! {res['packet_count']:,d} IP packets -> {Path(res['csv_file']).name} "
            f"({res['throughput_packets_per_sec']:,.0f} pkts/s)"
        )


if __name__ == "__main__":
    main()

