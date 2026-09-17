from __future__ import annotations

import argparse
import csv
import os
import sys
import time
from pathlib import Path
from typing import Iterator, Tuple

# Ensure parent directory is in sys.path so we can import streaming readers from main if available
_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

# High-performance streaming PCAP readers
try:
    import dpkt
except ImportError:
    dpkt = None

try:
    from protocol_layer.mptcp_level import compute_mptcp_token, parse_mptcp_packet
except ImportError:
    compute_mptcp_token = None
    parse_mptcp_packet = None

try:
    from scapy.utils import RawPcapReader, RawPcapNgReader
except ImportError:
    RawPcapReader = None
    RawPcapNgReader = None

# Known PCAP magic bytes
PCAP_LE = b"\xd4\xc3\xb2\xa1"
PCAP_BE = b"\xa1\xb2\xc3\xd4"
PCAP_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAP_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAP_CLASSIC_MAGICS = {PCAP_LE, PCAP_BE, PCAP_NS_LE, PCAP_NS_BE}
PCAPNG_MAGIC = b"\n\r\r\n"

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}
DEFAULT_BUFFER_SIZE = 4 * 1024 * 1024  # 4MB buffer for high-throughput disk reads
DEFAULT_CSV_BATCH_SIZE = 5000  # Rows to buffer before writing to disk
DEFAULT_LINK_SPEED_BPS = 1_000_000_000.0  # Default: 1 Gbps (1,000,000,000 bps)


def parse_link_speed(speed_str: str | float | int) -> float:
    """
    Parse a human-friendly link speed string into bits per second (bps).
    Examples: '1G' -> 1e9, '100M' -> 1e8, '10G' -> 1e10.
    """
    if isinstance(speed_str, (int, float)):
        return float(speed_str)

    s = speed_str.strip().upper()
    if s.endswith("G") or s.endswith("GBPS"):
        num = s.rstrip("GBPS")
        return float(num) * 1_000_000_000.0
    if s.endswith("M") or s.endswith("MBPS"):
        num = s.rstrip("MBPS")
        return float(num) * 1_000_000.0
    if s.endswith("K") or s.endswith("KBPS"):
        num = s.rstrip("KBPS")
        return float(num) * 1_000.0
    return float(s)


def detect_pcap_format(file_path: Path) -> str:
    """Inspect the first 4 bytes to distinguish classic PCAP from PCAPNG."""
    try:
        with file_path.open("rb") as f:
            magic = f.read(4)
            if magic in PCAP_CLASSIC_MAGICS:
                return "pcap"
            if magic == PCAPNG_MAGIC:
                return "pcapng"
    except OSError:
        pass

    suffix = file_path.suffix.lower()
    if suffix in {".pcap", ".cap"}:
        return "pcap"
    if suffix == ".pcapng":
        return "pcapng"
    return "unknown"


def stream_pcap_packets(
    file_path: Path | str,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> Iterator[Tuple[float, bytes]]:
    """
    Stream packets from PCAP/PCAPNG with O(1) memory footprint.
    Uses dpkt as primary engine with Scapy RawPcapReader fallback.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    fmt = detect_pcap_format(file_path)

    # 1. Primary Engine: DPKT
    if dpkt is not None:
        try:
            with file_path.open("rb", buffering=buffer_size) as handle:
                if fmt == "pcapng":
                    reader = dpkt.pcapng.Reader(handle)
                else:
                    reader = dpkt.pcap.Reader(handle)

                for timestamp, packet_bytes in reader:
                    yield float(timestamp), packet_bytes
                return
        except (dpkt.NeedData, EOFError):
            return
        except Exception:
            pass

    # 2. Fallback Engine: Scapy Streaming
    str_path = str(file_path)
    if fmt == "pcapng" and RawPcapNgReader is not None:
        try:
            for packet_bytes, metadata in RawPcapNgReader(str_path):
                if hasattr(metadata, "tshigh") and hasattr(metadata, "tslow"):
                    resol = float(getattr(metadata, "tsresol", 1e6) or 1e6)
                    ts = float((metadata.tshigh << 32) | metadata.tslow) / resol
                elif hasattr(metadata, "sec") and hasattr(metadata, "usec"):
                    ts = float(metadata.sec) + float(metadata.usec) / 1e6
                else:
                    ts = 0.0
                yield ts, packet_bytes
            return
        except Exception:
            pass

    if RawPcapReader is not None:
        try:
            for packet_bytes, metadata in RawPcapReader(str_path):
                if hasattr(metadata, "sec") and hasattr(metadata, "usec"):
                    ts = float(metadata.sec) + float(metadata.usec) / 1e6
                elif hasattr(metadata, "time"):
                    ts = float(metadata.time)
                else:
                    ts = 0.0
                yield ts, packet_bytes
            return
        except Exception:
            pass

    raise RuntimeError(f"Unable to read PCAP file '{file_path}'. Ensure dpkt is installed.")


def parse_ethernet_header(packet_bytes: bytes) -> tuple[str, str, str, int | None, int]:
    """
    Extract Ethernet Layer features directly via byte slicing for maximum throughput.
    Returns:
        (Source MAC, Destination MAC, EtherType, VLAN ID, Frame Length)
    """
    frame_len = len(packet_bytes)
    if frame_len < 14:
        return ("00:00:00:00:00:00", "00:00:00:00:00:00", "0x0000", None, frame_len)

    dst_mac = f"{packet_bytes[0]:02x}:{packet_bytes[1]:02x}:{packet_bytes[2]:02x}:{packet_bytes[3]:02x}:{packet_bytes[4]:02x}:{packet_bytes[5]:02x}"
    src_mac = f"{packet_bytes[6]:02x}:{packet_bytes[7]:02x}:{packet_bytes[8]:02x}:{packet_bytes[9]:02x}:{packet_bytes[10]:02x}:{packet_bytes[11]:02x}"

    type_or_len = (packet_bytes[12] << 8) | packet_bytes[13]

    vlan_id = None
    if type_or_len in (0x8100, 0x88A8) and frame_len >= 18:
        # 802.1Q / 802.1ad VLAN Tag
        vlan_id = ((packet_bytes[14] & 0x0F) << 8) | packet_bytes[15]
        inner_type = (packet_bytes[16] << 8) | packet_bytes[17]
        # QinQ double-tag support
        if inner_type in (0x8100, 0x88A8) and frame_len >= 22:
            vlan_id = ((packet_bytes[18] & 0x0F) << 8) | packet_bytes[19]
            ethertype_val = (packet_bytes[20] << 8) | packet_bytes[21]
        else:
            ethertype_val = inner_type
    else:
        ethertype_val = type_or_len

    ethertype_str = f"0x{ethertype_val:04X}"
    return (src_mac, dst_mac, ethertype_str, vlan_id, frame_len)


class EthernetFeatureEvaluator:
    """
    Stateful streaming evaluator for Ethernet features across a capture.
    Calculates running and cumulative metrics with O(1) memory:
      - Source MAC
      - Destination MAC
      - EtherType
      - VLAN ID
      - Frame Length
      - Average Frame Size
      - Maximum Frame Size
      - Minimum Frame Size
      - Interface Utilization (%)
    """

    def __init__(self, link_speed_bps: float = DEFAULT_LINK_SPEED_BPS) -> None:
        self.link_speed_bps = link_speed_bps
        self.packet_count: int = 0
        self.total_bytes: int = 0
        self.min_frame_size: int | None = None
        self.max_frame_size: int | None = None
        self.first_timestamp: float | None = None
        self.last_timestamp: float | None = None

    def evaluate_frame(
        self, timestamp: float, packet_bytes: bytes
    ) -> tuple[int, float, str, str, str, int | None, int, float, int, int, float]:
        """
        Evaluate a single frame and return all features:
        (
            Packet Number,
            Timestamp,
            Source MAC,
            Destination MAC,
            EtherType,
            VLAN ID,
            Frame Length,
            Average Frame Size,
            Maximum Frame Size,
            Minimum Frame Size,
            Interface Utilization
        )
        """
        self.packet_count += 1
        src_mac, dst_mac, ethertype, vlan_id, frame_len = parse_ethernet_header(packet_bytes)

        self.total_bytes += frame_len
        self.min_frame_size = (
            frame_len if self.min_frame_size is None else min(self.min_frame_size, frame_len)
        )
        self.max_frame_size = (
            frame_len if self.max_frame_size is None else max(self.max_frame_size, frame_len)
        )
        avg_frame_size = self.total_bytes / self.packet_count

        if self.first_timestamp is None:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp

        elapsed_time = timestamp - self.first_timestamp
        if elapsed_time > 0 and self.link_speed_bps > 0:
            # Interface Utilization (%) = (Total Bits / (Elapsed Seconds * Link Speed)) * 100
            utilization = (self.total_bytes * 8.0) / (elapsed_time * self.link_speed_bps) * 100.0
        else:
            utilization = 0.0

        return (
            self.packet_count,
            timestamp,
            src_mac,
            dst_mac,
            ethertype,
            vlan_id,
            frame_len,
            avg_frame_size,
            self.max_frame_size,
            self.min_frame_size,
            utilization,
        )


def extract_ethernet_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    link_speed_bps: float = DEFAULT_LINK_SPEED_BPS,
    limit_packets: int | None = None,
    batch_size: int = DEFAULT_CSV_BATCH_SIZE,
) -> dict:
    """Extract aggregate Ethernet features with one row per MPTCP connection."""
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_suffix(".csv")
    else:
        output_csv_path = Path(output_csv_path).resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    if parse_mptcp_packet is None or compute_mptcp_token is None:
        raise RuntimeError("MPTCP parser is required for per-connection Ethernet extraction.")

    connections: dict[str, dict] = {}
    subflow_to_connection: dict[tuple[tuple[str, int], tuple[str, int]], str] = {}
    token_to_connection: dict[str, str] = {}
    next_connection_id = 1
    packet_count = 0
    t_start = time.perf_counter()

    for ts, pkt_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mptcp_packet(pkt_bytes)
        if parsed is None:
            continue

        subflow_key = tuple(sorted((
            (parsed["src_ip"], parsed["sport"]),
            (parsed["dst_ip"], parsed["dport"]),
        )))
        connection_id = subflow_to_connection.get(subflow_key)
        if connection_id is None:
            token = None
            if parsed.get("sender_key"):
                token = compute_mptcp_token(parsed["sender_key"])
            elif parsed.get("receiver_key"):
                token = compute_mptcp_token(parsed["receiver_key"])
            elif parsed.get("join_token"):
                token = f"0x{parsed['join_token'].hex().upper()}"

            if token:
                connection_id = token_to_connection.get(token)
                if connection_id is None:
                    connection_id = f"conn_{next_connection_id}"
                    next_connection_id += 1
                    token_to_connection[token] = connection_id
            else:
                connection_id = f"conn_{next_connection_id}"
                next_connection_id += 1
            subflow_to_connection[subflow_key] = connection_id

        state = connections.setdefault(connection_id, {
            "packet_count": 0,
            "total_bytes": 0,
            "min_frame_size": None,
            "max_frame_size": None,
            "first_timestamp": ts,
            "last_timestamp": ts,
            "source_macs": set(),
            "destination_macs": set(),
            "ethertypes": set(),
            "vlan_ids": set(),
        })
        src_mac, dst_mac, ethertype, vlan_id, frame_len = parse_ethernet_header(pkt_bytes)
        state["packet_count"] += 1
        packet_count += 1
        state["total_bytes"] += frame_len
        state["min_frame_size"] = frame_len if state["min_frame_size"] is None else min(state["min_frame_size"], frame_len)
        state["max_frame_size"] = frame_len if state["max_frame_size"] is None else max(state["max_frame_size"], frame_len)
        state["last_timestamp"] = ts
        state["source_macs"].add(src_mac)
        state["destination_macs"].add(dst_mac)
        state["ethertypes"].add(ethertype)
        if vlan_id is not None:
            state["vlan_ids"].add(str(vlan_id))

        if limit_packets is not None and packet_count >= limit_packets:
            break

    with open(csv_path, "w", newline="", buffering=2 * 1024 * 1024, encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "MPTCP Connection ID",
            "Packet Count",
            "Source MACs",
            "Destination MACs",
            "EtherTypes",
            "VLAN IDs",
            "Total Bytes",
            "Average Frame Size",
            "Maximum Frame Size",
            "Minimum Frame Size",
            "Interface Utilization",
        ])
        for connection_id in sorted(connections):
            state = connections[connection_id]
            duration = max(state["last_timestamp"] - state["first_timestamp"], 0.0)
            utilization = (
                state["total_bytes"] * 8.0 / (duration * link_speed_bps) * 100.0
                if duration > 0 and link_speed_bps > 0 else 0.0
            )
            writer.writerow([
                pcap_path.name,
                connection_id,
                state["packet_count"],
                ";".join(sorted(state["source_macs"])),
                ";".join(sorted(state["destination_macs"])),
                ";".join(sorted(state["ethertypes"])),
                ";".join(sorted(state["vlan_ids"])),
                state["total_bytes"],
                f"{state['total_bytes'] / state['packet_count']:.2f}",
                state["max_frame_size"],
                state["min_frame_size"],
                f"{utilization:.6f}",
            ])

    t_elapsed = max(time.perf_counter() - t_start, 1e-9)
    csv_size = csv_path.stat().st_size if csv_path.exists() else 0
    total_bytes = sum(state["total_bytes"] for state in connections.values())

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "connection_count": len(connections),
        "total_bytes": total_bytes,
        "csv_size_bytes": csv_size,
        "min_frame_size": min((state["min_frame_size"] for state in connections.values() if state["min_frame_size"] is not None), default=0),
        "max_frame_size": max((state["max_frame_size"] for state in connections.values() if state["max_frame_size"] is not None), default=0),
        "avg_frame_size": total_bytes / packet_count if packet_count else 0.0,
        "processing_time_seconds": t_elapsed,
        "throughput_packets_per_sec": packet_count / t_elapsed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract and evaluate Ethernet features from PCAP files into CSV."
    )
    parser.add_argument("input", help="PCAP file or folder containing PCAP files.")
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help="Optional directory to save CSV files (default: same directory as PCAP).",
    )
    parser.add_argument(
        "--link-speed",
        "-s",
        default="1G",
        help="Interface link speed for utilization evaluation (e.g. 100M, 1G, 10G; default: 1G).",
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
    link_speed_bps = parse_link_speed(args.link_speed)

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

    print(f"Extracting Ethernet features for {len(pcap_files)} file(s)...")
    for pcap in pcap_files:
        print(f"Processing: {pcap.name} ... ", end="", flush=True)
        res = extract_ethernet_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            link_speed_bps=link_speed_bps,
            limit_packets=args.limit,
        )
        print(
            f"Done! {res['packet_count']:,d} frames -> {Path(res['csv_file']).name} "
            f"({res['throughput_packets_per_sec']:,.0f} pkts/s)"
        )


if __name__ == "__main__":
    main()
