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
except ImportError:
    try:
        from ethernet import stream_pcap_packets
    except ImportError:
        import dpkt

        def stream_pcap_packets(file_path: Path | str):
            with open(file_path, "rb") as f:
                reader = dpkt.pcap.Reader(f)
                for ts, pkt in reader:
                    yield float(ts), pkt


PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


def _extract_mptcp_options(packet_bytes: bytes):
    """Parse TCP options to detect MP_JOIN and return extracted values."""
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

    sport = (tcp_data[0] << 8) | tcp_data[1]
    dport = (tcp_data[2] << 8) | tcp_data[3]
    data_offset = (tcp_data[12] >> 4) * 4
    if data_offset <= 20 or len(tcp_data) < data_offset:
        return None

    options_bytes = tcp_data[20:data_offset]
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport": sport,
        "dport": dport,
        "options": options_bytes,
    }


def parse_mp_join_packet(packet_bytes: bytes):
    """Parse MP_JOIN option data from a TCP packet if present."""
    parsed = _extract_mptcp_options(packet_bytes)
    if parsed is None:
        return None

    options = parsed["options"]
    i = 0
    while i < len(options):
        kind = options[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(options):
            break

        length = options[i + 1]
        if length < 2 or i + length > len(options):
            break

        if kind == 30:
            value = options[i + 2 : i + length]
            if len(value) < 1:
                break

            subtype = value[0] >> 4
            if subtype != 1:
                i += length
                continue

            token = value[1:5] if len(value) >= 5 else b""
            address_id = value[5] if len(value) >= 6 else None
            nonce = value[6:14] if len(value) >= 14 else b""
            hmac = value[14:] if len(value) > 14 else b""

            return {
                **parsed,
                "token": token,
                "address_id": address_id,
                "nonce": nonce,
                "hmac": hmac,
            }

        i += length

    return None


def _format_hex(data: bytes | None) -> str:
    if not data:
        return ""
    return f"0x{data.hex().upper()}"


def extract_mp_join_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """
    Extract MP_JOIN features from a PCAP file and save the result as
    '<pcap_stem>_mp_join.csv'. Each row represents one MP_JOIN subflow event.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_mp_join.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_mp_join.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    packet_count = 0
    t_start = time.perf_counter()
    capture_end_ts = None

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mp_join_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        if capture_end_ts is None or ts > capture_end_ts:
            capture_end_ts = ts

        rows.append(
            {
                "pcap_file": pcap_path.name,
                "src_ip": parsed["src_ip"],
                "dst_ip": parsed["dst_ip"],
                "sport": parsed["sport"],
                "dport": parsed["dport"],
                "token": _format_hex(parsed["token"]),
                "address_id": parsed["address_id"],
                "nonce": _format_hex(parsed["nonce"]),
                "hmac": _format_hex(parsed["hmac"]),
                "new_subflow_count": 1,
                "subflow_creation_time": f"{ts:.6f}",
                "subflow_lifetime": "",
                "subflow_duration": "",
                "concurrent_subflow_count": 0,
                "active_subflow_count": 0,
                "maximum_subflow_count": 0,
            }
        )

        if limit_packets is not None and packet_count >= limit_packets:
            break

    total_join_events = len(rows)
    if capture_end_ts is None:
        capture_end_ts = 0.0

    for row in rows:
        creation_ts = float(row["subflow_creation_time"])
        lifetime = max(capture_end_ts - creation_ts, 0.0)
        row["subflow_lifetime"] = f"{lifetime:.6f}"
        row["subflow_duration"] = f"{lifetime:.6f}"
        row["concurrent_subflow_count"] = total_join_events
        row["active_subflow_count"] = total_join_events
        row["maximum_subflow_count"] = total_join_events

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Token",
            "Address ID",
            "Nonce",
            "HMAC",
            "New Subflow Count",
            "Subflow Creation Time",
            "Subflow Lifetime",
            "Subflow Duration",
            "Concurrent Subflow Count",
            "Active Subflow Count",
            "Maximum Subflow Count",
        ])

        for row in rows:
            writer.writerow([
                row["pcap_file"],
                row["src_ip"],
                row["dst_ip"],
                row["sport"],
                row["dport"],
                row["token"],
                row["address_id"] if row["address_id"] is not None else "",
                row["nonce"],
                row["hmac"],
                row["new_subflow_count"],
                row["subflow_creation_time"],
                row["subflow_lifetime"],
                row["subflow_duration"],
                row["concurrent_subflow_count"],
                row["active_subflow_count"],
                row["maximum_subflow_count"],
            ])

    elapsed = max(time.perf_counter() - t_start, 1e-9)

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "mp_join_events": total_join_events,
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": elapsed,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract MP_JOIN features from PCAP files into CSV."
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
        result = extract_mp_join_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Processed {pcap.name}: {result['packet_count']} packets -> {Path(result['csv_file']).name}"
        )


if __name__ == "__main__":
    main()
