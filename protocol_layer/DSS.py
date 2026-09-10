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
    """Parse TCP options and return raw IPv4/IPv6 metadata plus the TCP option bytes."""
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


def parse_dss_packet(packet_bytes: bytes):
    """Parse DSS metadata from a single packet if the packet contains an MP_DSS option."""
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
            if len(value) < 2:
                break

            subtype = value[0] >> 4
            if subtype != 2:
                i += length
                continue

            flags = value[1]
            has_dack = bool(flags & 0x01)
            dack_is_8 = bool(flags & 0x02)
            has_dsn = bool(flags & 0x04)
            dsn_is_8 = bool(flags & 0x08)
            data_fin = bool(flags & 0x10)

            idx = 2
            data_ack = None
            if has_dack:
                ack_len = 8 if dack_is_8 else 4
                if idx + ack_len <= len(value):
                    data_ack = int.from_bytes(value[idx : idx + ack_len], "big")
                    idx += ack_len

            dsn = None
            ssn = None
            data_length = None
            if has_dsn:
                dsn_len = 8 if dsn_is_8 else 4
                if idx + dsn_len <= len(value):
                    dsn = int.from_bytes(value[idx : idx + dsn_len], "big")
                    idx += dsn_len
                if idx + 4 <= len(value):
                    ssn = int.from_bytes(value[idx : idx + 4], "big")
                    idx += 4
                if idx + 2 <= len(value):
                    data_length = int.from_bytes(value[idx : idx + 2], "big")
                    idx += 2

            mapping_length = data_length if data_length is not None else 0

            return {
                **parsed,
                "flags": flags,
                "data_ack": data_ack,
                "data_sequence_number": dsn,
                "subflow_sequence_number": ssn,
                "data_length": data_length,
                "mapping_length": mapping_length,
                "data_fin": int(data_fin),
            }

        i += length

    return None


def _format_number(value):
    if value is None:
        return ""
    return value


def extract_dss_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """
    Extract DSS features from a PCAP file and save the results as
    '<pcap_stem>_dss.csv'. Each row represents a parsed DSS packet event.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_dss.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_dss.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    packet_count = 0
    t_start = time.perf_counter()

    connection_state: dict[tuple[tuple[str, int], tuple[str, int]], dict] = {}
    subflow_state: dict[tuple[str, int, str, int], dict] = {}
    dsn_seen_for_connection: dict[tuple[tuple[str, int], tuple[str, int]], dict[int, float]] = {}

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_dss_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        if limit_packets is not None and packet_count > limit_packets:
            break

        endpoint_a = (parsed["src_ip"], parsed["sport"])
        endpoint_b = (parsed["dst_ip"], parsed["dport"])
        conn_key = tuple(sorted((endpoint_a, endpoint_b)))

        subflow_key = (parsed["src_ip"], parsed["sport"], parsed["dst_ip"], parsed["dport"])

        if conn_key not in connection_state:
            connection_state[conn_key] = {
                "start_ts": ts,
                "total_bytes": 0,
                "prev_dsn": None,
                "prev_data_ack": None,
                "prev_ts": ts,
                "last_data_ack": None,
            }
            dsn_seen_for_connection[conn_key] = {}

        if subflow_key not in subflow_state:
            subflow_state[subflow_key] = {
                "start_ts": ts,
                "total_bytes": 0,
            }

        conn_state = connection_state[conn_key]
        subflow_state_entry = subflow_state[subflow_key]

        data_length = parsed["data_length"] or 0
        conn_state["total_bytes"] += data_length
        subflow_state_entry["total_bytes"] += data_length

        conn_elapsed = max(ts - conn_state["start_ts"], 1e-9)
        subflow_elapsed = max(ts - subflow_state_entry["start_ts"], 1e-9)

        dsn_progression_rate = ""
        if parsed["data_sequence_number"] is not None and conn_state["prev_dsn"] is not None and conn_state["prev_ts"] != ts:
            delta_dsn = parsed["data_sequence_number"] - conn_state["prev_dsn"]
            if delta_dsn > 0:
                dsn_progression_rate = f"{delta_dsn / max(ts - conn_state['prev_ts'], 1e-9):.6f}"

        data_ack_progression_rate = ""
        if parsed["data_ack"] is not None and conn_state["prev_data_ack"] is not None and conn_state["prev_ts"] != ts:
            delta_ack = parsed["data_ack"] - conn_state["prev_data_ack"]
            if delta_ack > 0:
                data_ack_progression_rate = f"{delta_ack / max(ts - conn_state['prev_ts'], 1e-9):.6f}"

        connection_level_throughput = f"{conn_state['total_bytes'] / conn_elapsed:.6f}"
        subflow_level_throughput = f"{subflow_state_entry['total_bytes'] / subflow_elapsed:.6f}"

        reordering_distance = ""
        if parsed["data_sequence_number"] is not None and conn_state["prev_dsn"] is not None:
            reordering_distance = str(abs(parsed["data_sequence_number"] - conn_state["prev_dsn"]))

        reassembly_delay = ""
        if parsed["data_ack"] is not None:
            dsn_lookup = dsn_seen_for_connection[conn_key]
            if parsed["data_ack"] in dsn_lookup:
                reassembly_delay = f"{max(ts - dsn_lookup[parsed['data_ack']], 0.0):.6f}"

        row = {
            "pcap_file": pcap_path.name,
            "src_ip": parsed["src_ip"],
            "dst_ip": parsed["dst_ip"],
            "sport": parsed["sport"],
            "dport": parsed["dport"],
            "data_sequence_number": _format_number(parsed["data_sequence_number"]),
            "data_ack": _format_number(parsed["data_ack"]),
            "subflow_sequence_number": _format_number(parsed["subflow_sequence_number"]),
            "data_length": _format_number(parsed["data_length"]),
            "mapping_length": _format_number(parsed["mapping_length"]),
            "data_fin": parsed["data_fin"],
            "dsn_progression_rate": dsn_progression_rate,
            "data_ack_progression_rate": data_ack_progression_rate,
            "connection_level_throughput": connection_level_throughput,
            "subflow_level_throughput": subflow_level_throughput,
            "reordering_distance": reordering_distance,
            "reassembly_delay": reassembly_delay,
        }
        rows.append(row)

        if parsed["data_sequence_number"] is not None:
            dsn_seen_for_connection[conn_key][parsed["data_sequence_number"]] = ts

        conn_state["prev_dsn"] = parsed["data_sequence_number"]
        conn_state["prev_data_ack"] = parsed["data_ack"]
        conn_state["prev_ts"] = ts

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Data Sequence Number",
            "Data ACK",
            "Subflow Sequence Number",
            "Data Length",
            "Mapping Length",
            "DATA_FIN",
            "DSN Progression Rate",
            "Data ACK Progression Rate",
            "Connection-Level Throughput",
            "Subflow-Level Throughput",
            "Reordering Distance",
            "Reassembly Delay",
        ])

        for row in rows:
            writer.writerow([
                row["pcap_file"],
                row["src_ip"],
                row["dst_ip"],
                row["sport"],
                row["dport"],
                row["data_sequence_number"],
                row["data_ack"],
                row["subflow_sequence_number"],
                row["data_length"],
                row["mapping_length"],
                row["data_fin"],
                row["dsn_progression_rate"],
                row["data_ack_progression_rate"],
                row["connection_level_throughput"],
                row["subflow_level_throughput"],
                row["reordering_distance"],
                row["reassembly_delay"],
            ])

    elapsed = max(time.perf_counter() - t_start, 1e-9)

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "dss_events": len(rows),
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": elapsed,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract DSS features from PCAP files into CSV."
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
        result = extract_dss_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Processed {pcap.name}: {result['packet_count']} packets -> {Path(result['csv_file']).name}"
        )


if __name__ == "__main__":
    main()
