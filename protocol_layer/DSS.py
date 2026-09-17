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
        from ethernet import stream_pcap_packets
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


def _subflow_key(parsed: dict) -> tuple[tuple[str, int], tuple[str, int]]:
	return tuple(sorted((
		(parsed["src_ip"], parsed["sport"]),
		(parsed["dst_ip"], parsed["dport"]),
	)))


def _connection_token(parsed: dict) -> str | None:
	if parsed.get("sender_key"):
		return compute_mptcp_token(parsed["sender_key"])
	if parsed.get("receiver_key"):
		return compute_mptcp_token(parsed["receiver_key"])
	if parsed.get("join_token"):
		return f"0x{parsed['join_token'].hex().upper()}"
	return None


def extract_dss_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """Extract aggregate DSS features and write one row per MPTCP connection."""
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

    packet_count = 0
    t_start = time.perf_counter()
    connection_states: dict[str, dict] = {}
    subflow_to_connection: dict[tuple[tuple[str, int], tuple[str, int]], str] = {}
    token_to_connection: dict[str, str] = {}
    next_connection_id = 1

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        mptcp = parse_mptcp_packet(packet_bytes)
        if mptcp is None:
            continue

        subflow_key = _subflow_key(mptcp)
        connection_id = subflow_to_connection.get(subflow_key)
        if connection_id is None:
            token = _connection_token(mptcp)
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

        parsed = parse_dss_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        if limit_packets is not None and packet_count >= limit_packets:
            break

        if connection_id not in connection_states:
            connection_states[connection_id] = {
                "start_ts": ts,
                "last_ts": ts,
                "minimum_dsn": None,
                "maximum_dsn": None,
                "final_dsn": None,
                "data_ack_values": [],
                "data_fin": False,
                "total_bytes": 0,
                "previous_dsn": None,
                "previous_ack": None,
                "previous_ts": ts,
                "dsn_rates": [],
                "ack_rates": [],
                "reordering_distances": [],
                "reassembly_delays": [],
                "dsn_times": {},
            }

        conn_state = connection_states[connection_id]
        conn_state["last_ts"] = ts

        data_length = parsed["data_length"] or 0
        conn_state["total_bytes"] += data_length
        dsn = parsed["data_sequence_number"]
        ack = parsed["data_ack"]
        if dsn is not None:
            conn_state["minimum_dsn"] = dsn if conn_state["minimum_dsn"] is None else min(conn_state["minimum_dsn"], dsn)
            conn_state["maximum_dsn"] = dsn if conn_state["maximum_dsn"] is None else max(conn_state["maximum_dsn"], dsn)
            conn_state["final_dsn"] = dsn
            if conn_state["previous_dsn"] is not None and conn_state["previous_ts"] != ts:
                delta_dsn = dsn - conn_state["previous_dsn"]
                if delta_dsn > 0:
                    conn_state["dsn_rates"].append(delta_dsn / max(ts - conn_state["previous_ts"], 1e-9))
            if conn_state["previous_dsn"] is not None:
                conn_state["reordering_distances"].append(abs(dsn - conn_state["previous_dsn"]))
            conn_state["dsn_times"][dsn] = ts

        if ack is not None:
            conn_state["data_ack_values"].append(ack)
            if conn_state["previous_ack"] is not None and conn_state["previous_ts"] != ts:
                delta_ack = ack - conn_state["previous_ack"]
                if delta_ack > 0:
                    conn_state["ack_rates"].append(delta_ack / max(ts - conn_state["previous_ts"], 1e-9))
            if ack in conn_state["dsn_times"]:
                conn_state["reassembly_delays"].append(max(ts - conn_state["dsn_times"][ack], 0.0))

        conn_state["data_fin"] = conn_state["data_fin"] or bool(parsed["data_fin"])
        conn_state["previous_dsn"] = dsn
        conn_state["previous_ack"] = ack
        conn_state["previous_ts"] = ts

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "MPTCP Connection ID",
            "Minimum DSN",
            "Maximum DSN",
            "Final DSN",
            "Data ACK Values",
            "DATA_FIN",
            "Total Data Length",
            "DSN Range",
            "Connection-Level Throughput",
            "Average DSN Progression Rate",
            "Average Data ACK Progression Rate",
            "Maximum Reordering Distance",
            "Average Reassembly Delay",
        ])

        for connection_id in sorted(connection_states):
            state = connection_states[connection_id]
            duration = max(state["last_ts"] - state["start_ts"], 1e-9)
            dsn_range = ""
            if state["minimum_dsn"] is not None and state["maximum_dsn"] is not None:
                dsn_range = state["maximum_dsn"] - state["minimum_dsn"]
            average_dsn_rate = sum(state["dsn_rates"]) / len(state["dsn_rates"]) if state["dsn_rates"] else ""
            average_ack_rate = sum(state["ack_rates"]) / len(state["ack_rates"]) if state["ack_rates"] else ""
            max_reordering = max(state["reordering_distances"]) if state["reordering_distances"] else ""
            average_reassembly = sum(state["reassembly_delays"]) / len(state["reassembly_delays"]) if state["reassembly_delays"] else ""
            writer.writerow([
                pcap_path.name,
                connection_id,
                _format_number(state["minimum_dsn"]),
                _format_number(state["maximum_dsn"]),
                _format_number(state["final_dsn"]),
                ";".join(str(value) for value in state["data_ack_values"]),
                "1" if state["data_fin"] else "0",
                state["total_bytes"],
                dsn_range,
                f"{state['total_bytes'] / duration:.6f}",
                f"{average_dsn_rate:.6f}" if average_dsn_rate != "" else "",
                f"{average_ack_rate:.6f}" if average_ack_rate != "" else "",
                max_reordering,
                f"{average_reassembly:.6f}" if average_reassembly != "" else "",
            ])

    elapsed = max(time.perf_counter() - t_start, 1e-9)

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "connection_count": len(connection_states),
        "dss_events": packet_count,
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
