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


def parse_mp_prio_packet(packet_bytes: bytes):
    """Parse MP_PRIO option data from a TCP packet if present."""
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
            if subtype != 5:
                i += length
                continue

            backup_flag = 1 if (value[1] & 0x01) else 0
            active_flag = 1 if (value[1] & 0x02) else 0
            priority = int.from_bytes(value[2:4], "big") if len(value) >= 4 else 0

            return {
                **parsed,
                "backup_flag": backup_flag,
                "active_flag": active_flag,
                "priority": priority,
            }

        i += length

    return None


def extract_mp_prio_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """
    Extract MP_PRIO features from a PCAP file and save the results as
    '<pcap_stem>_mp_prio.csv'.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_mp_prio.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_mp_prio.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    packet_count = 0
    t_start = time.perf_counter()
    first_ts = None
    last_ts = None
    backup_to_active_transitions = 0
    active_to_backup_transitions = 0
    current_state = None

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mp_prio_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        state = {
            "backup_flag": parsed["backup_flag"],
            "active_flag": parsed["active_flag"],
            "priority": parsed["priority"],
            "timestamp": ts,
        }

        if current_state is not None:
            if current_state["backup_flag"] == 1 and state["active_flag"] == 1:
                backup_to_active_transitions += 1
            if current_state["active_flag"] == 1 and state["backup_flag"] == 1:
                active_to_backup_transitions += 1

        current_state = state
        rows.append(
            {
                "pcap_file": pcap_path.name,
                "src_ip": parsed["src_ip"],
                "dst_ip": parsed["dst_ip"],
                "sport": parsed["sport"],
                "dport": parsed["dport"],
                "backup_flag": parsed["backup_flag"],
                "active_flag": parsed["active_flag"],
                "priority_changes": 1,
                "priority_switch_frequency": 0.0,
                "backup_to_active_transition_count": backup_to_active_transitions,
                "active_to_backup_transition_count": active_to_backup_transitions,
            }
        )

        if limit_packets is not None and packet_count >= limit_packets:
            break

    total_events = len(rows)
    duration = max((last_ts or first_ts or 0.0) - (first_ts or 0.0), 0.0)
    priority_changes = total_events
    priority_switch_frequency = priority_changes / duration if duration > 0 else float(priority_changes)

    for row in rows:
        row["priority_switch_frequency"] = priority_switch_frequency

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Backup Flag",
            "Active Flag",
            "Priority Changes",
            "Priority Switch Frequency",
            "Backup-to-Active Transition Count",
            "Active-to-Backup Transition Count",
        ])

        for row in rows:
            writer.writerow([
                row["pcap_file"],
                row["src_ip"],
                row["dst_ip"],
                row["sport"],
                row["dport"],
                row["backup_flag"],
                row["active_flag"],
                row["priority_changes"],
                f"{row['priority_switch_frequency']:.6f}",
                row["backup_to_active_transition_count"],
                row["active_to_backup_transition_count"],
            ])

    elapsed = max(time.perf_counter() - t_start, 1e-9)

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "mp_prio_events": total_events,
        "backup_to_active_transition_count": backup_to_active_transitions,
        "active_to_backup_transition_count": active_to_backup_transitions,
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": elapsed,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract MP_PRIO features from PCAP files into CSV."
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
        extract_mp_prio_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )


if __name__ == "__main__":
    main()
