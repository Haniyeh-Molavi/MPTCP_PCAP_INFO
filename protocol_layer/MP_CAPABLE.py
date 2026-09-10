from __future__ import annotations

import csv
import hashlib
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


def compute_mptcp_token(key_bytes: bytes) -> str:
    """Derive 32-bit MPTCP token from a 64-bit key as defined by RFC 6824."""
    if not key_bytes or len(key_bytes) != 8:
        return ""
    token_bytes = hashlib.sha1(key_bytes).digest()[:4]
    return f"0x{token_bytes.hex().upper()}"


def _extract_mptcp_options(packet_bytes: bytes):
    """Parse TCP options to detect MP_CAPABLE and return extracted values."""
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


def parse_mp_capable_packet(packet_bytes: bytes):
    """Return a structured view of an MP_CAPABLE option if present in the packet."""
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
            if subtype != 0:
                i += length
                continue

            version = value[0] & 0x0F
            flags = value[1]
            checksum_capability = 1 if (flags & 0x80) else 0

            sender_key = value[2:10] if len(value) >= 10 else None
            receiver_key = value[10:18] if len(value) >= 18 else None

            return {
                **parsed,
                "flags": flags,
                "checksum_capability": checksum_capability,
                "mptcp_version": version,
                "sender_key": sender_key,
                "receiver_key": receiver_key,
                "connection_token": compute_mptcp_token(sender_key or receiver_key or b""),
            }

        i += length

    return None


def extract_mp_capable_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """
    Extract MP_CAPABLE handshake metadata from a PCAP file and save the result as
    '<pcap_stem>_mp_capable.csv'. Each CSV row represents one connection handshake.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_mp_capable.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_mp_capable.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    sessions: dict[tuple[str, int, str, int], dict] = {}
    packet_count = 0
    first_ts_seen = None
    t_start = time.perf_counter()

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mp_capable_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        if first_ts_seen is None:
            first_ts_seen = ts

        endpoint_a = (parsed["src_ip"], parsed["sport"])
        endpoint_b = (parsed["dst_ip"], parsed["dport"])
        key = tuple(sorted((endpoint_a, endpoint_b)))
        state = sessions.get(key)
        if state is None:
            state = {
                "src_ip": parsed["src_ip"],
                "dst_ip": parsed["dst_ip"],
                "sport": parsed["sport"],
                "dport": parsed["dport"],
                "sender_key": None,
                "receiver_key": None,
                "flags": None,
                "checksum_capability": None,
                "mptcp_version": None,
                "connection_token": "",
                "start_ts": ts,
                "response_ts": None,
                "status": "Failure",
            }
            sessions[key] = state

        if parsed["sender_key"] and state["sender_key"] is None:
            state["sender_key"] = parsed["sender_key"]
            state["connection_token"] = parsed["connection_token"]

        if parsed["receiver_key"] and state["receiver_key"] is None:
            state["receiver_key"] = parsed["receiver_key"]
            state["response_ts"] = ts
            if not state["connection_token"]:
                state["connection_token"] = parsed["connection_token"]

        if state["flags"] is None and parsed["flags"] is not None:
            state["flags"] = parsed["flags"]
        if state["checksum_capability"] is None and parsed["checksum_capability"] is not None:
            state["checksum_capability"] = parsed["checksum_capability"]
        if state["mptcp_version"] is None and parsed["mptcp_version"] is not None:
            state["mptcp_version"] = parsed["mptcp_version"]

        if state["sender_key"] and state["receiver_key"]:
            state["status"] = "Success"
        else:
            state["status"] = "Failure"

        if limit_packets is not None and packet_count >= limit_packets:
            break

    ordered_sessions = sorted(sessions.values(), key=lambda s: (s["start_ts"], s["src_ip"], s["dst_ip"]))

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Sender Key",
            "Receiver Key",
            "Flags",
            "Checksum Capability",
            "MPTCP Version",
            "Connection Token",
            "Handshake Duration (s)",
            "MP_CAPABLE Status",
        ])

        for state in ordered_sessions:
            sender_key = state["sender_key"].hex().upper() if state["sender_key"] else ""
            receiver_key = state["receiver_key"].hex().upper() if state["receiver_key"] else ""
            duration = ""
            if state["response_ts"] is not None and state["start_ts"] is not None:
                duration = f"{max(state['response_ts'] - state['start_ts'], 0.0):.6f}"

            writer.writerow([
                pcap_path.name,
                state["src_ip"],
                state["dst_ip"],
                state["sport"],
                state["dport"],
                f"0x{sender_key}",
                f"0x{receiver_key}",
                state["flags"] if state["flags"] is not None else "",
                state["checksum_capability"] if state["checksum_capability"] is not None else "",
                state["mptcp_version"] if state["mptcp_version"] is not None else "",
                state["connection_token"],
                duration,
                state["status"],
            ])

    elapsed = max(time.perf_counter() - t_start, 1e-9)

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "session_count": len(ordered_sessions),
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": elapsed,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract MP_CAPABLE features from one or more PCAP files into CSV."
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
        result = extract_mp_capable_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Processed {pcap.name}: {result['packet_count']} MP_CAPABLE packets -> {Path(result['csv_file']).name}"
        )


if __name__ == "__main__":
    main()
