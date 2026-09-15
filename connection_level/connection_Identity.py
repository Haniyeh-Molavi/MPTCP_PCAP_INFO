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
    from protocol_layer.mptcp_level import compute_mptcp_token
except ImportError:
    import dpkt

    def stream_pcap_packets(file_path: Path | str):
        with open(file_path, "rb") as f:
            reader = dpkt.pcap.Reader(f)
            for ts, pkt in reader:
                yield float(ts), pkt

    def compute_mptcp_token(_key_bytes: bytes) -> str:
        return ""

try:
    from protocol_layer.MP_CAPABLE import parse_mp_capable_packet
except ImportError:
        def parse_mp_capable_packet(_packet_bytes: bytes):
            return None

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


class ConnectionIdentityState:
    def __init__(self, connection_id: str, start_ts: float) -> None:
        self.connection_id = connection_id
        self.start_ts = start_ts
        self.sender_key = None
        self.receiver_key = None
        self.local_token = ""
        self.remote_token = ""
        self.mptcp_version = ""
        self.checksum_enabled = ""


def _canonical_connection_key(src_ip: str, sport: int, dst_ip: str, dport: int) -> tuple[str, int, str, int]:
    endpoint_a = (src_ip, sport)
    endpoint_b = (dst_ip, dport)
    return tuple(sorted((endpoint_a, endpoint_b)))  # type: ignore[return-value]


def _connection_id_from_keys(sender_key: bytes | None, receiver_key: bytes | None) -> str:
    if sender_key:
        token = compute_mptcp_token(sender_key)
        if token:
            return token

    if receiver_key:
        token = compute_mptcp_token(receiver_key)
        if token:
            return token

    return ""


def extract_connection_identity_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """
    Extract per-connection identity metadata (Sender Key, Receiver Key, Local Token,
    Remote Token, MPTCP Version, Checksum Enabled, Connection ID) from a PCAP file.
    Saves the result as '<pcap_stem>_connection_identity.csv'.
    """
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_connection_identity.csv")
    else:
        output_csv_path = Path(output_csv_path).expanduser().resolve()
        if output_csv_path.is_dir():
            csv_path = output_csv_path / f"{pcap_path.stem}_connection_identity.csv"
        else:
            csv_path = output_csv_path

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    connection_states: dict[tuple[str, int, str, int], ConnectionIdentityState] = {}
    packet_count = 0
    t_start = time.perf_counter()

    for ts, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_mp_capable_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1

        src_ip = parsed["src_ip"]
        dst_ip = parsed["dst_ip"]
        sport = parsed["sport"]
        dport = parsed["dport"]
        key = _canonical_connection_key(src_ip, sport, dst_ip, dport)

        state = connection_states.get(key)
        if state is None:
            connection_id = _connection_id_from_keys(parsed.get("sender_key"), parsed.get("receiver_key"))
            if not connection_id:
                connection_id = f"conn_{len(connection_states) + 1}"
            state = ConnectionIdentityState(connection_id=connection_id, start_ts=ts)
            connection_states[key] = state

        if parsed.get("sender_key") is not None:
            state.sender_key = parsed["sender_key"]
            state.local_token = compute_mptcp_token(parsed["sender_key"]) or state.local_token
            if not state.connection_id:
                state.connection_id = state.local_token

        if parsed.get("receiver_key") is not None:
            state.receiver_key = parsed["receiver_key"]
            state.remote_token = compute_mptcp_token(parsed["receiver_key"]) or state.remote_token
            if not state.connection_id:
                state.connection_id = state.remote_token

        if parsed.get("mptcp_version") is not None:
            state.mptcp_version = str(parsed["mptcp_version"])

        if parsed.get("checksum_capability") is not None:
            state.checksum_enabled = "1" if parsed["checksum_capability"] else "0"

        if not state.connection_id:
            state.connection_id = f"conn_{len(connection_states)}"

        if limit_packets is not None and packet_count >= limit_packets:
            break

    rows = []
    for state in sorted(connection_states.values(), key=lambda s: (s.start_ts, s.connection_id)):
        rows.append(
            {
                "pcap_file": pcap_path.name,
                "connection_id": state.connection_id,
                "sender_key": f"0x{state.sender_key.hex().upper()}" if state.sender_key else "",
                "receiver_key": f"0x{state.receiver_key.hex().upper()}" if state.receiver_key else "",
                "local_token": state.local_token,
                "remote_token": state.remote_token,
                "mptcp_version": state.mptcp_version,
                "checksum_enabled": state.checksum_enabled,
            }
        )

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "Connection ID",
            "Sender Key",
            "Receiver Key",
            "Local Token",
            "Remote Token",
            "MPTCP Version",
            "Checksum Enabled",
        ])

        for row in rows:
            writer.writerow(
                [
                    row["pcap_file"],
                    row["connection_id"],
                    row["sender_key"],
                    row["receiver_key"],
                    row["local_token"],
                    row["remote_token"],
                    row["mptcp_version"],
                    row["checksum_enabled"],
                ]
            )

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
        description="Extract per-connection MPTCP identity metadata from one or more PCAP files into CSV."
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
        result = extract_connection_identity_to_csv(
            pcap,
            output_csv_path=args.output_dir,
            limit_packets=args.limit,
        )
        print(
            f"Processed {pcap.name}: {result['connection_count']} connection(s) -> {result['csv_file']}"
        )


if __name__ == "__main__":
    main()
