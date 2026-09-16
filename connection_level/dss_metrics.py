from __future__ import annotations

import csv
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict

_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

try:
    from protocol_layer.DSS import parse_dss_packet
    from protocol_layer.ethernet import stream_pcap_packets
except ImportError:
    import dpkt

    from protocol_layer.DSS import parse_dss_packet

    def stream_pcap_packets(file_path: Path | str):
        with open(file_path, "rb") as capture_file:
            reader = dpkt.pcap.Reader(capture_file)
            for timestamp, packet in reader:
                yield float(timestamp), packet


PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


def _connection_key(parsed: dict) -> tuple[str, int, str, int]:
    endpoint_a = (parsed["src_ip"], parsed["sport"])
    endpoint_b = (parsed["dst_ip"], parsed["dport"])
    first, second = sorted((endpoint_a, endpoint_b))
    return first[0], first[1], second[0], second[1]


def _growth_rate(samples: list[tuple[float, int]]) -> float | None:
    """Return net value growth per second for one direction."""
    if len(samples) < 2:
        return None

    elapsed = samples[-1][0] - samples[0][0]
    if elapsed <= 0:
        return None
    return (samples[-1][1] - samples[0][1]) / elapsed


class DSSMetricState:
    def __init__(self, connection_id: str) -> None:
        self.connection_id = connection_id
        self.mapping_lengths: list[int] = []
        self.dsn_samples: DefaultDict[tuple[str, int, str, int], list[tuple[float, int]]] = defaultdict(list)
        self.data_ack_samples: DefaultDict[tuple[str, int, str, int], list[tuple[float, int]]] = defaultdict(list)

    def update(self, timestamp: float, parsed: dict) -> None:
        direction = (
            parsed["src_ip"],
            parsed["sport"],
            parsed["dst_ip"],
            parsed["dport"],
        )
        dsn = parsed.get("data_sequence_number")
        if dsn is not None:
            self.mapping_lengths.append(parsed.get("mapping_length") or 0)
            self.dsn_samples[direction].append((timestamp, dsn))

        data_ack = parsed.get("data_ack")
        if data_ack is not None:
            self.data_ack_samples[direction].append((timestamp, data_ack))

    @staticmethod
    def _average_rates(
        samples_by_direction: DefaultDict[
            tuple[str, int, str, int], list[tuple[float, int]]
        ],
    ) -> float | None:
        rates = [
            rate
            for samples in samples_by_direction.values()
            if (rate := _growth_rate(samples)) is not None
        ]
        return sum(rates) / len(rates) if rates else None

    def as_row(self, pcap_name: str) -> list[str | int | float]:
        average_rate = self._average_rates(self.dsn_samples)
        ack_rate = self._average_rates(self.data_ack_samples)
        return [
            pcap_name,
            self.connection_id,
            len(self.mapping_lengths),
            f"{sum(self.mapping_lengths) / len(self.mapping_lengths):.6f}"
            if self.mapping_lengths
            else "",
            max(self.mapping_lengths, default=""),
            min(self.mapping_lengths, default=""),
            f"{average_rate:.6f}" if average_rate is not None else "",
            f"{ack_rate:.6f}" if ack_rate is not None else "",
        ]


def extract_dss_metrics_to_csv(
    pcap_path: Path | str,
    output_csv_path: Path | str | None = None,
    limit_packets: int | None = None,
) -> dict:
    """Extract aggregate DSS mapping, DSN, and Data ACK metrics per connection."""
    pcap_path = Path(pcap_path).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if output_csv_path is None:
        csv_path = pcap_path.with_name(f"{pcap_path.stem}_dss_metrics.csv")
    else:
        output_path = Path(output_csv_path).expanduser().resolve()
        csv_path = (
            output_path / f"{pcap_path.stem}_dss_metrics.csv"
            if output_path.is_dir() or output_path.suffix == ""
            else output_path
        )
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    states: dict[tuple[str, int, str, int], DSSMetricState] = {}
    packet_count = 0
    dss_mapping_count = 0
    start_time = time.perf_counter()

    for timestamp, packet_bytes in stream_pcap_packets(pcap_path):
        parsed = parse_dss_packet(packet_bytes)
        if parsed is None:
            continue

        packet_count += 1
        key = _connection_key(parsed)
        state = states.get(key)
        if state is None:
            state = DSSMetricState(f"conn_{len(states) + 1}")
            states[key] = state
        before = len(state.mapping_lengths)
        state.update(timestamp, parsed)
        dss_mapping_count += len(state.mapping_lengths) - before

        if limit_packets is not None and packet_count >= limit_packets:
            break

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "PCAP File",
            "MPTCP Connection ID",
            "Total DSS Mappings",
            "Average DSS Mapping Length",
            "Maximum DSS Mapping Length",
            "Minimum DSS Mapping Length",
            "DSN Growth Rate",
            "Data ACK Growth Rate",
        ])
        for state in sorted(states.values(), key=lambda item: item.connection_id):
            writer.writerow(state.as_row(pcap_path.name))

    return {
        "pcap_file": str(pcap_path),
        "csv_file": str(csv_path),
        "packet_count": packet_count,
        "connection_count": len(states),
        "dss_mapping_count": dss_mapping_count,
        "csv_size_bytes": csv_path.stat().st_size,
        "processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Extract aggregate DSS metrics into CSV.")
    parser.add_argument("input", help="PCAP file or folder containing PCAP files.")
    parser.add_argument("--output-dir", "-o", default=None, help="Optional output directory.")
    parser.add_argument("--limit", "-l", type=int, default=None, help="Maximum DSS packets per file.")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    if input_path.is_file():
        pcap_files = [input_path]
    elif input_path.is_dir():
        pcap_files = sorted(
            path for path in input_path.rglob("*")
            if path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS
        )
    else:
        pcap_files = []

    if not pcap_files:
        print(f"No PCAP files found in: {input_path}")
        return

    for pcap_file in pcap_files:
        result = extract_dss_metrics_to_csv(pcap_file, args.output_dir, args.limit)
        print(f"Processed {pcap_file.name}: {result['connection_count']} connection(s) -> {result['csv_file']}")


if __name__ == "__main__":
    main()