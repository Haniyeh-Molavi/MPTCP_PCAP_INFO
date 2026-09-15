from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

_CURRENT_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _CURRENT_DIR.parent
if str(_ROOT_DIR) not in sys.path:
	sys.path.insert(0, str(_ROOT_DIR))

try:
	from protocol_layer.ethernet import stream_pcap_packets
	from protocol_layer.mptcp_level import parse_mptcp_packet
except ImportError:
	import dpkt

	def stream_pcap_packets(file_path: Path | str):
		with open(file_path, "rb") as capture_file:
			reader = dpkt.pcap.Reader(capture_file)
			for timestamp, packet in reader:
				yield float(timestamp), packet

	def parse_mptcp_packet(_packet_bytes: bytes):
		return None

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


class ThroughputState:
	def __init__(self, connection_id: str, start_ts: float) -> None:
		self.connection_id = connection_id
		self.start_ts = start_ts
		self.last_ts = start_ts
		self.total_bytes = 0
		self.goodput_bytes = 0
		self.payload_ranges: list[tuple[int, int]] = []
		self.interval_rates: list[float] = []

	def _add_payload_range(self, start: int, length: int) -> None:
		if length <= 0:
			return

		new_start = start
		new_end = start + length
		merged_ranges: list[tuple[int, int]] = []
		inserted = False

		for range_start, range_end in self.payload_ranges:
			if range_end < new_start:
				merged_ranges.append((range_start, range_end))
			elif new_end < range_start:
				if not inserted:
					merged_ranges.append((new_start, new_end))
					inserted = True
				merged_ranges.append((range_start, range_end))
			else:
				new_start = min(new_start, range_start)
				new_end = max(new_end, range_end)

		if not inserted:
			merged_ranges.append((new_start, new_end))

		self.payload_ranges = merged_ranges
		self.goodput_bytes = sum(end - start for start, end in merged_ranges)

	def update(self, timestamp: float, parsed: dict) -> None:
		frame_len = parsed.get("frame_len", 0) or 0
		self.total_bytes += frame_len

		elapsed = timestamp - self.last_ts
		if elapsed > 0:
			self.interval_rates.append(frame_len / elapsed)
		self.last_ts = timestamp

		dsn = parsed.get("dsn")
		data_len = parsed.get("data_len", 0) or 0
		if dsn is not None:
			self._add_payload_range(dsn, data_len)


def _connection_key(parsed: dict) -> tuple[str, int, str, int]:
	endpoint_a = (parsed["src_ip"], parsed["sport"])
	endpoint_b = (parsed["dst_ip"], parsed["dport"])
	first, second = sorted((endpoint_a, endpoint_b))
	return first[0], first[1], second[0], second[1]


def extract_throughput_to_csv(
	pcap_path: Path | str,
	output_csv_path: Path | str | None = None,
	limit_packets: int | None = None,
) -> dict:
	"""Extract throughput, goodput, and payload efficiency per MPTCP connection."""
	pcap_path = Path(pcap_path).expanduser().resolve()
	if not pcap_path.exists():
		raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

	if output_csv_path is None:
		csv_path = pcap_path.with_name(f"{pcap_path.stem}_throughput.csv")
	else:
		output_path = Path(output_csv_path).expanduser().resolve()
		csv_path = (
			output_path / f"{pcap_path.stem}_throughput.csv"
			if output_path.is_dir() or output_path.suffix == ""
			else output_path
		)
	csv_path.parent.mkdir(parents=True, exist_ok=True)

	states: dict[tuple[str, int, str, int], ThroughputState] = {}
	packet_count = 0
	start_time = time.perf_counter()

	for timestamp, packet_bytes in stream_pcap_packets(pcap_path):
		parsed = parse_mptcp_packet(packet_bytes)
		if parsed is None:
			continue

		packet_count += 1
		key = _connection_key(parsed)
		state = states.get(key)
		if state is None:
			state = ThroughputState(f"conn_{len(states) + 1}", timestamp)
			states[key] = state
		state.update(timestamp, parsed)

		if limit_packets is not None and packet_count >= limit_packets:
			break

	with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow([
			"PCAP File",
			"MPTCP Connection ID",
			"Average Throughput",
			"Peak Throughput",
			"Minimum Throughput",
			"Goodput",
			"Payload Efficiency",
		])
		for state in sorted(states.values(), key=lambda item: item.connection_id):
			duration = max(state.last_ts - state.start_ts, 1e-9)
			average_throughput = state.total_bytes / duration
			peak_throughput = max(state.interval_rates, default=0.0)
			minimum_throughput = min(state.interval_rates, default=0.0)
			goodput = state.goodput_bytes / duration
			payload_efficiency = (
				min(state.goodput_bytes / state.total_bytes * 100, 100.0)
				if state.total_bytes > 0
				else 0.0
			)
			writer.writerow([
				pcap_path.name,
				state.connection_id,
				f"{average_throughput:.6f}",
				f"{peak_throughput:.6f}",
				f"{minimum_throughput:.6f}",
				f"{goodput:.6f}",
				f"{payload_efficiency:.6f}",
			])

	return {
		"pcap_file": str(pcap_path),
		"csv_file": str(csv_path),
		"packet_count": packet_count,
		"connection_count": len(states),
		"throughput_connections": len(states),
		"csv_size_bytes": csv_path.stat().st_size,
		"processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
	}


def main() -> None:
	import argparse

	parser = argparse.ArgumentParser(description="Extract MPTCP throughput features into CSV.")
	parser.add_argument("input", help="PCAP file or folder containing PCAP files.")
	parser.add_argument("--output-dir", "-o", default=None, help="Optional output directory.")
	parser.add_argument("--limit", "-l", type=int, default=None, help="Maximum packets per file.")
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
		result = extract_throughput_to_csv(pcap_file, args.output_dir, args.limit)
		print(f"Processed {pcap_file.name}: {result['connection_count']} connection(s) -> {result['csv_file']}")


if __name__ == "__main__":
	main()
