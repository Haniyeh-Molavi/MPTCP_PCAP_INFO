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
	from protocol_layer.tcp import IDLE_THRESHOLD_SECONDS, parse_tcp_segment
except ImportError:
	import dpkt

	IDLE_THRESHOLD_SECONDS = 0.100

	def stream_pcap_packets(file_path: Path | str):
		with open(file_path, "rb") as capture_file:
			reader = dpkt.pcap.Reader(capture_file)
			for timestamp, packet in reader:
				yield float(timestamp), packet

	from protocol_layer.tcp import parse_tcp_segment

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


class FlowActivityState:
	def __init__(self, flow_id: str, first_timestamp: float) -> None:
		self.flow_id = flow_id
		self.last_timestamp = first_timestamp
		self.packet_count = 1
		self.active_time = 0.0
		self.idle_time = 0.0
		self.active_periods = 1
		self.largest_idle_gap = 0.0
		self.inter_packet_total = 0.0

	def update(self, timestamp: float) -> None:
		gap = max(timestamp - self.last_timestamp, 0.0)
		self.inter_packet_total += gap
		self.packet_count += 1
		if gap > IDLE_THRESHOLD_SECONDS:
			self.idle_time += gap
			self.largest_idle_gap = max(self.largest_idle_gap, gap)
			self.active_periods += 1
		else:
			self.active_time += gap
		self.last_timestamp = timestamp


def _flow_key(parsed: dict) -> tuple[tuple[str, int], tuple[str, int]]:
	endpoint_a = (parsed["src_ip"], parsed["sport"])
	endpoint_b = (parsed["dst_ip"], parsed["dport"])
	return tuple(sorted((endpoint_a, endpoint_b)))


def extract_flow_activity_to_csv(
	pcap_path: Path | str,
	output_csv_path: Path | str | None = None,
	limit_packets: int | None = None,
) -> dict:
	"""Extract active, idle, and inter-packet timing metrics per TCP flow."""
	pcap_path = Path(pcap_path).expanduser().resolve()
	if not pcap_path.exists():
		raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

	if output_csv_path is None:
		csv_path = pcap_path.with_name(f"{pcap_path.stem}_flow.csv")
	else:
		output_path = Path(output_csv_path).expanduser().resolve()
		csv_path = (
			output_path / f"{pcap_path.stem}_flow.csv"
			if output_path.is_dir() or output_path.suffix == ""
			else output_path
		)
	csv_path.parent.mkdir(parents=True, exist_ok=True)

	states: dict[tuple[tuple[str, int], tuple[str, int]], FlowActivityState] = {}
	packet_count = 0
	start_time = time.perf_counter()

	for timestamp, packet_bytes in stream_pcap_packets(pcap_path):
		parsed = parse_tcp_segment(packet_bytes)
		if parsed is None:
			continue

		packet_count += 1
		key = _flow_key(parsed)
		state = states.get(key)
		if state is None:
			state = FlowActivityState(f"conn_{len(states) + 1}", timestamp)
			states[key] = state
		else:
			state.update(timestamp)

		if limit_packets is not None and packet_count >= limit_packets:
			break

	with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow([
			"PCAP File",
			"TCP Connection ID",
			"Active Time",
			"Idle Time",
			"Number of Active Periods",
			"Largest Idle Gap",
			"Average Inter-packet Time",
		])
		for state in sorted(states.values(), key=lambda item: item.flow_id):
			average_inter_packet_time = state.inter_packet_total / max(state.packet_count - 1, 1)
			writer.writerow([
				pcap_path.name,
				state.flow_id,
				f"{state.active_time:.6f}",
				f"{state.idle_time:.6f}",
				state.active_periods,
				f"{state.largest_idle_gap:.6f}",
				f"{average_inter_packet_time:.6f}",
			])

	return {
		"pcap_file": str(pcap_path),
		"csv_file": str(csv_path),
		"packet_count": packet_count,
		"connection_count": len(states),
		"flow_activity_flows": len(states),
		"csv_size_bytes": csv_path.stat().st_size,
		"processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
	}


def main() -> None:
	import argparse

	parser = argparse.ArgumentParser(description="Extract TCP flow activity features into CSV.")
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
		result = extract_flow_activity_to_csv(pcap_file, args.output_dir, args.limit)
		print(f"Processed {pcap_file.name}: {result['connection_count']} connection(s) -> {result['csv_file']}")


if __name__ == "__main__":
	main()
