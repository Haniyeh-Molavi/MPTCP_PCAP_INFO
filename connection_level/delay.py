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
	from protocol_layer.tcp import TCPFeatureEvaluator, parse_tcp_segment
except ImportError:
	import dpkt

	def stream_pcap_packets(file_path: Path | str):
		with open(file_path, "rb") as capture_file:
			reader = dpkt.pcap.Reader(capture_file)
			for timestamp, packet in reader:
				yield float(timestamp), packet

	from protocol_layer.tcp import TCPFeatureEvaluator, parse_tcp_segment

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


def extract_delay_to_csv(
	pcap_path: Path | str,
	output_csv_path: Path | str | None = None,
	limit_packets: int | None = None,
) -> dict:
	"""Extract RTT and jitter statistics per TCP flow."""
	pcap_path = Path(pcap_path).expanduser().resolve()
	if not pcap_path.exists():
		raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

	if output_csv_path is None:
		csv_path = pcap_path.with_name(f"{pcap_path.stem}_delay.csv")
	else:
		output_path = Path(output_csv_path).expanduser().resolve()
		csv_path = (
			output_path / f"{pcap_path.stem}_delay.csv"
			if output_path.is_dir() or output_path.suffix == ""
			else output_path
		)
	csv_path.parent.mkdir(parents=True, exist_ok=True)

	evaluator = TCPFeatureEvaluator()
	rtt_samples: dict[tuple, list[float]] = {}
	packet_count = 0
	start_time = time.perf_counter()

	for timestamp, packet_bytes in stream_pcap_packets(pcap_path):
		parsed = parse_tcp_segment(packet_bytes)
		if parsed is None:
			continue

		evaluator.evaluate_packet(timestamp, parsed)
		packet_count += 1

		endpoint_a = (parsed["src_ip"], parsed["sport"])
		endpoint_b = (parsed["dst_ip"], parsed["dport"])
		flow_key = tuple(sorted((endpoint_a, endpoint_b)))
		flow = evaluator.flows[flow_key]
		samples = rtt_samples.setdefault(flow_key, [])
		if flow.rtt_count > len(samples) and flow.latest_rtt is not None:
			samples.append(flow.latest_rtt)

		if limit_packets is not None and packet_count >= limit_packets:
			break

	with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow([
			"PCAP File",
			"TCP Connection ID",
			"Average RTT",
			"Minimum RTT",
			"Maximum RTT",
			"RTT Variance",
			"RTT Standard Deviation",
			"Jitter",
		])
		for index, (flow_key, flow) in enumerate(sorted(evaluator.flows.items(), key=lambda item: str(item[0])), 1):
			samples = rtt_samples.get(flow_key, [])
			variance = flow.rtt_M2 / (flow.rtt_count - 1) if flow.rtt_count > 1 else 0.0
			standard_deviation = variance ** 0.5
			jitter = (
				sum(abs(current - previous) for previous, current in zip(samples, samples[1:]))
				/ (len(samples) - 1)
				if len(samples) > 1
				else 0.0
			)
			writer.writerow([
				pcap_path.name,
				f"conn_{index}",
				f"{flow.rtt_mean:.6f}" if flow.rtt_count else "",
				f"{flow.rtt_min:.6f}" if flow.rtt_min is not None else "",
				f"{flow.rtt_max:.6f}" if flow.rtt_max is not None else "",
				f"{variance:.6f}" if flow.rtt_count > 1 else "0.000000",
				f"{standard_deviation:.6f}" if flow.rtt_count > 1 else "0.000000",
				f"{jitter:.6f}" if samples else "",
			])

	return {
		"pcap_file": str(pcap_path),
		"csv_file": str(csv_path),
		"packet_count": packet_count,
		"connection_count": len(evaluator.flows),
		"delay_flows": len(evaluator.flows),
		"csv_size_bytes": csv_path.stat().st_size,
		"processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
	}


def main() -> None:
	import argparse

	parser = argparse.ArgumentParser(description="Extract TCP delay and RTT features into CSV.")
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
		result = extract_delay_to_csv(pcap_file, args.output_dir, args.limit)
		print(f"Processed {pcap_file.name}: {result['connection_count']} connection(s) -> {result['csv_file']}")


if __name__ == "__main__":
	main()
