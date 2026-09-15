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


def _flow_key(parsed: dict) -> tuple[tuple[str, int], tuple[str, int], int]:
	endpoint_a = (parsed["src_ip"], parsed["sport"])
	endpoint_b = (parsed["dst_ip"], parsed["dport"])
	if endpoint_a <= endpoint_b:
		return endpoint_a, endpoint_b, 0
	return endpoint_b, endpoint_a, 1


def extract_reliability_to_csv(
	pcap_path: Path | str,
	output_csv_path: Path | str | None = None,
	limit_packets: int | None = None,
) -> dict:
	"""Extract retransmission, duplicate ACK, ordering, and loss metrics per TCP flow."""
	pcap_path = Path(pcap_path).expanduser().resolve()
	if not pcap_path.exists():
		raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

	if output_csv_path is None:
		csv_path = pcap_path.with_name(f"{pcap_path.stem}_reliability.csv")
	else:
		output_path = Path(output_csv_path).expanduser().resolve()
		csv_path = (
			output_path / f"{pcap_path.stem}_reliability.csv"
			if output_path.is_dir() or output_path.suffix == ""
			else output_path
		)
	csv_path.parent.mkdir(parents=True, exist_ok=True)

	evaluator = TCPFeatureEvaluator()
	retransmitted_bytes: dict[tuple, int] = {}
	retransmitted_packets: dict[tuple, int] = {}
	out_of_order_data: dict[tuple, int] = {}
	data_packets: dict[tuple, int] = {}
	packet_count = 0
	start_time = time.perf_counter()

	for timestamp, packet_bytes in stream_pcap_packets(pcap_path):
		parsed = parse_tcp_segment(packet_bytes)
		if parsed is None:
			continue

		flow_key = _flow_key(parsed)
		canonical_key = flow_key[:2]
		direction = flow_key[2]
		flow = evaluator.flows.get(canonical_key)
		if flow is not None:
			tcp_length = parsed["tcp_length"]
			has_sequence = tcp_length > 0 or parsed["syn"] or parsed["fin"]
			if has_sequence:
				if flow.max_seq_seen[direction] > 0 and parsed["seq"] < flow.max_seq_seen[direction]:
					retransmitted_packets[canonical_key] = retransmitted_packets.get(canonical_key, 0) + 1
					retransmitted_bytes[canonical_key] = retransmitted_bytes.get(canonical_key, 0) + tcp_length
				elif flow.next_expected_seq[direction] > 0 and parsed["seq"] > flow.next_expected_seq[direction] and tcp_length > 0:
					out_of_order_data[canonical_key] = out_of_order_data.get(canonical_key, 0) + 1

		if parsed["tcp_length"] > 0:
			data_packets[canonical_key] = data_packets.get(canonical_key, 0) + 1

		evaluator.evaluate_packet(timestamp, parsed)
		packet_count += 1
		if limit_packets is not None and packet_count >= limit_packets:
			break

	with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow([
			"PCAP File",
			"TCP Connection ID",
			"Retransmitted Bytes",
			"Retransmitted Packets",
			"Retransmission Ratio",
			"Duplicate ACK Count",
			"Out-of-Order Data Count",
			"Data Reordering Rate",
			"Lost Packet Estimate",
		])
		for index, (flow_key, flow) in enumerate(sorted(evaluator.flows.items(), key=lambda item: str(item[0])), 1):
			retrans_packets = retransmitted_packets.get(flow_key, 0)
			retrans_bytes = retransmitted_bytes.get(flow_key, 0)
			out_of_order_count = out_of_order_data.get(flow_key, 0)
			data_packet_count = data_packets.get(flow_key, 0)
			writer.writerow([
				pcap_path.name,
				f"conn_{index}",
				retrans_bytes,
				retrans_packets,
				f"{retrans_packets / max(flow.packet_count, 1):.6f}",
				flow.dupack_count,
				out_of_order_count,
				f"{out_of_order_count / max(data_packet_count, 1):.6f}",
				retrans_packets,
			])

	return {
		"pcap_file": str(pcap_path),
		"csv_file": str(csv_path),
		"packet_count": packet_count,
		"connection_count": len(evaluator.flows),
		"reliability_flows": len(evaluator.flows),
		"csv_size_bytes": csv_path.stat().st_size,
		"processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
	}


def main() -> None:
	import argparse

	parser = argparse.ArgumentParser(description="Extract TCP reliability features into CSV.")
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
		result = extract_reliability_to_csv(pcap_file, args.output_dir, args.limit)
		print(f"Processed {pcap_file.name}: {result['connection_count']} connection(s) -> {result['csv_file']}")


if __name__ == "__main__":
	main()
