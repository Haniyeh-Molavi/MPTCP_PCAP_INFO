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
	from protocol_layer.mptcp_level import compute_mptcp_token, parse_mptcp_packet
except ImportError:
	import dpkt

	def stream_pcap_packets(file_path: Path | str):
		with open(file_path, "rb") as capture_file:
			reader = dpkt.pcap.Reader(capture_file)
			for timestamp, packet in reader:
				yield float(timestamp), packet

	def parse_mptcp_packet(_packet_bytes: bytes):
		return None

	def compute_mptcp_token(_key_bytes: bytes) -> str:
		return ""

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


class TrafficVolumeState:
	def __init__(self, connection_id: str, source_endpoint: tuple[str, int]) -> None:
		self.connection_id = connection_id
		self.source_endpoint = source_endpoint
		self.packets_sent = 0
		self.packets_received = 0
		self.bytes_sent = 0
		self.bytes_received = 0
		self.payload_bytes = 0

	def update(self, parsed: dict) -> None:
		endpoint = (parsed["src_ip"], parsed["sport"])
		frame_len = parsed.get("frame_len", 0) or 0
		payload_len = parsed.get("data_len", 0) or 0

		if endpoint == self.source_endpoint:
			self.packets_sent += 1
			self.bytes_sent += frame_len
		else:
			self.packets_received += 1
			self.bytes_received += frame_len

		self.payload_bytes += payload_len


def _connection_key(parsed: dict) -> tuple[str, tuple[str, int, str, int]]:
	endpoint_a = (parsed["src_ip"], parsed["sport"])
	endpoint_b = (parsed["dst_ip"], parsed["dport"])
	endpoints = tuple(sorted((endpoint_a, endpoint_b)))

	sender_key = parsed.get("sender_key")
	receiver_key = parsed.get("receiver_key")
	token = compute_mptcp_token(sender_key) if sender_key else ""
	if not token and receiver_key:
		token = compute_mptcp_token(receiver_key)

	return token, (endpoints[0][0], endpoints[0][1], endpoints[1][0], endpoints[1][1])


def extract_traffic_volume_to_csv(
	pcap_path: Path | str,
	output_csv_path: Path | str | None = None,
	limit_packets: int | None = None,
) -> dict:
	"""Extract sent, received, total, and payload traffic volume per MPTCP connection."""
	pcap_path = Path(pcap_path).expanduser().resolve()
	if not pcap_path.exists():
		raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

	if output_csv_path is None:
		csv_path = pcap_path.with_name(f"{pcap_path.stem}_traffic_volume.csv")
	else:
		output_path = Path(output_csv_path).expanduser().resolve()
		csv_path = (
			output_path / f"{pcap_path.stem}_traffic_volume.csv"
			if output_path.is_dir() or output_path.suffix == ""
			else output_path
		)

	csv_path.parent.mkdir(parents=True, exist_ok=True)

	connections: dict[tuple[str, tuple[str, int, str, int]], TrafficVolumeState] = {}
	token_to_connection: dict[str, tuple[str, tuple[str, int, str, int]]] = {}
	endpoint_to_connection: dict[tuple[str, int, str, int], tuple[str, tuple[str, int, str, int]]] = {}
	packet_count = 0
	start_time = time.perf_counter()

	for _, packet_bytes in stream_pcap_packets(pcap_path):
		parsed = parse_mptcp_packet(packet_bytes)
		if parsed is None:
			continue

		packet_count += 1
		token, endpoint_key = _connection_key(parsed)
		connection_key = (token, endpoint_key)
		if token:
			connection_key = token_to_connection.get(token, connection_key)
		else:
			connection_key = endpoint_to_connection.get(endpoint_key, connection_key)

		state = connections.get(connection_key)
		if state is None:
			state = TrafficVolumeState(
				connection_id=token or f"conn_{len(connections) + 1}",
				source_endpoint=(parsed["src_ip"], parsed["sport"]),
			)
			connections[connection_key] = state
			if token:
				token_to_connection[token] = connection_key

		state.update(parsed)
		endpoint_to_connection[endpoint_key] = connection_key

		if limit_packets is not None and packet_count >= limit_packets:
			break

	with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow([
			"PCAP File",
			"MPTCP Connection ID",
			"Total Packets Sent",
			"Total Packets Received",
			"Total Packets",
			"Total Bytes Sent",
			"Total Bytes Received",
			"Total Bytes",
			"Total Payload Bytes",
		])
		for state in sorted(connections.values(), key=lambda item: item.connection_id):
			total_packets = state.packets_sent + state.packets_received
			total_bytes = state.bytes_sent + state.bytes_received
			writer.writerow([
				pcap_path.name,
				state.connection_id,
				state.packets_sent,
				state.packets_received,
				total_packets,
				state.bytes_sent,
				state.bytes_received,
				total_bytes,
				state.payload_bytes,
			])

	return {
		"pcap_file": str(pcap_path),
		"csv_file": str(csv_path),
		"packet_count": packet_count,
		"connection_count": len(connections),
		"csv_size_bytes": csv_path.stat().st_size,
		"processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
	}


def main() -> None:
	import argparse

	parser = argparse.ArgumentParser(description="Extract MPTCP traffic volume metrics into CSV.")
	parser.add_argument("input", help="PCAP file or folder containing PCAP files.")
	parser.add_argument("--output-dir", "-o", default=None, help="Optional output directory.")
	parser.add_argument("--limit", "-l", type=int, default=None, help="Maximum packets per file.")
	args = parser.parse_args()

	input_path = Path(args.input).expanduser().resolve()
	pcap_files = (
		[input_path]
		if input_path.is_file()
		else sorted(p for p in input_path.rglob("*") if p.is_file() and p.suffix.lower() in PCAP_EXTENSIONS)
		if input_path.is_dir()
		else []
	)
	if not pcap_files:
		print(f"No PCAP files found in: {input_path}")
		return

	for pcap_file in pcap_files:
		result = extract_traffic_volume_to_csv(pcap_file, args.output_dir, args.limit)
		print(f"Processed {pcap_file.name}: {result['connection_count']} connection(s) -> {result['csv_file']}")


if __name__ == "__main__":
	main()
