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


class DSSState:
	def __init__(self, connection_id: str) -> None:
		self.connection_id = connection_id
		self.minimum_dsn: int | None = None
		self.maximum_dsn: int | None = None
		self.final_dsn: int | None = None
		self.data_ack_values: list[int] = []
		self.data_fin_present = False

	def update(self, parsed: dict) -> None:
		dsn = parsed.get("data_sequence_number")
		if dsn is not None:
			self.minimum_dsn = dsn if self.minimum_dsn is None else min(self.minimum_dsn, dsn)
			self.maximum_dsn = dsn if self.maximum_dsn is None else max(self.maximum_dsn, dsn)
			self.final_dsn = dsn

		data_ack = parsed.get("data_ack")
		if data_ack is not None:
			self.data_ack_values.append(data_ack)

		if parsed.get("data_fin"):
			self.data_fin_present = True


def _connection_key(parsed: dict) -> tuple[str, int, str, int]:
	endpoint_a = (parsed["src_ip"], parsed["sport"])
	endpoint_b = (parsed["dst_ip"], parsed["dport"])
	first, second = sorted((endpoint_a, endpoint_b))
	return first[0], first[1], second[0], second[1]


def extract_dss_to_csv(
	pcap_path: Path | str,
	output_csv_path: Path | str | None = None,
	limit_packets: int | None = None,
) -> dict:
	"""Extract aggregate DSS sequence and acknowledgment features per connection."""
	pcap_path = Path(pcap_path).expanduser().resolve()
	if not pcap_path.exists():
		raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

	if output_csv_path is None:
		csv_path = pcap_path.with_name(f"{pcap_path.stem}_dss.csv")
	else:
		output_path = Path(output_csv_path).expanduser().resolve()
		csv_path = (
			output_path / f"{pcap_path.stem}_dss.csv"
			if output_path.is_dir() or output_path.suffix == ""
			else output_path
		)

	csv_path.parent.mkdir(parents=True, exist_ok=True)
	states: dict[tuple[str, int, str, int], DSSState] = {}
	packet_count = 0
	start_time = time.perf_counter()

	for _, packet_bytes in stream_pcap_packets(pcap_path):
		parsed = parse_dss_packet(packet_bytes)
		if parsed is None:
			continue

		packet_count += 1
		key = _connection_key(parsed)
		state = states.get(key)
		if state is None:
			state = DSSState(connection_id=f"conn_{len(states) + 1}")
			states[key] = state
		state.update(parsed)

		if limit_packets is not None and packet_count >= limit_packets:
			break

	with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
		writer = csv.writer(csvfile)
		writer.writerow([
			"PCAP File",
			"MPTCP Connection ID",
			"Minimum DSN",
			"Maximum DSN",
			"Final DSN",
			"Data ACK Values",
			"DATA_FIN Presence",
			"DSN Range",
		])
		for state in sorted(states.values(), key=lambda item: item.connection_id):
			dsn_range = ""
			if state.minimum_dsn is not None and state.maximum_dsn is not None:
				dsn_range = state.maximum_dsn - state.minimum_dsn
			writer.writerow([
				pcap_path.name,
				state.connection_id,
				state.minimum_dsn if state.minimum_dsn is not None else "",
				state.maximum_dsn if state.maximum_dsn is not None else "",
				state.final_dsn if state.final_dsn is not None else "",
				";".join(str(value) for value in state.data_ack_values),
				"1" if state.data_fin_present else "0",
				dsn_range,
			])

	return {
		"pcap_file": str(pcap_path),
		"csv_file": str(csv_path),
		"packet_count": packet_count,
		"connection_count": len(states),
		"dss_events": packet_count,
		"csv_size_bytes": csv_path.stat().st_size,
		"processing_time_seconds": max(time.perf_counter() - start_time, 1e-9),
	}


def main() -> None:
	import argparse

	parser = argparse.ArgumentParser(description="Extract aggregate DSS features into CSV.")
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
		result = extract_dss_to_csv(pcap_file, args.output_dir, args.limit)
		print(f"Processed {pcap_file.name}: {result['connection_count']} connection(s) -> {result['csv_file']}")


if __name__ == "__main__":
	main()
