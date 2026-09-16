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

    def stream_pcap_packets(file_path):
        with open(file_path, "rb") as f:
            reader = dpkt.pcap.Reader(f)
            for ts, pkt in reader:
                yield float(ts), pkt


class DSSMetricState:
    def __init__(self, connection_id: str):
        self.connection_id = connection_id

        self.dsn_values = []
        self.data_ack_values = []
        self.mapping_lengths = []

    def update(self, parsed):
        dsn = parsed.get("data_sequence_number")
        if dsn is not None:
            self.dsn_values.append(dsn)

        ack = parsed.get("data_ack")
        if ack is not None:
            self.data_ack_values.append(ack)

        mapping_length = (
            parsed.get("data_level_length")
            or parsed.get("dsn_length")
            or parsed.get("mapping_length")
        )

        if mapping_length is not None:
            self.mapping_lengths.append(mapping_length)