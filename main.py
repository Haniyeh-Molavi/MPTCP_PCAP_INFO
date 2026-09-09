from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator, Tuple

# Attempt high-performance parser import (dpkt is ~10-50x faster than scapy)
try:
    import dpkt
except ImportError:
    dpkt = None

# Attempt Scapy fallback (streaming raw reader, avoids full layer object trees)
try:
    from scapy.utils import RawPcapReader, RawPcapNgReader
except ImportError:
    RawPcapReader = None
    RawPcapNgReader = None


# Known magic bytes for fast format detection
PCAP_LE = b"\xd4\xc3\xb2\xa1"
PCAP_BE = b"\xa1\xb2\xc3\xd4"
PCAP_NS_LE = b"\x4d\x3c\xb2\xa1"
PCAP_NS_BE = b"\xa1\xb2\x3c\x4d"
PCAP_CLASSIC_MAGICS = {PCAP_LE, PCAP_BE, PCAP_NS_LE, PCAP_NS_BE}

PCAPNG_MAGIC = b"\n\r\r\n"  # 0x0A0D0D0A (Section Header Block)

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}
DEFAULT_BUFFER_SIZE = 4 * 1024 * 1024  # 4 MB read buffer for high disk throughput


def format_bytes(size: int | float) -> str:
    """Format bytes into human-readable representation."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.2f} PB"


def detect_pcap_format(file_path: Path) -> str:
    """
    Inspect the first 4 bytes of the file to determine if it is classic PCAP or PCAPNG.
    Returns 'pcap', 'pcapng', or 'unknown'.
    """
    try:
        with file_path.open("rb") as f:
            magic = f.read(4)
            if magic in PCAP_CLASSIC_MAGICS:
                return "pcap"
            if magic == PCAPNG_MAGIC:
                return "pcapng"
    except OSError:
        pass

    # Fallback to extension check
    suffix = file_path.suffix.lower()
    if suffix in {".pcap", ".cap"}:
        return "pcap"
    if suffix == ".pcapng":
        return "pcapng"

    return "unknown"


def find_pcap_files(folder: Path | str, recursive: bool = True) -> list[Path]:
    """Return all PCAP-like files under the given folder."""
    folder = Path(folder).expanduser().resolve()
    if not folder.exists():
        raise FileNotFoundError(f"Folder not found: {folder}")

    files = []
    pattern_iter = folder.rglob("*") if recursive else folder.glob("*")
    for path in pattern_iter:
        if path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS:
            files.append(path)

    return sorted(files)


def stream_pcap_packets(
    file_path: Path | str,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> Iterator[Tuple[float, bytes]]:
    """
    Stream packets from a PCAP or PCAPNG file without loading the capture into memory.
    Yields (timestamp: float, packet_bytes: bytes).

    Uses dpkt for maximum throughput (~600k+ pkts/s), with seamless fallback to
    Scapy's streaming RawPcapReader / RawPcapNgReader.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    fmt = detect_pcap_format(file_path)

    # 1. Primary Engine: DPKT (Fastest, zero layer-overhead)
    if dpkt is not None:
        try:
            with file_path.open("rb", buffering=buffer_size) as handle:
                if fmt == "pcapng":
                    reader = dpkt.pcapng.Reader(handle)
                else:
                    reader = dpkt.pcap.Reader(handle)

                for timestamp, packet_bytes in reader:
                    yield float(timestamp), packet_bytes
                return
        except (dpkt.NeedData, EOFError):
            # Gracefully handle truncated file at end
            return
        except Exception:
            # If dpkt encounters an unhandled block type, fall back to Scapy
            pass

    # 2. Fallback Engine: Scapy Raw Streaming Readers
    str_path = str(file_path)
    if fmt == "pcapng" and RawPcapNgReader is not None:
        try:
            for packet_bytes, metadata in RawPcapNgReader(str_path):
                if hasattr(metadata, "tshigh") and hasattr(metadata, "tslow"):
                    resol = float(getattr(metadata, "tsresol", 1e6) or 1e6)
                    ts = float((metadata.tshigh << 32) | metadata.tslow) / resol
                elif hasattr(metadata, "sec") and hasattr(metadata, "usec"):
                    ts = float(metadata.sec) + float(metadata.usec) / 1e6
                elif hasattr(metadata, "time"):
                    ts = float(metadata.time)
                else:
                    ts = 0.0
                yield ts, packet_bytes
            return
        except Exception:
            pass

    if RawPcapReader is not None:
        try:
            for packet_bytes, metadata in RawPcapReader(str_path):
                if hasattr(metadata, "sec") and hasattr(metadata, "usec"):
                    ts = float(metadata.sec) + float(metadata.usec) / 1e6
                elif hasattr(metadata, "time"):
                    ts = float(metadata.time)
                else:
                    ts = 0.0
                yield ts, packet_bytes
            return
        except Exception:
            pass

    # If neither succeeded or libraries missing
    if dpkt is None and RawPcapReader is None:
        raise RuntimeError(
            "Neither dpkt nor scapy is installed. Please install dpkt for best performance:\n"
            "  pip install dpkt"
        )
    raise RuntimeError(f"Unable to read PCAP file '{file_path}' with available libraries.")


def process_pcap_file(
    file_path: Path | str,
    limit_packets: int | None = None,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> dict:
    """
    Stream and summarize a single PCAP/PCAPNG file.
    Returns a dictionary of metrics:
      - file: str
      - file_name: str
      - file_size_bytes: int
      - packet_count: int
      - payload_bytes: int
      - first_timestamp: float | None
      - last_timestamp: float | None
      - duration_seconds: float
      - processing_time_seconds: float
      - throughput_packets_per_sec: float
      - throughput_mb_per_sec: float
    """
    file_path = Path(file_path)
    file_size = file_path.stat().st_size if file_path.exists() else 0
    packet_count = 0
    payload_bytes = 0
    first_ts: float | None = None
    last_ts: float | None = None

    t_start = time.perf_counter()

    for ts, pkt_bytes in stream_pcap_packets(file_path, buffer_size=buffer_size):
        packet_count += 1
        payload_bytes += len(pkt_bytes)
        if first_ts is None:
            first_ts = ts
        last_ts = ts

        if limit_packets is not None and packet_count >= limit_packets:
            break

    t_elapsed = max(time.perf_counter() - t_start, 1e-9)

    duration = 0.0
    if first_ts is not None and last_ts is not None:
        duration = max(0.0, last_ts - first_ts)

    throughput_pps = packet_count / t_elapsed
    throughput_mbps = (payload_bytes / (1024 * 1024)) / t_elapsed

    return {
        "file": str(file_path),
        "file_name": file_path.name,
        "file_size_bytes": file_size,
        "packet_count": packet_count,
        "payload_bytes": payload_bytes,
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "duration_seconds": duration,
        "processing_time_seconds": t_elapsed,
        "throughput_packets_per_sec": throughput_pps,
        "throughput_mb_per_sec": throughput_mbps,
    }


def _process_file_worker(file_path_str: str, limit_packets: int | None) -> dict:
    """Helper for parallel execution across process boundaries."""
    return process_pcap_file(Path(file_path_str), limit_packets=limit_packets)


def stream_folder_packets(
    folder: Path | str,
    recursive: bool = True,
    limit_packets: int | None = None,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> Iterator[Tuple[Path, float, bytes]]:
    """
    Sequentially stream packets across all PCAP files found in the given folder.
    Yields (file_path: Path, timestamp: float, packet_bytes: bytes).
    Memory footprint remains O(1) regardless of total dataset size.
    """
    folder = Path(folder)
    total_yielded = 0

    for file_path in find_pcap_files(folder, recursive=recursive):
        for ts, pkt_bytes in stream_pcap_packets(file_path, buffer_size=buffer_size):
            yield file_path, ts, pkt_bytes
            total_yielded += 1
            if limit_packets is not None and total_yielded >= limit_packets:
                return


def process_folder(
    folder: Path | str,
    recursive: bool = True,
    max_workers: int | None = None,
    limit_packets: int | None = None,
) -> list[dict]:
    """
    Process all PCAP files found in the folder.
    When multiple files exist and max_workers != 1, uses ProcessPoolExecutor to
    process files concurrently across CPU cores.
    """
    folder = Path(folder)
    pcap_files = find_pcap_files(folder, recursive=recursive)

    if not pcap_files:
        return []

    # If only 1 file or explicit single worker, run sequentially
    if len(pcap_files) == 1 or max_workers == 1:
        return [process_pcap_file(f, limit_packets=limit_packets) for f in pcap_files]

    # Parallel processing across CPU cores
    workers = max_workers or min(os.cpu_count() or 1, len(pcap_files))
    results = []

    with ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_file = {
            executor.submit(_process_file_worker, str(f), limit_packets): f
            for f in pcap_files
        }
        for future in as_completed(future_to_file):
            file_path = future_to_file[future]
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                results.append(
                    {
                        "file": str(file_path),
                        "file_name": file_path.name,
                        "error": str(exc),
                        "packet_count": 0,
                        "payload_bytes": 0,
                        "file_size_bytes": file_path.stat().st_size if file_path.exists() else 0,
                        "first_timestamp": None,
                        "last_timestamp": None,
                        "duration_seconds": 0.0,
                        "processing_time_seconds": 0.0,
                        "throughput_packets_per_sec": 0.0,
                        "throughput_mb_per_sec": 0.0,
                    }
                )

    results.sort(key=lambda x: x["file"])
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="High-performance streaming reader for large PCAP/PCAPNG files in a folder."
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default=".",
        help="Folder containing PCAP files (default: current directory).",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=None,
        help="Number of parallel worker processes (default: CPU count).",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=None,
        help="Optional maximum number of packets to process per file.",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Do not scan subdirectories recursively.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output summary results in JSON format.",
    )
    args = parser.parse_args()

    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists():
        print(f"Error: Folder does not exist: {folder}", file=sys.stderr)
        sys.exit(1)

    t_start = time.perf_counter()
    results = process_folder(
        folder=folder,
        recursive=not args.no_recursive,
        max_workers=args.workers,
        limit_packets=args.limit,
    )
    total_elapsed = time.perf_counter() - t_start

    if not results:
        print(f"No PCAP files found in: {folder}")
        return

    if args.json:
        print(json.dumps(results, indent=2))
        return

    total_packets = sum(r.get("packet_count", 0) for r in results)
    total_file_bytes = sum(r.get("file_size_bytes", 0) for r in results)
    total_payload_bytes = sum(r.get("payload_bytes", 0) for r in results)
    overall_throughput_pps = total_packets / max(total_elapsed, 1e-9)
    overall_throughput_mb = (total_payload_bytes / (1024 * 1024)) / max(total_elapsed, 1e-9)

    print(f"\nProcessed {len(results)} file(s) in: {folder}")
    print("=" * 100)
    print(
        f"{'File':<40} {'Size':>10} {'Packets':>10} {'Throughput':>16} {'Elapsed':>10} {'Status':>10}"
    )
    print("-" * 100)

    for item in results:
        if "error" in item:
            status = "ERROR"
            size_str = format_bytes(item["file_size_bytes"])
            print(f"{item['file_name']:<40} {size_str:>10} {'N/A':>10} {'N/A':>16} {'N/A':>10} {status:>10}")
        else:
            status = "OK"
            size_str = format_bytes(item["file_size_bytes"])
            pps_str = f"{item['throughput_packets_per_sec']:,.0f} pkt/s"
            elapsed_str = f"{item['processing_time_seconds']:.2f}s"
            print(
                f"{item['file_name']:<40} {size_str:>10} {item['packet_count']:>10,d} {pps_str:>16} {elapsed_str:>10} {status:>10}"
            )

    print("=" * 100)
    print(
        f"Summary: {len(results)} files | {total_packets:,d} total packets | "
        f"{format_bytes(total_file_bytes)} total size | {total_elapsed:.2f}s total time "
        f"({overall_throughput_pps:,.0f} pkt/s, {overall_throughput_mb:.2f} MB/s)\n"
    )


if __name__ == "__main__":
    main()
