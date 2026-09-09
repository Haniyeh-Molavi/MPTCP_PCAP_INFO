from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator, Tuple

# Ensure workspace root is in sys.path for protocol_layer package imports
_CURRENT_DIR = Path(__file__).resolve().parent
if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))

try:
    from protocol_layer.ethernet import (
        DEFAULT_LINK_SPEED_BPS,
        extract_ethernet_to_csv,
        parse_link_speed,
        stream_pcap_packets,
    )
except ImportError:
    # Fallback if running directly inside folder
    _ALT_DIR = _CURRENT_DIR / "protocol_layer"
    if str(_ALT_DIR) not in sys.path:
        sys.path.insert(0, str(_ALT_DIR))
    from protocol_layer.ethernet import (
        DEFAULT_LINK_SPEED_BPS,
        extract_ethernet_to_csv,
        parse_link_speed,
        stream_pcap_packets,
    )

PCAP_EXTENSIONS = {".pcap", ".cap", ".pcapng"}


def format_bytes(size: int | float) -> str:
    """Format bytes into human-readable representation."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.2f} PB"


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


def stream_folder_packets(
    folder: Path | str,
    recursive: bool = True,
    limit_packets: int | None = None,
) -> Iterator[Tuple[Path, float, bytes]]:
    """
    Sequentially stream packets across all PCAP files found in the given folder.
    Yields (file_path: Path, timestamp: float, packet_bytes: bytes).
    Memory footprint remains O(1) regardless of total dataset size.
    """
    folder = Path(folder)
    total_yielded = 0

    for file_path in find_pcap_files(folder, recursive=recursive):
        for ts, pkt_bytes in stream_pcap_packets(file_path):
            yield file_path, ts, pkt_bytes
            total_yielded += 1
            if limit_packets is not None and total_yielded >= limit_packets:
                return


def _ethernet_worker(task: tuple[str, str | None, float, int | None]) -> dict:
    """Worker function for multiprocessing pool to process a PCAP file with ethernet.py."""
    pcap_path_str, output_dir_str, link_speed_bps, limit_packets = task
    pcap_path = Path(pcap_path_str)
    output_dir = Path(output_dir_str) if output_dir_str else None
    return extract_ethernet_to_csv(
        pcap_path=pcap_path,
        output_csv_path=output_dir,
        link_speed_bps=link_speed_bps,
        limit_packets=limit_packets,
    )


def process_folder_ethernet(
    folder: Path | str,
    output_dir: Path | str | None = None,
    link_speed_bps: float = DEFAULT_LINK_SPEED_BPS,
    max_workers: int | None = None,
    limit_packets: int | None = None,
    recursive: bool = True,
) -> list[dict]:
    """
    Find all PCAP files in folder, bring each PCAP to ethernet.py to extract features,
    and save them into CSV files with the same name as the PCAP files.

    Uses ProcessPoolExecutor for concurrent multi-file processing on large captures.
    """
    folder = Path(folder).expanduser().resolve()
    pcap_files = find_pcap_files(folder, recursive=recursive)

    if not pcap_files:
        return []

    out_dir_str = str(Path(output_dir).resolve()) if output_dir else None

    # If only 1 file or explicit single worker, run sequentially
    if len(pcap_files) == 1 or max_workers == 1:
        results = []
        for pcap in pcap_files:
            try:
                res = extract_ethernet_to_csv(
                    pcap_path=pcap,
                    output_csv_path=Path(out_dir_str) if out_dir_str else None,
                    link_speed_bps=link_speed_bps,
                    limit_packets=limit_packets,
                )
                results.append(res)
            except Exception as exc:
                csv_name = f"{pcap.stem}.csv"
                results.append({
                    "pcap_file": str(pcap),
                    "csv_file": str(Path(out_dir_str) / csv_name if out_dir_str else pcap.with_suffix(".csv")),
                    "error": str(exc),
                    "packet_count": 0,
                    "total_bytes": 0,
                    "csv_size_bytes": 0,
                    "min_frame_size": 0,
                    "max_frame_size": 0,
                    "avg_frame_size": 0.0,
                    "processing_time_seconds": 0.0,
                    "throughput_packets_per_sec": 0.0,
                })
        return results

    # Parallel processing across multiple CPU cores
    workers = max_workers or min(os.cpu_count() or 1, len(pcap_files))
    tasks = [
        (str(pcap), out_dir_str, link_speed_bps, limit_packets)
        for pcap in pcap_files
    ]

    results = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_file = {
            executor.submit(_ethernet_worker, task): Path(task[0])
            for task in tasks
        }
        for future in as_completed(future_to_file):
            pcap = future_to_file[future]
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                csv_name = f"{pcap.stem}.csv"
                results.append({
                    "pcap_file": str(pcap),
                    "csv_file": str(Path(out_dir_str) / csv_name if out_dir_str else pcap.with_suffix(".csv")),
                    "error": str(exc),
                    "packet_count": 0,
                    "total_bytes": 0,
                    "csv_size_bytes": 0,
                    "min_frame_size": 0,
                    "max_frame_size": 0,
                    "avg_frame_size": 0.0,
                    "processing_time_seconds": 0.0,
                    "throughput_packets_per_sec": 0.0,
                })

    results.sort(key=lambda x: x["pcap_file"])
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract Ethernet features from PCAP/PCAPNG files into CSV using ethernet.py."
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default=".",
        help="Folder containing PCAP files (default: current directory).",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help="Optional directory to save CSV files (default: same directory as PCAP).",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=None,
        help="Number of parallel worker processes (default: CPU count).",
    )
    parser.add_argument(
        "--link-speed",
        "-s",
        default="1G",
        help="Interface link speed for utilization evaluation (e.g. 100M, 1G, 10G; default: 1G).",
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
    # If run with default '.' and no PCAPs found in current directory, prompt interactively
    if args.folder == "." and not find_pcap_files(folder, recursive=not args.no_recursive):
        if sys.stdin.isatty():
            try:
                entered = input("Enter path to folder containing PCAP files: ").strip().strip('"\'')
                if entered:
                    folder = Path(entered).expanduser().resolve()
            except (EOFError, KeyboardInterrupt):
                sys.exit(0)

    if not folder.exists():
        print(f"Error: Folder does not exist: {folder}", file=sys.stderr)
        sys.exit(1)

    link_speed_bps = parse_link_speed(args.link_speed)

    t_start = time.perf_counter()
    results = process_folder_ethernet(
        folder=folder,
        output_dir=args.output_dir,
        link_speed_bps=link_speed_bps,
        max_workers=args.workers,
        limit_packets=args.limit,
        recursive=not args.no_recursive,
    )
    total_elapsed = time.perf_counter() - t_start

    if not results:
        print(f"No PCAP files found in: {folder}")
        return

    if args.json:
        print(json.dumps(results, indent=2))
        return

    total_packets = sum(r.get("packet_count", 0) for r in results)
    total_payload = sum(r.get("total_bytes", 0) for r in results)
    overall_pps = total_packets / max(total_elapsed, 1e-9)
    overall_mb = (total_payload / (1024 * 1024)) / max(total_elapsed, 1e-9)

    print(f"\nProcessed {len(results)} PCAP file(s) via protocol layer/ethernet.py:")
    print("=" * 110)
    print(
        f"{'PCAP File':<30} {'CSV File':<30} {'Frames':>10} {'Avg Size':>10} {'Min/Max':>12} {'Speed':>14}"
    )
    print("-" * 110)

    for item in results:
        pcap_name = Path(item["pcap_file"]).name
        csv_name = Path(item["csv_file"]).name
        if "error" in item:
            print(f"{pcap_name:<30} {csv_name:<30} {'ERROR':>10} {'N/A':>10} {'N/A':>12} {'N/A':>14}")
        else:
            min_max_str = f"{item['min_frame_size']}/{item['max_frame_size']}"
            pps_str = f"{item['throughput_packets_per_sec']:,.0f} pkt/s"
            print(
                f"{pcap_name:<30} {csv_name:<30} {item['packet_count']:>10,d} "
                f"{item['avg_frame_size']:>10.1f} {min_max_str:>12} {pps_str:>14}"
            )

    print("=" * 110)
    print(
        f"Summary: {len(results)} files converted to CSV | {total_packets:,d} total frames | "
        f"{format_bytes(total_payload)} total data | {total_elapsed:.2f}s total time "
        f"({overall_pps:,.0f} pkt/s, {overall_mb:.2f} MB/s)\n"
    )


if __name__ == "__main__":
    main()
