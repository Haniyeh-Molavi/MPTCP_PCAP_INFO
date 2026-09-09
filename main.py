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
    from protocol_layer.ip import extract_ip_to_csv
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
    from protocol_layer.ip import extract_ip_to_csv

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


def _pcap_worker(task: tuple) -> dict:
    """Worker function for multiprocessing pool to process a PCAP file across requested protocol layers."""
    pcap_path_str, output_dir_str, link_speed_bps, limit_packets, layers = task
    pcap_path = Path(pcap_path_str)
    output_dir = Path(output_dir_str) if output_dir_str else None

    result: dict = {
        "pcap_file": str(pcap_path),
        "pcap_name": pcap_path.name,
    }

    t0 = time.perf_counter()

    # 1. Ethernet Layer extraction
    if "ethernet" in layers:
        try:
            eth_res = extract_ethernet_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                link_speed_bps=link_speed_bps,
                limit_packets=limit_packets,
            )
            result["ethernet"] = eth_res
        except Exception as exc:
            result["ethernet_error"] = str(exc)

    # 2. IP Layer extraction
    if "ip" in layers:
        try:
            ip_res = extract_ip_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["ip"] = ip_res
        except Exception as exc:
            result["ip_error"] = str(exc)

    result["total_worker_time"] = max(time.perf_counter() - t0, 1e-9)
    return result


def process_folder_protocol_layers(
    folder: Path | str,
    output_dir: Path | str | None = None,
    layers: tuple[str, ...] = ("ethernet", "ip"),
    link_speed_bps: float = DEFAULT_LINK_SPEED_BPS,
    max_workers: int | None = None,
    limit_packets: int | None = None,
    recursive: bool = True,
) -> list[dict]:
    """
    Find all PCAP files in folder and automatically dispatch each PCAP to the requested
    protocol layer extractors (protocol_layer/ethernet.py and protocol_layer/ip.py).

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
            task = (str(pcap), out_dir_str, link_speed_bps, limit_packets, layers)
            results.append(_pcap_worker(task))
        return results

    # Parallel processing across multiple CPU cores
    workers = max_workers or min(os.cpu_count() or 1, len(pcap_files))
    tasks = [
        (str(pcap), out_dir_str, link_speed_bps, limit_packets, layers)
        for pcap in pcap_files
    ]

    results = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        future_to_file = {
            executor.submit(_pcap_worker, task): Path(task[0])
            for task in tasks
        }
        for future in as_completed(future_to_file):
            pcap = future_to_file[future]
            try:
                res = future.result()
                results.append(res)
            except Exception as exc:
                results.append({
                    "pcap_file": str(pcap),
                    "pcap_name": pcap.name,
                    "error": str(exc),
                })

    results.sort(key=lambda x: x["pcap_file"])
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract protocol layer features (Ethernet & IP) from PCAP files into CSV."
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default=".",
        help="Folder containing PCAP files (default: current directory).",
    )
    parser.add_argument(
        "--layer",
        choices=["all", "ethernet", "ip"],
        default="all",
        help="Protocol layer(s) to extract: 'all' (default), 'ethernet', or 'ip'.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default=None,
        help="Optional directory to save CSV files (default: alongside source PCAP).",
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
        help="Interface link speed for Ethernet utilization (e.g. 100M, 1G, 10G; default: 1G).",
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

    if args.layer == "all":
        selected_layers = ("ethernet", "ip")
    elif args.layer == "ethernet":
        selected_layers = ("ethernet",)
    else:
        selected_layers = ("ip",)

    t_start = time.perf_counter()
    results = process_folder_protocol_layers(
        folder=folder,
        output_dir=args.output_dir,
        layers=selected_layers,
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

    layer_names = " & ".join(l.upper() for l in selected_layers)
    print(f"\nProcessed {len(results)} PCAP file(s) across [{layer_names}] layers:")
    print("=" * 125)

    header_cols = f"{'PCAP File':<32} "
    if "ethernet" in selected_layers:
        header_cols += f"{'Ethernet CSV':<28} {'Frames':>10} "
    if "ip" in selected_layers:
        header_cols += f"{'IP CSV':<28} {'IP Pkts':>10} {'Paths':>6} "
    header_cols += f"{'Speed':>14} {'Status':>8}"

    print(header_cols)
    print("-" * 125)

    total_frames = 0
    total_ip_pkts = 0

    for item in results:
        pcap_name = item["pcap_name"]
        row_str = f"{pcap_name:<32} "
        status = "OK"

        if "ethernet" in selected_layers:
            eth = item.get("ethernet")
            if eth:
                csv_name = Path(eth["csv_file"]).name
                cnt = eth["packet_count"]
                total_frames += cnt
                row_str += f"{csv_name:<28} {cnt:>10,d} "
            else:
                row_str += f"{'ERROR':<28} {'N/A':>10} "
                status = "ERR"

        if "ip" in selected_layers:
            ip_info = item.get("ip")
            if ip_info:
                csv_name = Path(ip_info["csv_file"]).name
                cnt = ip_info["packet_count"]
                paths = ip_info["path_count"]
                total_ip_pkts += cnt
                row_str += f"{csv_name:<28} {cnt:>10,d} {paths:>6d} "
            else:
                row_str += f"{'ERROR':<28} {'N/A':>10} {'N/A':>6} "
                status = "ERR"

        worker_time = item.get("total_worker_time", 1.0)
        pps = (total_frames or total_ip_pkts) / max(worker_time, 1e-9)
        pps_str = f"{pps:,.0f} pkt/s"
        row_str += f"{pps_str:>14} {status:>8}"
        print(row_str)

    print("=" * 125)
    summary_text = f"Summary: {len(results)} files processed in {total_elapsed:.2f}s"
    if "ethernet" in selected_layers:
        summary_text += f" | {total_frames:,d} Ethernet frames"
    if "ip" in selected_layers:
        summary_text += f" | {total_ip_pkts:,d} IP packets"
    print(f"{summary_text}\n")


if __name__ == "__main__":
    main()
