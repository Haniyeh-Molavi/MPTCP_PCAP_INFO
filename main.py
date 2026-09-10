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
    from protocol_layer.tcp import extract_tcp_to_csv
    from protocol_layer.mptcp_level import extract_mptcp_to_csv
    from protocol_layer.MP_CAPABLE import extract_mp_capable_to_csv
    from protocol_layer.MP_JOIN import extract_mp_join_to_csv
    from protocol_layer.DSS import extract_dss_to_csv
    from protocol_layer.ADD_ADDR import extract_add_addr_to_csv
    from protocol_layer.REMOVE_ADDR import extract_remove_addr_to_csv
    from protocol_layer.MP_PRIO import extract_mp_prio_to_csv
    from protocol_layer.MP_FAIL import extract_mp_fail_to_csv
    from protocol_layer.MP_FASTCLOSE import extract_mp_fastclose_to_csv
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
    from protocol_layer.tcp import extract_tcp_to_csv
    from protocol_layer.mptcp_level import extract_mptcp_to_csv
    from protocol_layer.MP_CAPABLE import extract_mp_capable_to_csv
    from protocol_layer.MP_JOIN import extract_mp_join_to_csv
    from protocol_layer.DSS import extract_dss_to_csv
    from protocol_layer.ADD_ADDR import extract_add_addr_to_csv
    from protocol_layer.REMOVE_ADDR import extract_remove_addr_to_csv
    from protocol_layer.MP_PRIO import extract_mp_prio_to_csv
    from protocol_layer.MP_FAIL import extract_mp_fail_to_csv
    from protocol_layer.MP_FASTCLOSE import extract_mp_fastclose_to_csv

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

    # 3. TCP Layer extraction
    if "tcp" in layers:
        try:
            tcp_res = extract_tcp_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["tcp"] = tcp_res
        except Exception as exc:
            result["tcp_error"] = str(exc)

    # 4. MPTCP Layer extraction
    if "mptcp" in layers:
        try:
            mptcp_res = extract_mptcp_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["mptcp"] = mptcp_res
        except Exception as exc:
            result["mptcp_error"] = str(exc)

    # 5. MP_CAPABLE extraction
    if "mp_capable" in layers:
        try:
            mp_capable_res = extract_mp_capable_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["mp_capable"] = mp_capable_res
        except Exception as exc:
            result["mp_capable_error"] = str(exc)

    # 6. MP_JOIN extraction
    if "mp_join" in layers:
        try:
            mp_join_res = extract_mp_join_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["mp_join"] = mp_join_res
        except Exception as exc:
            result["mp_join_error"] = str(exc)

    # 7. DSS extraction
    if "dss" in layers:
        try:
            dss_res = extract_dss_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["dss"] = dss_res
        except Exception as exc:
            result["dss_error"] = str(exc)

    # 8. ADD_ADDR extraction
    if "add_addr" in layers:
        try:
            add_addr_res = extract_add_addr_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["add_addr"] = add_addr_res
        except Exception as exc:
            result["add_addr_error"] = str(exc)

    # 9. REMOVE_ADDR extraction
    if "remove_addr" in layers:
        try:
            remove_addr_res = extract_remove_addr_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["remove_addr"] = remove_addr_res
        except Exception as exc:
            result["remove_addr_error"] = str(exc)

    # 10. MP_PRIO extraction
    if "mp_prio" in layers:
        try:
            mp_prio_res = extract_mp_prio_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["mp_prio"] = mp_prio_res
        except Exception as exc:
            result["mp_prio_error"] = str(exc)

    # 11. MP_FAIL extraction
    if "mp_fail" in layers:
        try:
            mp_fail_res = extract_mp_fail_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["mp_fail"] = mp_fail_res
        except Exception as exc:
            result["mp_fail_error"] = str(exc)

    # 12. MP_FASTCLOSE extraction
    if "mp_fastclose" in layers:
        try:
            mp_fastclose_res = extract_mp_fastclose_to_csv(
                pcap_path=pcap_path,
                output_csv_path=output_dir,
                limit_packets=limit_packets,
            )
            result["mp_fastclose"] = mp_fastclose_res
        except Exception as exc:
            result["mp_fastclose_error"] = str(exc)

    result["total_worker_time"] = max(time.perf_counter() - t0, 1e-9)
    return result


def process_folder_protocol_layers(
    folder: Path | str,
    output_dir: Path | str | None = None,
    layers: tuple[str, ...] = ("ethernet", "ip", "tcp", "mptcp"),
    link_speed_bps: float = DEFAULT_LINK_SPEED_BPS,
    max_workers: int | None = None,
    limit_packets: int | None = None,
    recursive: bool = True,
) -> list[dict]:
    """
    Find all PCAP files in folder and automatically dispatch each PCAP to the requested
    protocol layer extractors (ethernet, ip, tcp, mptcp).

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
        description="Extract protocol layer features (Ethernet, IP, TCP, MPTCP) from PCAP files into CSV."
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default=".",
        help="Folder containing PCAP files (default: current directory).",
    )
    parser.add_argument(
        "--layer",
        choices=["all", "ethernet", "ip", "tcp", "mptcp", "mp_capable", "mp_join", "dss", "add_addr", "remove_addr", "mp_prio", "mp_fail", "mp_fastclose"],
        default="all",
        help="Protocol layer(s) to extract: 'all' (default), 'ethernet', 'ip', 'tcp', 'mptcp', 'mp_capable', 'mp_join', 'dss', 'add_addr', 'remove_addr', 'mp_prio', 'mp_fail', or 'mp_fastclose'.",
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
        selected_layers = ("ethernet", "ip", "tcp", "mptcp", "mp_capable", "mp_join", "dss", "add_addr", "remove_addr", "mp_prio", "mp_fail", "mp_fastclose")
    elif args.layer == "ethernet":
        selected_layers = ("ethernet",)
    elif args.layer == "ip":
        selected_layers = ("ip",)
    elif args.layer == "tcp":
        selected_layers = ("tcp",)
    elif args.layer == "mptcp":
        selected_layers = ("mptcp",)
    elif args.layer == "mp_capable":
        selected_layers = ("mp_capable",)
    elif args.layer == "mp_join":
        selected_layers = ("mp_join",)
    elif args.layer == "dss":
        selected_layers = ("dss",)
    elif args.layer == "add_addr":
        selected_layers = ("add_addr",)
    elif args.layer == "remove_addr":
        selected_layers = ("remove_addr",)
    elif args.layer == "mp_prio":
        selected_layers = ("mp_prio",)
    elif args.layer == "mp_fail":
        selected_layers = ("mp_fail",)
    else:
        selected_layers = ("mp_fastclose",)

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
    print("=" * 135)

    header_cols = f"{'PCAP File':<32} "
    if "ethernet" in selected_layers:
        header_cols += f"{'Ethernet CSV':<24} {'Frames':>8} "
    if "ip" in selected_layers:
        header_cols += f"{'IP CSV':<24} {'IP Pkts':>8} "
    if "tcp" in selected_layers:
        header_cols += f"{'TCP CSV':<24} {'TCP Pkts':>8} {'Flows':>6} "
    if "mptcp" in selected_layers:
        header_cols += f"{'MPTCP CSV':<24} {'MPTCP Pkts':>10} {'Conns':>6} "
    if "mp_capable" in selected_layers:
        header_cols += f"{'MP_CAPABLE CSV':<24} {'Sessions':>8} "
    if "mp_join" in selected_layers:
        header_cols += f"{'MP_JOIN CSV':<24} {'Events':>8} "
    if "dss" in selected_layers:
        header_cols += f"{'DSS CSV':<24} {'Events':>8} "
    if "add_addr" in selected_layers:
        header_cols += f"{'ADD_ADDR CSV':<24} {'Events':>8} "
    if "remove_addr" in selected_layers:
        header_cols += f"{'REMOVE_ADDR CSV':<24} {'Events':>8} "
    if "mp_prio" in selected_layers:
        header_cols += f"{'MP_PRIO CSV':<24} {'Events':>8} "
    if "mp_fail" in selected_layers:
        header_cols += f"{'MP_FAIL CSV':<24} {'Events':>8} "
    if "mp_fastclose" in selected_layers:
        header_cols += f"{'MP_FASTCLOSE CSV':<24} {'Events':>8} "
    header_cols += f"{'Speed':>14} {'Status':>8}"

    print(header_cols)
    print("-" * 160)

    total_frames = 0
    total_ip_pkts = 0
    total_tcp_pkts = 0
    total_mptcp_pkts = 0

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
                row_str += f"{csv_name:<24} {cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "ip" in selected_layers:
            ip_info = item.get("ip")
            if ip_info:
                csv_name = Path(ip_info["csv_file"]).name
                cnt = ip_info["packet_count"]
                total_ip_pkts += cnt
                row_str += f"{csv_name:<24} {cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "tcp" in selected_layers:
            tcp_info = item.get("tcp")
            if tcp_info:
                csv_name = Path(tcp_info["csv_file"]).name
                cnt = tcp_info["packet_count"]
                flows_cnt = tcp_info["tcp_flows_count"]
                total_tcp_pkts += cnt
                row_str += f"{csv_name:<24} {cnt:>8,d} {flows_cnt:>6d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} {'N/A':>6} "
                status = "ERR"

        if "mptcp" in selected_layers:
            mptcp_info = item.get("mptcp")
            if mptcp_info:
                csv_name = Path(mptcp_info["csv_file"]).name
                cnt = mptcp_info["packet_count"]
                conns_cnt = mptcp_info["mptcp_conns_count"]
                total_mptcp_pkts += cnt
                row_str += f"{csv_name:<24} {cnt:>10,d} {conns_cnt:>6d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>10} {'N/A':>6} "
                status = "ERR"

        if "mp_capable" in selected_layers:
            mp_capable_info = item.get("mp_capable")
            if mp_capable_info:
                csv_name = Path(mp_capable_info["csv_file"]).name
                sessions_cnt = mp_capable_info["session_count"]
                row_str += f"{csv_name:<24} {sessions_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "mp_join" in selected_layers:
            mp_join_info = item.get("mp_join")
            if mp_join_info:
                csv_name = Path(mp_join_info["csv_file"]).name
                events_cnt = mp_join_info["mp_join_events"]
                row_str += f"{csv_name:<24} {events_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "dss" in selected_layers:
            dss_info = item.get("dss")
            if dss_info:
                csv_name = Path(dss_info["csv_file"]).name
                events_cnt = dss_info["dss_events"]
                row_str += f"{csv_name:<24} {events_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "add_addr" in selected_layers:
            add_addr_info = item.get("add_addr")
            if add_addr_info:
                csv_name = Path(add_addr_info["csv_file"]).name
                events_cnt = add_addr_info["add_addr_events"]
                row_str += f"{csv_name:<24} {events_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "remove_addr" in selected_layers:
            remove_addr_info = item.get("remove_addr")
            if remove_addr_info:
                csv_name = Path(remove_addr_info["csv_file"]).name
                events_cnt = remove_addr_info["remove_addr_events"]
                row_str += f"{csv_name:<24} {events_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "mp_prio" in selected_layers:
            mp_prio_info = item.get("mp_prio")
            if mp_prio_info:
                csv_name = Path(mp_prio_info["csv_file"]).name
                events_cnt = mp_prio_info["mp_prio_events"]
                row_str += f"{csv_name:<24} {events_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "mp_fail" in selected_layers:
            mp_fail_info = item.get("mp_fail")
            if mp_fail_info:
                csv_name = Path(mp_fail_info["csv_file"]).name
                events_cnt = mp_fail_info["mp_fail_events"]
                row_str += f"{csv_name:<24} {events_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        if "mp_fastclose" in selected_layers:
            mp_fastclose_info = item.get("mp_fastclose")
            if mp_fastclose_info:
                csv_name = Path(mp_fastclose_info["csv_file"]).name
                events_cnt = mp_fastclose_info["mp_fastclose_events"]
                row_str += f"{csv_name:<24} {events_cnt:>8,d} "
            else:
                row_str += f"{'ERROR':<24} {'N/A':>8} "
                status = "ERR"

        worker_time = item.get("total_worker_time", 1.0)
        pps = (total_frames or total_ip_pkts or total_tcp_pkts or total_mptcp_pkts) / max(worker_time, 1e-9)
        pps_str = f"{pps:,.0f} pkt/s"
        row_str += f"{pps_str:>14} {status:>8}"
        print(row_str)

    print("=" * 160)
    summary_parts = [f"Summary: {len(results)} files processed in {total_elapsed:.2f}s"]
    if "ethernet" in selected_layers:
        summary_parts.append(f"{total_frames:,d} Ethernet frames")
    if "ip" in selected_layers:
        summary_parts.append(f"{total_ip_pkts:,d} IP packets")
    if "tcp" in selected_layers:
        summary_parts.append(f"{total_tcp_pkts:,d} TCP packets")
    if "mptcp" in selected_layers:
        summary_parts.append(f"{total_mptcp_pkts:,d} MPTCP packets")
    print(" | ".join(summary_parts) + "\n")


if __name__ == "__main__":
    main()
