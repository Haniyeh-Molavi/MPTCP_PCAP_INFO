# MPTCP_PCAP_INFO

High-performance, memory-efficient PCAP analyzer designed to process large capture files and extract protocol layer features (starting with the Ethernet layer) without memory bloat or performance degradation.

---

## Requirements & Installation

Install the required streaming libraries:

```powershell
pip install -r requirements.txt
```

- **`dpkt`**: Primary high-speed engine (~500k+ packets/sec) using low-level C-struct unpacking.
- **`scapy`**: Streaming fallback reader for complex or non-standard capture structures.

---

## Commands & Usage

### 1. Run Automatically on Current Folder / Dataset
The simplest way to run `main.py`. It automatically scans the workspace (including subfolders such as `Dataset/`), discovers all PCAP/PCAPNG files, and dispatches them to `protocol_layer/ethernet.py`:

```powershell
python main.py
```

*Note: If no PCAP files are found in the current folder, `main.py` will interactively prompt you to enter the folder path.*

---

### 2. Specify a Folder Containing PCAP Files
Run on a specific relative or absolute directory:

```powershell
# Relative folder
python main.py Dataset

# Absolute path
python main.py "C:\path\to\your\pcap_folder"
```

---

### 3. Parallel Multi-Core Processing
Accelerate processing across multiple CPU cores when dealing with many large PCAP files:

```powershell
# Use 4 worker processes:
python main.py Dataset --workers 4

# Use 8 worker processes:
python main.py Dataset -w 8
```

---

### 4. Save CSV Files in a Custom Directory
By default, each CSV file is created next to its source PCAP with the same base name (e.g. `traffic.pcap` → `traffic.csv`). To save all CSVs into a separate output directory:

```powershell
python main.py Dataset --output-dir "output_csvs.csv"
```

---

### 5. Configure Interface Link Speed
Specify the link speed to accurately calculate the **Interface Utilization (%)** column (supports `K`, `M`, `G` suffixes; defaults to `1G` / 1 Gbps):

```powershell
# 10 Gbps Ethernet:
python main.py Dataset --link-speed 10G

# 100 Mbps Ethernet:
python main.py Dataset --link-speed 100M
```

---

### 6. Fast Testing with Packet Limits
Process only the first $N$ packets per file (useful for fast verification on huge files):

```powershell
python main.py Dataset --limit 1000
```

---

### 7. Non-Recursive Scan
Scan only the top level of the specified directory without traversing subfolders:

```powershell
python main.py Dataset --no-recursive
```

---

### 8. Output Summary as JSON
Output structured JSON summary data for automated scripts and pipelines:

```powershell
python main.py Dataset --json
```

---

### 9. Run Ethernet Extractor Standalone
You can also run `protocol_layer/ethernet.py` directly on a single PCAP file or folder:

```powershell
# Single PCAP file:
python protocol_layer/ethernet.py "Dataset\mptcp-dump_20150308_21403700.pcap"

# Folder of PCAPs:
python protocol_layer/ethernet.py Dataset --output-dir "csv_results"
```

---

## Command-Line Arguments Reference

```text
usage: main.py [-h] [--output-dir OUTPUT_DIR] [--workers WORKERS]
               [--link-speed LINK_SPEED] [--limit LIMIT] [--no-recursive]
               [--json]
               [folder]

positional arguments:
  folder                Folder containing PCAP files (default: current directory).

options:
  -h, --help            Show this help message and exit.
  --output-dir OUTPUT_DIR, -o OUTPUT_DIR
                        Optional directory to save CSV files (default: same directory as PCAP).
  --workers WORKERS, -w WORKERS
                        Number of parallel worker processes (default: CPU count).
  --link-speed LINK_SPEED, -s LINK_SPEED
                        Interface link speed for utilization evaluation (e.g. 100M, 1G, 10G; default: 1G).
  --limit LIMIT, -l LIMIT
                        Optional maximum number of packets to process per file.
  --no-recursive        Do not scan subdirectories recursively.
  --json                Output summary results in JSON format.
```

---

## Extracted Features (CSV Output)

Each generated `.csv` file contains the following columns:

| Column | Description | Example |
| :--- | :--- | :--- |
| **`Packet Number`** | Sequential 1-based frame index | `1, 2, 3...` |
| **`Timestamp`** | High-precision epoch timestamp | `1426795223.659552` |
| **`Source MAC`** | Sender hardware address | `00:11:22:33:44:55` |
| **`Destination MAC`** | Target hardware address | `aa:bb:cc:dd:ee:ff` |
| **`EtherType`** | Encapsulated protocol type in hexadecimal | `0x0800` (IPv4), `0x86DD` (IPv6), `0x0806` (ARP) |
| **`VLAN ID`** | 802.1Q / 802.1ad VLAN identifier | `105` (empty if untagged) |
| **`Frame Length`** | Total wire length of the frame (bytes) | `86`, `1514` |
| **`Average Frame Size`** | Running cumulative average frame size | `82.34` |
| **`Maximum Frame Size`** | Maximum frame size observed so far | `1514` |
| **`Minimum Frame Size`** | Minimum frame size observed so far | `60` |
| **`Interface Utilization`** | Cumulative bandwidth utilization percentage | `0.029119` (%) |