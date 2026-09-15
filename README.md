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

### 9. Run Protocol Extractors Standalone
You can run the individual protocol layer extractors directly on a single PCAP file or folder:

```powershell
# Ethernet Layer extractor:
python protocol_layer/ethernet.py "Dataset\mptcp-dump_20150308_21403700.pcap"

# IP Layer extractor:
python protocol_layer/ip.py "Dataset\mptcp-dump_20150308_21403700.pcap"

# TCP Layer extractor:
python protocol_layer/tcp.py "Dataset\mptcp-dump_20150308_21403700.pcap"

# Connection timing extractor:
python connection_level/timing.py "Dataset\mptcp-dump_20150308_21403700.pcap"
```

The timing extractor writes a per-connection CSV named
`[pcap_name]_connection_timing.csv`. When a folder is provided, it processes all
PCAP, CAP, and PCAPNG files under that folder recursively.

---

### 10. Run Timing Through main.py
Use the `timing` layer to run connection timing through the main workflow. It
supports folder scanning, parallel workers, custom output directories, packet
limits, and JSON summaries:

```powershell
# Process every capture in Dataset:
python main.py Dataset --layer timing

# Process every capture and save the timing CSVs in outputs:
python main.py Dataset --layer timing --output-dir outputs

# Process a small sample for a quick test:
python main.py Dataset --layer timing --limit 1000 --workers 1

# Print machine-readable results:
python main.py Dataset --layer timing --json
```

The timing output contains one row per detected MPTCP connection with its
start/end times, connection duration, first and last data timestamps, and data
transfer duration. The older `connection_timing` layer name remains supported
as an alias.

---

### 11. Select Specific Protocol Layers in main.py
Control which protocol layers are extracted via the `--layer` flag:

```powershell
# Extract all layers (default: Ethernet, IP, and TCP):
python main.py Dataset --layer all

# Extract only TCP layer features:
python main.py Dataset --layer tcp

# Extract only IP layer features:
python main.py Dataset --layer ip

# Extract only Ethernet layer features:
python main.py Dataset --layer ethernet

# Extract only connection timing features:
python main.py Dataset --layer timing
```

### 12. Extract Traffic Volume Features
The `traffic_volume` layer calculates traffic totals for each detected MPTCP
connection and saves one CSV per PCAP using the suffix
`_traffic_volume.csv`:

```powershell
# Process every capture in Dataset:
python main.py Dataset --layer traffic_volume

# Save the generated CSV files in outputs:
python main.py Dataset --layer traffic_volume --output-dir outputs

# Run a quick sample:
python main.py Dataset --layer traffic_volume --limit 1000 --workers 1
```

Each row contains `Total Packets Sent`, `Total Packets Received`, `Total
Packets`, `Total Bytes Sent`, `Total Bytes Received`, `Total Bytes`, and `Total
Payload Bytes`. The sent direction is the direction of the first packet seen for
the connection; payload bytes are the MPTCP data payload bytes.

---

## Command-Line Arguments Reference

```text
usage: main.py [-h] [--layer {all,ethernet,ip,tcp}] [--output-dir OUTPUT_DIR]
               [--workers WORKERS] [--link-speed LINK_SPEED] [--limit LIMIT]
               [--no-recursive] [--json]
               [folder]

positional arguments:
  folder                Folder containing PCAP files (default: current directory).

options:
  -h, --help            Show this help message and exit.
  --layer {all,ethernet,ip,tcp}
                        Protocol layer(s) to extract: 'all' (default), 'ethernet', 'ip', or 'tcp'.
  --output-dir OUTPUT_DIR, -o OUTPUT_DIR
                        Optional directory to save CSV files (default: alongside source PCAP).
  --workers WORKERS, -w WORKERS
                        Number of parallel worker processes (default: CPU count).
  --link-speed LINK_SPEED, -s LINK_SPEED
                        Interface link speed for Ethernet utilization (e.g. 100M, 1G, 10G; default: 1G).
  --limit LIMIT, -l LIMIT
                        Optional maximum number of packets to process per file.
  --no-recursive        Do not scan subdirectories recursively.
  --json                Output summary results in JSON format.
```

---

## Extracted Features (CSV Output)

### 1. Ethernet Layer (`[pcap_name].csv`)

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

### 2. IP Layer (`[pcap_name]_ip.csv`)

| Column | Description | Example |
| :--- | :--- | :--- |
| **`Packet Number`** | Sequential 1-based IP packet index | `1, 2, 3...` |
| **`Timestamp`** | High-precision epoch timestamp | `1426795223.659552` |
| **`Source IP`** | Sender IP address (IPv4 / IPv6) | `15.243.140.205` |
| **`Destination IP`** | Target IP address (IPv4 / IPv6) | `161.240.106.142` |
| **`TTL / Hop Limit`** | Time To Live (IPv4) or Hop Limit (IPv6) | `255`, `64` |
| **`DSCP/TOS`** | Differentiated Services / Type of Service byte | `0` |
| **`Protocol Number`** | Transport protocol number | `6` (TCP), `17` (UDP) |
| **`Identification`** | Packet fragment identification | `55484` |
| **`Fragment Offset`** | Fragmentation offset in bytes | `0` |
| **`Fragment Flags`** | Fragmentation flags | `DF`, `MF`, `None` |
| **`Header Length`** | IP header length in bytes | `20` (IPv4), `40` (IPv6) |
| **`Total Length`** | Total length of IP packet in bytes | `72`, `1500` |
| **`Packet Rate`** | Running packet rate up to this packet (pkts/s) | `17886.16` |
| **`Byte Rate`** | Running byte rate up to this packet (bytes/s) | `1287803.36` |
| **`Flow Duration`** | Elapsed duration for this specific flow (seconds) | `0.000112` |
| **`Unique IP Count`** | Cumulative count of distinct IPs seen so far | `2` |
| **`Path Count`** | Cumulative count of distinct active IP paths | `2` |
| **`TTL Mean`** | Running arithmetic mean of TTL values | `255.00` |
| **`TTL Variance`** | Running sample variance of TTL values (Welford's algorithm) | `0.00` |

### 3. TCP Layer (`[pcap_name]_tcp.csv`)

| Column | Description | Example |
| :--- | :--- | :--- |
| **`Packet Number`** | Sequential 1-based TCP packet index | `1, 2, 3...` |
| **`Timestamp`** | High-precision epoch timestamp | `1426795223.659552` |
| **`Source Port`** | Source TCP port number | `41192` |
| **`Destination Port`** | Destination TCP port number | `8388` |
| **`Sequence Number`** | Raw 32-bit TCP sequence number | `1496084684` |
| **`Acknowledgment Number`** | Raw 32-bit TCP acknowledgment number | `2188164481` |
| **`Window Size`** | Advertised TCP receive window size | `42340` |
| **`Checksum`** | TCP segment checksum in hexadecimal | `0xCFE5` |
| **`TCP Length`** | TCP segment payload data length in bytes | `0`, `1448` |
| **`Flags (SYN)`** | Synchronize flag (1 or 0) | `1` / `0` |
| **`Flags (ACK)`** | Acknowledgment flag (1 or 0) | `1` / `0` |
| **`Flags (FIN)`** | Finish flag (1 or 0) | `1` / `0` |
| **`Flags (RST)`** | Reset flag (1 or 0) | `1` / `0` |
| **`Flags (PSH)`** | Push flag (1 or 0) | `1` / `0` |
| **`Flags (URG)`** | Urgent flag (1 or 0) | `1` / `0` |
| **`MSS Option`** | Maximum Segment Size option value | `1460` |
| **`SACK Option`** | SACK Permitted or SACK block count | `Permitted`, `2 Blocks` |
| **`Timestamp Option`** | TCP Timestamp values (`TSval;TSecr`) | `8104048;347922022` |
| **`Window Scale Option`** | Window scale shift value | `6` |
| **`Retransmission Count`** | Cumulative retransmissions on this connection | `0`, `1` |
| **`Fast Retransmission Count`** | Cumulative fast retransmissions triggered | `0` |
| **`Duplicate ACK Count`** | Cumulative duplicate ACKs observed | `0`, `3` |
| **`Out-of-Order Packets`** | Cumulative out-of-order packets observed | `0` |
| **`RTT`** | Measured Round Trip Time sample for this ACK (seconds) | `0.036751` |
| **`RTT Min`** | Running minimum RTT observed on this connection | `0.036751` |
| **`RTT Max`** | Running maximum RTT observed on this connection | `0.045120` |
| **`RTT Std`** | Running standard deviation of RTT samples | `0.002341` |
| **`Packet Loss Rate`** | Running packet loss ratio (`retransmissions / total_packets`) | `0.000000` |
| **`Throughput`** | Running throughput in bytes/s on this connection | `1538209.57` |
| **`Goodput`** | Running non-retransmitted payload throughput (bytes/s) | `1250000.00` |
| **`Congestion Events`** | Cumulative count of congestion events (fast retransmits + 3x dup acks) | `0` |
| **`Flow Completion Time`** | Elapsed duration for this connection (seconds) | `0.036863` |
| **`Idle Time`** | Cumulative connection idle time (gaps > 100ms) | `0.000000` |
| **`Active Time`** | Cumulative connection active transfer time | `0.036863` |
| **`Inter-arrival Time`** | Time since previous packet on this connection (seconds) | `0.000112` |
| **`Burst Size`** | Payload bytes in current burst train (gaps < 5ms) | `1448` |