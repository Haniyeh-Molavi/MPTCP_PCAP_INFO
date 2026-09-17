import pandas as pd
import os
from functools import reduce

# Folder containing CSV files
csv_folder = r"C:\Users\sadra\Source\MPTCP_PCAP_INFO\outputs\Protocol Layer\REMOVE_ADDR"

# Get all CSV files
csv_files = [
    os.path.join(csv_folder, f)
    for f in os.listdir(csv_folder)
    if f.endswith(".csv")
]

dfs = []

for file in csv_files:
    df = pd.read_csv(file)

    # Optional: add source filename prefix to avoid duplicate column names
    filename = os.path.splitext(os.path.basename(file))[0]

    cols_to_rename = {
        c: f"{filename}_{c}"
        for c in df.columns
        if c not in ["PCAP File", "MPTCP Connection ID"]
    }

    df = df.rename(columns=cols_to_rename)
    dfs.append(df)

# Merge all files using composite key
merged_df = reduce(
    lambda left, right: pd.merge(
        left,
        right,
        on=["PCAP File", "MPTCP Connection ID"],
        how="outer"
    ),
    dfs
)

# Convert PCAP File to int64
merged_df["PCAP File"] = (
    pd.to_numeric(merged_df["PCAP File"], errors="coerce")
    .astype("Int64")
)

# Convert MPTCP Connection ID to object (string)
merged_df["MPTCP Connection ID"] = (
    merged_df["MPTCP Connection ID"]
    .astype(str)
)

# Save
merged_df.to_csv("Merged_MPTCP.csv", index=False)

print(f"Total rows: {len(merged_df)}")
print("Saved: Merged_MPTCP.csv")