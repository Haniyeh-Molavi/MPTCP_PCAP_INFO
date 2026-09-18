import os
import glob
import pandas as pd

# Main folder
main_folder = r".\outputs"

# Show first-level folders
folders = [
    f for f in os.listdir(main_folder)
    if os.path.isdir(os.path.join(main_folder, f))
]

print("\nAvailable folders:")
for i, folder in enumerate(folders, start=1):
    print(f"{i}. {folder}")

choice = int(input("\nSelect folder number: "))
selected_folder = folders[choice - 1]

selected_path = os.path.join(main_folder, selected_folder)

print(f"\nSelected: {selected_folder}")

# Process each subfolder
for subfolder in os.listdir(selected_path):
    if subfolder == "mptcp_behavior":
         # Skip the REMOVE_ADDR folder
        subfolder_path = os.path.join(selected_path, subfolder)

        if not os.path.isdir(subfolder_path):
            continue

        print(f"Processing: {subfolder}")

        csv_files = glob.glob(os.path.join(subfolder_path, "*.csv"))

        if not csv_files:
            print("  No CSV files found.")
            continue

        dfs = []
        for file in csv_files:
            df = pd.read_csv(file)

            print(file)
            print(df.dtypes)
            print("-" * 50)


        for csv_file in csv_files:
            df = pd.read_csv(csv_file)

            if "PCAP File" in df.columns:
                df["PCAP File"] = (
                    df["PCAP File"]
                    .astype(str)
                    .str.extract(r'(\d{4})\.pcap$')[0]
                    .fillna(1)
                    .astype(int)
                )

            dfs.append(df)

        merged_df = pd.concat(dfs, ignore_index=True)

        # Save using subfolder name
        output_file = os.path.join(selected_path, f"{subfolder}.csv")
        merged_df.to_csv(output_file, index=False)

        print(f"  Saved: {subfolder}.csv")

print("\nDone!")