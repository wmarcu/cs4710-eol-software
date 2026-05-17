import pandas
import csv
from pathlib import Path

root = Path("../nginx-nl")
output = Path("scanned_ips.csv")

existing_ips = set()
open(output, "w").close()
for csv_file in root.rglob("*.csv"):
    df = pandas.read_csv(csv_file)
    with open(output, "a", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        i = 0
        for value in df["ip"].to_list():
            if value not in existing_ips:
                writer.writerow(df.iloc[i])
                existing_ips.add(value)
            i += 1
