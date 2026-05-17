import pandas
import csv
from pathlib import Path
import pandas as pd
import socket

root = Path("../nginx-nl")
output = Path("scanned_ips.csv")

first = True

existing_ips = set()
open(output, "w").close()
for csv_file in root.rglob("*.csv"):
    df = pandas.read_csv(csv_file)
    with open(output, "a", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        if first: # keep header
            writer.writerow(df.columns)
            first = False

        i = 0
        for value in df["ip"].to_list():
            if value not in existing_ips:
                writer.writerow(df.iloc[i])
                existing_ips.add(value)
            i += 1

def cymru_lookup(ip_list: list) -> pd.DataFrame:
    """
    https://www.team-cymru.com/ip-asn-mapping

    returns dataframe with columns: "ip", "asn", "org"
    """

    def parse_result(raw_result: str) -> pd.DataFrame:
        asn_rows = []

        for line in raw_result.splitlines():
            if "|" not in line:
                continue

            parts = [p.strip() for p in line.split("|")]

            if len(parts) >= 7 and parts[0] != "AS":
                asn_rows.append({
                    "ip": parts[1],
                    "asn": parts[0],
                    "org": parts[6]
                })

        return pd.DataFrame(asn_rows)

    query = "begin\nverbose\n" + "\n".join(ip_list) + "\nend\n"

    with socket.socket() as s:
        s.connect(("whois.cymru.com", 43))
        s.sendall(query.encode())

        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk

    return parse_result(response.decode())

df = pd.read_csv(Path("scanned_ips.csv"))

ip_list = df["ip"].dropna().tolist()
df_result = cymru_lookup(ip_list)

merged = df.merge(df_result, on="ip", how="left")
merged.to_csv("scanned_ips_org.csv", index=False)

org_counts = merged["org"].value_counts().reset_index()
org_counts.columns = ["org", "count"]
org_counts.to_csv("org_counts.csv", index=False)
