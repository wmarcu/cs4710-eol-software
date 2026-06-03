import pandas
import copy
import csv
from datetime import datetime, date
import matplotlib.pyplot as plt
from pathlib import Path
import pandas as pd
import socket
import requests


def map_eol(first: bool, output: Path, eol_data: list, df: pandas.DataFrame,existing: set):
    df["eol_status"] = None
    with open(output, "a", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        if first:  # keep header
            writer.writerow(df.columns)
        i = 0

        for value in df["version"].to_list():
            if value != "unknown":
                for obj in eol_data:
                    if value.startswith(obj["cycle"]):
                        df.loc[i, "eol_status"] = obj["eol"]
                        if df.loc[i, "eol_status"] is not False and datetime.strptime(df.loc[i,"eol_status"], "%Y-%m-%d").date() > date.today():
                            df.loc[i, "eol_status"] = "False"
                        break
                if df.loc[i, "eol_status"] is None:
                    df.loc[i, "eol_status"] = "N/A"
            else:
                df.loc[i, "eol_status"] = "N/A"
            i += 1

        i = 0
        for value in df["ip"].to_list():
            if value not in existing:
                writer.writerow(df.iloc[i])
                existing.add(value)
            i += 1
    return existing


root1 = Path("../nginx-nl")
root2 = Path("../grab-banners")
output_nginx = Path("results/nginx/scanned_ips.csv")
output_mongodb =  Path("results/mongodb/scanned_ips.csv")
output_openssl =  Path("results/openssl/scanned_ips.csv")
open(output_nginx, "w").close()
open(output_mongodb, "w").close()
open(output_openssl, "w").close()

first_nginx = True
first_mongodb = True
first_openssl = True
eol_data_openssl = requests.get("https://endoflife.date/api/openssl.json").json()
eol_data_nginx = requests.get("https://endoflife.date/api/nginx.json").json()
eol_data_mongodb = requests.get("https://endoflife.date/api/mongodb.json").json()

obj = {"cycle": "1.5", "name": "test"}
eol_data_nginx2 = copy.deepcopy(eol_data_nginx)
for obj in eol_data_nginx:
    prefix, x = obj["cycle"].split(".")
    if int(x) <= 16:
        new_obj = copy.deepcopy(obj)
        new_obj["cycle"] = f"{prefix}.{int(x) + 1}"
        eol_data_nginx2.append(new_obj)
eol_data_nginx = eol_data_nginx2
total_scanned = 0
other_software = {}
existing_nginx = set()
existing_mongodb = set()
existing_openssl = set()
for csv_file in list(root1.rglob("*.csv")) + list(root2.rglob("*.csv")):
    df = pandas.read_csv(csv_file)
    if df.columns.str.contains("nginx_version").any():
        df.columns = df.columns.str.replace("nginx_version", "version", regex=False)
        if df.columns.str.contains("port").any():
            df = df.drop(columns=["port"])
        existing_nginx = map_eol(first_nginx, output_nginx, eol_data_nginx, df, existing_nginx)
        if first_nginx:
           first_nginx = False
    else:
        if not df.columns.str.contains("status_code").any():
            existing_mongodb = map_eol(first_mongodb, output_mongodb, eol_data_mongodb,df, existing_mongodb)
            if first_mongodb:
                first_mongodb = False
        else:
            total_scanned += len(df)
            for value in df["server_header"]:
                if pd.isna(value):
                    continue
                values = value.split("/")
                value = values[0]
                if value in other_software:
                    other_software[value] += 1
                else:
                    other_software[value] = 1

            df_openssl = df[df["server_header"].str.contains("OpenSSL", na = False)]
            df_openssl = df_openssl.reset_index(drop=True)
            if df_openssl.columns.str.contains("module").any():
                 df_openssl = df_openssl.drop(columns=["module"])
            if df_openssl.columns.str.contains("port").any():
                 df_openssl = df_openssl.drop(columns=["port"])
            i = 0
            for value in df_openssl["server_header"]:
                for value_sub in value.split(" "):
                    if "OpenSSL" in value_sub:
                        df_openssl.loc[i,"version"] = value_sub.split("/")[1]
                i += 1
            existing_openssl = map_eol(first_openssl, output_openssl, eol_data_openssl, df_openssl, existing_openssl)

            df_nginx = df[df["server_header"].str.startswith("nginx", na = False)]
            df_nginx = df_nginx.reset_index(drop=True)
            if df_nginx.columns.str.contains("module").any():
                 df_nginx = df_nginx.drop(columns=["module"])
            if df_nginx.columns.str.contains("port").any():
                 df_nginx = df_nginx.drop(columns=["port"])
            existing_nginx = map_eol(first_nginx, output_nginx, eol_data_nginx, df_nginx, existing_nginx)
            if first_nginx:
                first_nginx = False
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


df = pd.read_csv(Path("results/nginx/scanned_ips.csv"))

ip_list = df["ip"].dropna().tolist()
df_result = cymru_lookup(ip_list)

merged = df.merge(df_result, on="ip", how="left")
merged.to_csv("results/nginx/scanned_ips_org.csv", index=False)

org_counts = merged["org"].value_counts().reset_index()
org_counts.columns = ["org", "count"]
org_counts.to_csv("results/nginx/org_counts.csv", index=False)

df = pd.read_csv(Path("results/mongodb/scanned_ips.csv"))

ip_list = df["ip"].dropna().tolist()
df_result = cymru_lookup(ip_list)

merged = df.merge(df_result, on="ip", how="left")
merged.to_csv("results/mongodb/scanned_ips_org.csv", index=False)

org_counts = merged["org"].value_counts().reset_index()
org_counts.columns = ["org", "count"]
org_counts.to_csv("results/mongodb/org_counts.csv", index=False)

df = pd.read_csv(Path("results/openssl/scanned_ips.csv"))

ip_list = df["ip"].dropna().tolist()
df_result = cymru_lookup(ip_list)

merged = df.merge(df_result, on="ip", how="left")
merged.to_csv("results/openssl/scanned_ips_org.csv", index=False)

org_counts = merged["org"].value_counts().reset_index()
org_counts.columns = ["org", "count"]
org_counts.to_csv("results/openssl/org_counts.csv", index=False)




input_nginx = Path("results/nginx/scanned_ips.csv")
output_versions_nginx = Path("results/nginx/counts_versions.csv")
output_eol_nginx = Path("results/nginx/counts_eol.csv")

input_mongodb = Path("results/mongodb/scanned_ips.csv")
output_versions_mongodb = Path("results/mongodb/counts_versions.csv")
output_eol_mongodb= Path("results/mongodb/counts_eol.csv")

input_openssl = Path("results/openssl/scanned_ips.csv")
output_versions_openssl = Path("results/openssl/counts_versions.csv")
output_eol_openssl= Path("results/openssl/counts_eol.csv")

def count_versions_and_eol(input: Path, type: str, output_versions: Path, output_eol: Path):
    if type == "nginx":
        df = pandas.read_csv(input, header=None, names=["ip", "status_code", "server_header","version","eol_status"])
    elif type == "mongodb":
        df = pandas.read_csv(input, header=None, names=["ip", "module", "version", "eol_status"])
    elif type == "openssl":
        df = pandas.read_csv(input, header=None, names=["ip", "status_code", "server_header","version","eol_status"])
    else:
        return
    count_versions = dict()
    count_eol = dict()
    for value in df["version"].to_list():
        if value in count_versions:
            count_versions[value] +=1
        else:
            count_versions[value] = 1
    for value in df["eol_status"].to_list():
        if value in count_eol:
            count_eol[value] += 1
        else:
            count_eol[value] = 1
    with open(output_versions, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        items = count_versions.items()
        items = sorted(items,key = lambda x: x[1], reverse = True)
        for key, value in items:
            writer.writerow([key, value])
    with open(output_eol, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        items = count_eol.items()
        items = sorted(items,key = lambda x: x[1], reverse = True)
        for key, value in items:
            if pd.isna(key):
                writer.writerow(["unknown", value])
            elif key == "False":
                writer.writerow(["not EOL", value])
            elif key == "eol_status":
                continue
            else:
                writer.writerow([key, value])
count_versions_and_eol(input_nginx,"nginx",output_versions_nginx,output_eol_nginx)
count_versions_and_eol(input_mongodb,"mongodb",output_versions_mongodb,output_eol_mongodb)
count_versions_and_eol(input_openssl,"openssl",output_versions_openssl,output_eol_openssl)


def graph_eol(input_path: Path, output_path: Path, software: str):
    software_dates = software + "_dates.pdf"
    software_status = software + "_status.pdf"

    df = pd.read_csv(input_path, header=None, names=["EOL date", "number of hosts"])
    df_eol_dates = df[df["EOL date"] != "unknown"]
    df_eol_dates = df_eol_dates.sort_values("EOL date", ascending = False)
    plt.figure(figsize=(12, 6))
    plt.bar(df_eol_dates["EOL date"], df_eol_dates["number of hosts"], color = "red")
    plt.title("EOL dates for " + software + " hosts")
    plt.xlabel("EOL date")
    plt.ylabel("number of hosts")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_path / software_dates,format = "pdf")

    df_eol_status = df
    df_eol_status["EOL status"] = df["EOL date"].where(
        df["EOL date"].isin(["unknown", "not EOL"]),
        "EOL"
    )
    plt.close()
    plt.figure()
    df_eol_status = df_eol_status.groupby("EOL status", as_index=False)["number of hosts"].sum()
    plt.pie(
        df_eol_status["number of hosts"],
        labels=df_eol_status["EOL status"],
        autopct="%1.1f%%"
    )

    plt.title("Percentage of hosts operating on EOL " + software)
    plt.savefig(output_path / software_status, format="pdf")
    plt.close()

input_nginx = Path("results/nginx/counts_eol.csv")
input_mongodb = Path("results/mongodb/counts_eol.csv")
input_openssl = Path("results/openssl/counts_eol.csv")
output = Path("results/graphs")
graph_eol(input_nginx, output, "nginx")
graph_eol(input_mongodb, output, "mongodb")
graph_eol(input_openssl,output,"OpenSSL")


other_software_sorted = sorted(other_software.items(), key=lambda x: x[1], reverse=True)
top5 = other_software_sorted[:5]
other_sum = sum(v for _, v in other_software_sorted[5:])
labels = [k for k, _ in top5]
values = [v for _, v in top5]
if other_sum > 0:
    labels.append("Other")
    values.append(other_sum)
plt.figure()
plt.pie(
    values,
    labels=labels,
    autopct="%1.1f%%"
)
plt.axis("equal")
plt.savefig("results/graphs/other_software_distribution.pdf", format="pdf")
