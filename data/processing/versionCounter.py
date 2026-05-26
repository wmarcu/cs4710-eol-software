import pandas
import csv
from pathlib import Path



input = Path("scanned_ips.csv")
output_versions = Path("counts_versions.csv")
output_eol = Path("counts_eol.csv")
df = pandas.read_csv(input, header=None, names=["ip", "status_code", "server_header","nginx_version","eol_status"])
count_versions = dict()
count_eol = dict()
for value in df["nginx_version"].to_list():
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
       writer.writerow([key, value])



