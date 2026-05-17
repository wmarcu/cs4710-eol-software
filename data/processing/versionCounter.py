import pandas
import csv
from pathlib import Path



input = Path("scanned_ips.csv")
output = Path("counts.csv")
df = pandas.read_csv(input, header=None, names=["ip", "status_code", "server_header","nginx_version"])
count = dict()
for value in df["nginx_version"].to_list():
    if value in count:
        count[value] +=1
    else:
        count[value] = 1
with open(output, "w", newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    items = count.items()
    items = sorted(items,key = lambda x: x[1], reverse = True)
    for key, value in items:
       writer.writerow([key, value])

