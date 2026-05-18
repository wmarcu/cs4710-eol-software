import csv
import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input_csv> <output_file>")
    sys.exit(1)

input_csv = sys.argv[1]
output_file = sys.argv[2]

with open(input_csv, newline='') as f_in, open(output_file, 'w', newline='') as f_out:
    reader = csv.reader(f_in)
    next(reader)  # skip header
    for row in reader:
        f_out.write(f"{row[0]}\n")

print(f"IPs written to {output_file}")