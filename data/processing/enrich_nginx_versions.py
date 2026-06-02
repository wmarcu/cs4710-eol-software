import csv
import sys
from pathlib import Path

MAPPING = {
    "1.4.5": ("yes", "CVE-2013-2028; CVE-2014-0133"),
    "1.10.3": ("yes", "CVE-2017-7529; CVE-2021-23017"),
    "1.14.0": ("yes", "CVE-2019-20372; CVE-2021-23017"),
    "1.14.1": ("yes", "CVE-2019-20372; CVE-2021-23017"),
    "1.14.2": ("yes", "CVE-2019-20372; CVE-2021-23017"),
    "1.16.1": ("yes", "CVE-2021-23017"),
    "1.18.0": ("yes", "CVE-2021-23017; CVE-2023-44487"),
    "1.20.0": ("yes", "CVE-2021-23017; CVE-2023-44487"),
    "1.20.1": ("yes", "CVE-2021-23017; CVE-2023-44487"),
    "1.20.2": ("yes", "CVE-2023-44487"),
    "1.22.0": ("yes", "CVE-2023-44487"),
    "1.22.1": ("yes", "CVE-2023-44487"),
    "1.24.0": ("yes", "CVE-2023-44487"),
    "1.26.1": ("yes", "older advisories only"),
    "1.26.2": ("yes", "older advisories only"),
    "1.26.3": ("yes", "older advisories only"),
    "1.27.5": ("yes", "branch unsupported"),
    "1.28.0": ("no", "current stable branch"),
    "1.28.1": ("no", "current stable branch"),
    "1.29.8": ("no", "current mainline branch"),
    "1.30.0": ("no", "current mainline branch"),
}

def classify(version: str) -> tuple[str, str]:
    version = version.strip()

    if version == "" or version == "unknown":
        return "unknown", "version hidden"

    return MAPPING.get(version, ("check manually", "no local mapping"))

def has_header(path: Path) -> bool:
    with path.open(newline="") as f:
        first = next(csv.reader(f), None)
    return first is not None and "nginx_version" in first

def enrich_with_header(input_file: Path, output_file: Path) -> None:
    with input_file.open(newline="") as inp, output_file.open("w", newline="") as out:
        reader = csv.DictReader(inp)

        fieldnames = list(reader.fieldnames or [])
        for field in ["eol_status", "cve"]:
            if field not in fieldnames:
                fieldnames.append(field)

        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            version = row.get("nginx_version", "").strip()
            eol, cve = classify(version)
            row["eol_status"] = eol
            row["cve"] = cve
            writer.writerow(row)

def enrich_counts_without_header(input_file: Path, output_file: Path) -> None:
    with input_file.open(newline="") as inp, output_file.open("w", newline="") as out:
        reader = csv.reader(inp)
        writer = csv.writer(out)

        writer.writerow(["nginx_version", "count", "eol_status", "cve"])

        for row in reader:
            if len(row) < 2:
                continue

            version = row[0].strip()
            count = row[1].strip()
            eol, cve = classify(version)

            writer.writerow([version, count, eol, cve])

def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} INPUT_CSV OUTPUT_CSV", file=sys.stderr)
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"Input file does not exist: {input_file}", file=sys.stderr)
        sys.exit(1)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    if has_header(input_file):
        enrich_with_header(input_file, output_file)
    else:
        enrich_counts_without_header(input_file, output_file)

if __name__ == "__main__":
    main()
