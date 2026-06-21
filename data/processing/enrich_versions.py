import csv

CVE_MAP = {
    "nginx": {
        "1.4.5": ["CVE-2014-0133"],
        "1.10.3": ["CVE-2017-7529", "CVE-2021-23017"],
        "1.14.0": ["CVE-2019-20372", "CVE-2021-23017"],
        "1.14.1": ["CVE-2019-20372", "CVE-2021-23017"],
        "1.14.2": ["CVE-2019-20372", "CVE-2021-23017"],
        "1.16.1": ["CVE-2021-23017"],
        "1.18.0": ["CVE-2021-23017", "CVE-2023-44487"],
        "1.20.0": ["CVE-2021-23017", "CVE-2023-44487"],
        "1.20.1": ["CVE-2023-44487"],
        "1.20.2": ["CVE-2023-44487"],
        "1.22.0": ["CVE-2023-44487"],
        "1.22.1": ["CVE-2023-44487"],
        "1.24.0": ["CVE-2023-44487"],
        "1.26.1": [],
        "1.26.2": [],
        "1.26.3": [],
        "1.27.5": [],
        "1.28.0": [],
        "1.28.1": [],
        "1.29.8": [],
        "1.30.0": [],
    },

    "mongodb": {
        "3.6": [],
        "4.0": [],
        "4.2": [],
        "4.4": ["CVE-2021-20329"],
        "5.0": ["CVE-2021-32037"],
        "6.0": [],
        "7.0": [],
    },

    "openssl": {
        "1.0.1": ["CVE-2014-0160"],
        "1.0.2": [],
        "1.1.1": ["CVE-2022-0778"],
        "3.0": ["CVE-2022-3602", "CVE-2022-3786"],
        "3.1": [],
        "3.2": [],
    },
}

def normalize_version(version: str, software: str) -> str:
    version = str(version).strip()

    if version == "" or version == "unknown":
        return version

    if software == "mongodb":
        parts = version.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else version

    if software == "openssl":
        if version.startswith("OpenSSL/"):
            version = version.split("/", 1)[1]

        if version.startswith("1.1.1"):
            return "1.1.1"

        if version.startswith("1.0.2"):
            return "1.0.2"

        if version.startswith("1.0.1"):
            return "1.0.1"

        parts = version.split(".")
        return ".".join(parts[:2]) if len(parts) >= 2 else version

    return version

def get_cves(software: str, version: str) -> list[str]:
    version = str(version).strip()

    if version == "" or version == "unknown":
        return []

    normalized = normalize_version(version, software)
    return CVE_MAP.get(software, {}).get(normalized, [])

def enrich_scanned_ips(input_path, output_path, software: str) -> None:
    with open(input_path, newline="", encoding="utf-8") as inp:
        reader = csv.DictReader(inp)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])

    for field in ["cves", "cve_count"]:
        if field not in fieldnames:
            fieldnames.append(field)

    with open(output_path, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            if row.get("ip") == "ip" or row.get("version") == "version":
                continue

            version = row.get("version", "unknown")
            cves = get_cves(software, version)

            row["cves"] = "; ".join(cves) if cves else "none"
            row["cve_count"] = len(cves)

            writer.writerow(row)
def enrich_counts_versions(input_path, output_path, software: str) -> None:
    with open(input_path, newline="", encoding="utf-8") as inp, \
         open(output_path, "w", newline="", encoding="utf-8") as out:

        reader = csv.DictReader(inp)
        writer = csv.writer(out)

        writer.writerow(["version", "count", "cves", "cve_count"])

        for row in reader:
            version = row.get("version", "unknown")
            count = row.get("count", "0")
            cves = get_cves(software, version)

            writer.writerow([
                version,
                count,
                "; ".join(cves) if cves else "none",
                len(cves),
            ])
