import pandas as pd
import argparse
import os
import subprocess
import re

"""
probe-nginx-version.py

Attempts to retrieve hidden nginx versions from servers that disabled
`server_tokens` in their nginx configuration.
Uses the following methods:
1) Triggering error responses and analyzing their content
2) Nmap service version detection

Usage:
    python3 probe-nginx-version.py -i <input_file> [-o <output_file>]
    [-t <timeout>] [-vi <version_intensity>]
Example:
    python3 probe-nginx-version.py -i ../grab-banners/2026-05-26_12-24-07/grab-results.csv
"""

extract_version = r'(nginx/([0-9.]+))'


def get_ips(filename) -> list[str]:
    df = pd.read_csv(filename)
    df_empty_versions = df[df["nginx_version"] == "unknown"]
    ips = df_empty_versions["ip"].unique()
    return ips


def try_error_messages(ips, timeout) -> tuple[pd.DataFrame, list[str]]:
    found_rows = []
    not_found_ips = []

    for i, ip in enumerate(ips):
        print(f"error_messages: {i}/{len(ips)}")
        attempts = [
            ("GET",     f"http://{ip}/"),
            ("GET",     f"http://{ip}/" + "A"*500),
            ("TRACE",   f"http://{ip}/"),
            ("GET",     f"http://{ip}/thispagedoesnotexist"),
        ]

        found = False
        for method, url in attempts:
            try:
                result = subprocess.run(
                    ["curl", "-s", "-i", "-X", method, url],
                    capture_output=True, text=True, timeout=timeout
                )
                output = result.stdout

                if match := re.search(extract_version, output):
                    port = "443" if "https" in url else "80"
                    found_rows.append({
                        "ip": ip,
                        "port": port,
                        "server_header": match.group(1),
                        "nginx_version": match.group(2),
                    })
                    found = True
                    break
            except Exception:
                continue

        if not found:
            not_found_ips.append(ip)

    found_df = pd.DataFrame(found_rows, columns=[
                            "ip", "port", "server_header", "nginx_version"])

    print(f"error_messages: found nginx versions for {len(found_df)} ips")

    return found_df, not_found_ips


def try_nmap(ips, version_intensity) -> tuple[pd.DataFrame, list[str]]:
    found_rows = []
    not_found_ips = []

    for i, ip in enumerate(ips):
        print(f"nmap: {i}/{len(ips)}")
        try:
            result = subprocess.run(
                ["nmap", "-sV", "--version-intensity",
                    str(version_intensity), "-p", "80,443", ip],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout

            if match := re.search(extract_version, output):
                found_rows.append({
                    "ip": ip,
                    "nginx_version": match.group(2),
                    "server_header": match.group(1),
                    "port": None,
                })
            else:
                not_found_ips.append(ip)

        except subprocess.TimeoutExpired:
            print(f"{ip}: nmap timed out")
            not_found_ips.append(ip)
        except Exception as e:
            print(f"{ip}: failed - {e}")
            not_found_ips.append(ip)

    found_df = pd.DataFrame(found_rows, columns=[
                            "ip", "nginx_version", "server_header", "source"])

    print(f"nmap: found nginx versions for {len(found_df)} ips")

    return found_df, not_found_ips


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Probe hidden nginx version from configured servers")
    parser.add_argument("-i", required=True, help="Input file with IPs")
    parser.add_argument("-o", "--output", help="Output CSV file", default=None)
    parser.add_argument("-t", "--timeout", type=int, default=3)
    parser.add_argument("-vi", "--version-intensity",
                        help="Nmap version intensity flag", type=int, default=7)

    args = parser.parse_args()
    if args.output:
        output_file = args.output
    else:
        input_dir = os.path.dirname(os.path.abspath(args.i))
        output_file = os.path.join(input_dir, "probe_results.csv")

    ips = get_ips(args.i)

    found_df, ips = try_error_messages(ips, args.timeout)
    found_df2, ips = try_nmap(ips, args.version_intensity)

    combined_df = pd.concat([found_df, found_df2], ignore_index=True)
    combined_df.to_csv(output_file, index=False)
    print(f"Results saved to {output_file}")
