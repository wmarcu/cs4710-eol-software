import pandas as pd
import argparse

SOFTWARE = ["nginx", "mongodb", "openssl"]

DEFAULT_RESULTS_FOLDER = "data/processing/results"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Map version to cves")
    parser.add_argument("-i", "--input_dir", help="Results folder. Must contain [software]/version_cve.csv file.")

    args = parser.parse_args()

    RESULTS_FOLDER = args.input_dir if args.input_dir else DEFAULT_RESULTS_FOLDER

    for software_name in SOFTWARE:
        print(software_name)
        try:
            ip_version_df = pd.read_csv(f"{RESULTS_FOLDER}/{software_name}/scanned_ips.csv", usecols=["ip","version","eol_status"])
            version_cve_df = pd.read_csv(f"{RESULTS_FOLDER}/{software_name}/version_cve.csv")
        except pd.errors.EmptyDataError:
            # File is empty because no ips or CVEs were found for that software.
            continue
        
        ip_cve_df = ip_version_df.merge(version_cve_df, on="version", how="left")

        ip_cve_df.to_csv(f"{RESULTS_FOLDER}/{software_name}/ip_cve.csv", index=False)