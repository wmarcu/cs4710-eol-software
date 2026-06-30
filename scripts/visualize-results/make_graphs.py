import matplotlib.pyplot as plt
import pandas as pd
import argparse
import os

SOFTWARE = ["nginx", "mongodb", "openssl"]

DEFAULT_RESULTS_FOLDER = "data/processing/results"

def count_versions_and_eol(scanned_ips_filepath:str, output_versions: str, output_eol: str):
    """Takes as input a .csv with (at least) columns ip, version, eol_status"""
    df = pd.read_csv(scanned_ips_filepath)
    

    if "version" not in df.columns or "eol_status" not in df.columns:
        return
    
    version_counts = df["version"].value_counts()
    eol_counts = df["eol_status"].fillna("unknown").replace("False", "not EoL").value_counts(dropna=False)

    version_counts.to_csv(output_versions)
    eol_counts.to_csv(output_eol)

def graph_eol(counts_eol_filepath, graphs_folderpath: str, software: str):
    software_dates = software + "_dates.pdf"

    df = pd.read_csv(counts_eol_filepath)
    df_eol_dates = df[df["eol_status"] != "unknown"]
    df_eol_dates = df_eol_dates.sort_values("eol_status", ascending = False)

    plt.figure(figsize=(12, 6))
    plt.bar(df_eol_dates["eol_status"], df_eol_dates["count"], color = "red")
    plt.xlabel("EoL date",fontsize=20)
    plt.ylabel("number of hosts",fontsize=20)
    plt.xticks(rotation=45,ha='right',fontsize=20)
    plt.yticks(fontsize=20)
    plt.tight_layout()
    plt.savefig(graphs_folderpath + software_dates, format = "pdf")
    plt.close()

def table_host_severity_distribution(ip_cve_filepath):
    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    ip_cve_df = pd.read_csv(ip_cve_filepath).dropna(subset=["ip", "base_score", "base_severity"])
    ip_cve_df = ip_cve_df[ip_cve_df["eol_status"] != "False"]


    ip_cve_df["base_score"] = pd.to_numeric(ip_cve_df["base_score"], errors="coerce")
    ip_cve_df = ip_cve_df.dropna(subset=["base_score"])

    if ip_cve_df.empty:
        return

    idx = ip_cve_df.groupby("ip")["base_score"].idxmax()
    host_max = ip_cve_df.loc[idx].copy()

    host_max["base_severity"] = (
        host_max["base_severity"]
        .astype(str)
        .str.upper()
    )

    counts = (
        host_max["base_severity"]
        .value_counts()
        .reindex(severity_order, fill_value=0)
    )

    total = counts.sum()

    row = {
        "software": software,
        "total_hosts_with_cve": total,
        }

    for severity in severity_order:
        count = int(counts[severity])
        percentage = (count / total * 100) if total > 0 else 0

        row[f"{severity.lower()}_hosts"] = count
        row[f"{severity.lower()}_percentage"] = round(percentage, 1)

    return row

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Count and make graphs")
    parser.add_argument("-i", "--input_dir", help="Results folder. Must contain [software]/scanned_ips.csv and [software]/ip_cve.csv files.")

    args = parser.parse_args()

    RESULTS_FOLDER = args.input_dir if args.input_dir else DEFAULT_RESULTS_FOLDER

    severity_rows = []
    severity_filepath = f"{RESULTS_FOLDER}/host_severity_distribution.csv"

    graphs_folderpath = f"{RESULTS_FOLDER}/graphs/"
    os.makedirs(graphs_folderpath, exist_ok=True)

    for software in SOFTWARE:
        # inputs
        scanned_ips_filepath = f"{RESULTS_FOLDER}/{software}/scanned_ips.csv"
        ip_cve_filepath = f"{RESULTS_FOLDER}/{software}/ip_cve.csv"

        # outputs
        version_counts_filepath = f"{RESULTS_FOLDER}/{software}/counts_versions.csv"
        eol_counts_filepath = f"{RESULTS_FOLDER}/{software}/counts_eol.csv"
        
        try:
            count_versions_and_eol(scanned_ips_filepath, version_counts_filepath, eol_counts_filepath)
        except pd.errors.EmptyDataError:
            continue

        graph_eol(eol_counts_filepath, graphs_folderpath, software)

        severity_row = table_host_severity_distribution(ip_cve_filepath)
        if severity_row:
            severity_rows.append(severity_row)

    result = pd.DataFrame(severity_rows)
    result.to_csv(severity_filepath, index=False)






