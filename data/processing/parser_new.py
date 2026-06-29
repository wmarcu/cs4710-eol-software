from pathlib import Path
import argparse
import requests
import pandas as pd
import re
from datetime import datetime, date

SOFTWARE = "mongodb", "nginx", "openssl"

def get_eol_data(software):
    eol_json = requests.get(f"https://endoflife.date/api/{software}.json").json()
    
    # Does not contain eol dates for uneven nginx versions under 1.18, but they are identical to the even version before it.
    if software == "nginx":
        additional_versions = []
        for obj in eol_json:
            prefix, x = obj["cycle"].split(".")
            if int(x) <= 16:
                additional_versions.append({"cycle": f"{prefix}.{int(x) + 1}", "eol": obj["eol"]})
        eol_json += additional_versions

    def check_eol(date_str):
        if not date_str:
            return "False"
        if datetime.strptime(date_str, "%Y-%m-%d").date() > date.today():
            return "False"
        return date_str

    return {obj["cycle"]:check_eol(obj["eol"]) for obj in eol_json}

def read_csv(filepath):
    file_df = pd.read_csv(filepath)


    if file_df.columns.str.contains("nginx_version").any():
        df = file_df.loc[:, ["ip","server_header","nginx_version"]]
        df.rename(columns={"server_header":"software","nginx_version":"version"}, inplace=True)
    elif file_df.columns.str.contains("server_header").any():
        df = file_df.loc[:, ["ip","server_header","version"]]
        df.rename(columns={"server_header":"software"}, inplace=True)
    else:
        df = file_df.loc[:, ["ip","module","version"]]
        df.rename(columns={"module":"software"}, inplace=True)

    nginx_mask = df["software"].str.contains("nginx", case=False, na=False)
    mongodb_mask = df["software"].str.contains("mongodb", case=False, na=False)
    openssl_mask = df["software"].str.contains("openSSL", case=False, na=False)

    df_nginx = df[nginx_mask]
    df_mongodb = df[mongodb_mask]
    df_openssl = df[openssl_mask]
    df_openssl["version"] = (df_openssl["software"].str.extract(r"OpenSSL/([\d.]+\w*)", expand=False)
                             .fillna(df_openssl["software"].str.extract(r"openSSL/openSSL([\d.]+\w*)", expand=False))) # OpenSSL version is not read correctly by the grab-banner script, this fixes it.
    
    df_other = df[~(nginx_mask | mongodb_mask | openssl_mask)]

    return df_nginx, df_mongodb, df_openssl, df_other

def lookup_eol(version, eol_data: dict, software):
    if software == "openssl":
        version = re.search(r'(\d+\.\d+\.\d+)', version).group(1)
    if version in eol_data:
        return eol_data[version]
    
    return eol_data.get(".".join(version.split(".")[:2]), "N/A")

def map_eol(input_df : pd.DataFrame, eol_data: dict, software):
    input_df["eol_status"] = input_df["version"].apply(lambda version: lookup_eol(version, eol_data, software))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse scan results")
    parser.add_argument("-i", "--input_dir", help="Folder with scan output. Program will parse ALL .csv files recursively.", default="data/input")
    parser.add_argument("-o", "--output_dir", help="Output folder.", default = "data/processing/results2")

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = args.output_dir

    eol_data_mongodb, eol_data_nginx, eol_data_openssl = [get_eol_data(software) for software in SOFTWARE]

    nginx_dfs : list[pd.DataFrame] = []
    mongodb_dfs : list[pd.DataFrame] = []
    openssl_dfs : list[pd.DataFrame] = []
    other_dfs : list[pd.DataFrame] = []

    for csv_file in list(input_dir.rglob("*.csv")):
        df_nginx, df_mongodb, df_openssl, df_other = read_csv(csv_file)

        nginx_dfs.append(df_nginx)
        mongodb_dfs.append(df_mongodb)
        openssl_dfs.append(df_openssl)
        other_dfs.append(df_other)

    all_nginx = pd.concat(nginx_dfs)
    all_nginx.drop_duplicates("ip", inplace=True)
    map_eol(all_nginx, eol_data_nginx, "nginx")
    nginx_path = Path(f"{output_dir}/nginx/scanned_ips.csv")
    nginx_path.parent.mkdir(parents=True, exist_ok=True)
    all_nginx.to_csv(nginx_path, index=False)

    all_mongodb = pd.concat(mongodb_dfs)
    all_mongodb.drop_duplicates("ip", inplace=True)
    map_eol(all_mongodb, eol_data_mongodb, "mongodb")
    mongodb_path = Path(f"{output_dir}/mongodb/scanned_ips.csv")
    mongodb_path.parent.mkdir(parents=True, exist_ok=True)
    all_mongodb.to_csv(mongodb_path, index=False)

    all_openssl = pd.concat(openssl_dfs)
    all_openssl.drop_duplicates("ip", inplace=True)
    map_eol(all_openssl, eol_data_openssl, "openssl")
    openssl_path = Path(f"{output_dir}/openssl/scanned_ips.csv")
    openssl_path.parent.mkdir(parents=True, exist_ok=True)
    all_openssl.to_csv(openssl_path, index=False)

    all_other = pd.concat(other_dfs)
    all_other.drop_duplicates("ip", inplace=True)



