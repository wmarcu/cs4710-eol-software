import requests
import json
from packaging.version import Version
import pandas as pd
import time
import os
import re
import argparse

API_KEY = ""

DEFAULT_VERSION_COUNTS_RESULTS_DIRECTORY = "data/processing/results"

NGINX = {
    "name": "nginx",
    "cpe" : "a:f5:nginx"
}

MONGODB = {
    "name" : "mongodb",
    "cpe" : "a:mongodb:mongodb"
}

OPENSSL = {
    "name" : "openssl",
    "cpe" : "a:openssl:openssl"
}

SOFTWARE = [NGINX, MONGODB, OPENSSL]
SOFTWARE_IDX = {
    "nginx": 0,
    "mongodb": 1,
    "openssl": 2
}

def parse_openssl_version(v):
    """OpenSSL versions may have letters which pythons Version does not understand, so this parses to a sortable tuple."""
    v = v.split('-')[0]
    m = re.match(r'(\d+)\.(\d+)\.(\d+)([a-z]*)', v)
    if not m:
        return None
    major, minor, patch, letter = m.groups()
    return (int(major), int(minor), int(patch), letter)

def get_min_max_version(directory : str):
    df = pd.read_csv(f"{directory}/counts_versions.csv")
    if len(df) == 0:
        raise ValueError("empty df")
    versions = df["version"][df["version"].str.contains(r"\d")]
    if directory.endswith("openssl"):
        parsed_versions = versions.apply(parse_openssl_version).notna()
    else:
        parsed_versions = versions.apply(Version)
    first_version = versions.loc[parsed_versions.idxmin()]
    last_version = versions.loc[parsed_versions.idxmax()]
    return first_version, last_version

def url(cpe, versionstart, versionend, start_index):
    return f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:{cpe}&versionStart={versionstart}&versionStartType=including&versionEnd={versionend}&versionEndType=including&startIndex={start_index}"

def load_state(state_file):
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            return json.load(f)
    return {"software_idx": 0,  "results_read": 0, "total_results": -1}

def save_state(software, results_read, total_results, state_file):
    tmp_file = state_file + ".tmp"
    state = {"software_idx": SOFTWARE_IDX[software["name"]],  "results_read": results_read, "total_results": total_results}
    with open(tmp_file, "w") as f:
        json.dump(state, f)
    os.replace(tmp_file, state_file)

def save_page(software, cves, cve_dir):
    with open(f"{cve_dir}/{software["name"]}.jsonl", "a") as f:
        for cve in cves:
            f.write(json.dumps(cve) + "\n")

        f.flush()

def get_page(software, start_index):
    while True:
        r = requests.get(url(software["cpe"], software["version_start"], software["version_end"], start_index), headers={"apiKey" : API_KEY})
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            raise Exception("URL BROKE")
        else:
            print("Something went wrong. Status code:", r.status_code)
            time.sleep(10)
            print("retrying...")

def request_cves(software, results_read, total_results, cve_dir, state_file):
    while results_read != total_results:
        json_res = get_page(software, results_read)
        if total_results == -1:
            total_results = json_res["totalResults"]

        save_page(software, json_res["vulnerabilities"], cve_dir)
        results_read = json_res["resultsPerPage"]
        save_state(software, results_read, total_results, state_file)
        print(f"Retrieved {results_read} of {total_results} results.")


if __name__ == "__main__":
    if API_KEY == "":
        print("ADD API KEY")
        exit()

    parser = argparse.ArgumentParser(description="Retrieve CVEs from NIST database based on version numbers.")
    parser.add_argument("-i", "--input_dir", help="Folder containing subfolders with 'counts_versions.csv' files.")

    args = parser.parse_args()
    
    VERSION_COUNTS_RESULTS_DIRECTORY = args.input_dir if args.input_dir else DEFAULT_VERSION_COUNTS_RESULTS_DIRECTORY
    CVE_DIR = VERSION_COUNTS_RESULTS_DIRECTORY + "/CVE"
    os.makedirs(CVE_DIR, exist_ok=True)
    STATE_FILE = CVE_DIR + "/progress.json"

    state = load_state(STATE_FILE)

    for i in range(state["software_idx"], 3):
        print("Starting", SOFTWARE[i]["name"])
        try:
            SOFTWARE[i]["version_start"], SOFTWARE[i]["version_end"] = get_min_max_version(VERSION_COUNTS_RESULTS_DIRECTORY + "/" + SOFTWARE[i]["name"])
        except ValueError as e:
            if "empty df" in str(e):
                print(f"No versions found for {SOFTWARE[i]["name"]}")
                continue
            else:
                raise e
        request_cves(SOFTWARE[i], state["results_read"], state["total_results"], CVE_DIR, STATE_FILE)
        state["results_read"], state["total_results"] = 0, -1

# r = requests.get(url(NGINX["cpe"]), headers={"apiKey" : API_KEY})

# print(r.status_code)
# if r.status_code != 200:
#     exit()
# #print(r.request.body)


# j = r.json()
# with open(f"{j}.json", "w") as f:
#     json.dump(j, f)

# l = []
# for v in j['vulnerabilities']:
#     cve = v['cve']
#     affected_versions = cve['affected'][0]['affectedData'][0]['versions']


#     metrics = cve['metrics']
#     try:
#         l.append(metrics['cvssMetricV31'][0]['cvssData']['baseSeverity'])
#     except:
#         continue

# l.sort()



# print(j.keys())

