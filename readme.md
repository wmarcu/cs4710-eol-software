# Introduction

This repository contains code for the [Research in Cyber Security (CS4710)](https://studyguide.tudelft.nl/courses/study-guide/educations/14429) course at Delft University of Technology (Netherlands, EU). We investigate the prevalence of end-of-life software out in the wild and its impact on security. In particular, we focus on uncovering end-of-life Nginx versions used in the Netherlands.

# Methodology

We use the open-source network measurement tools offered by [The ZMap Project](https://zmap.io/), namely ZMap, ZGrab, and ZTee. The process we follow is outlined in [this readme](https://github.com/zmap/.github/blob/main/wiki/getting-started-with-zmap-and-zgrab2.md). This repository helps orchestrate this process so that it remains transparent and reproducible to aid our research endeavours. The Netherlands IP ranges used throughout this study were obtained from [ScaniteX](https://scanitex.com/en/resources/ip-ranges/nl/download/cidr).

# How to Run

For reproducibility, we set everything up so that it can be run from within a single Docker container. Run the following commands in order to get started:

1. Build the Docker image:
```bash
docker build -t hack-lab .
```

2. Run the container:
```bash
docker run --rm -it \
    --name hack-lab \
    --network host \
    --cap-add NET_RAW \
    --cap-add NET_ADMIN \
    -v $(pwd):/workspace \
    hack-lab
```
or on Windows in powershell:
```bash
docker run --rm -it --name hack-lab --network host --cap-add NET_RAW --cap-add NET_ADMIN -v ${PWD}:/workspace hack-lab
```

3. From inside the container, run the orchestration script:
```bash
./scripts/nginx-nl.sh
```

4. After the script finishes, check the `data/` directory for results.

# Processing results

1. Output of the scans must be moved to a folder. Run `scripts/parse-scan-results/parser.py' to sort the results.
```bash
python scripts/parse-scan-results/parser.py -i <input folder> -o <output folder>
```
Running without arguments defaults to ```data/input``` as input and ```data/processing/results``` for output.

```parser.py``` will make a folder for ```nginx```, ```mongodb``` and ```openssl```. Each will contain a ```scanned_ips.csv``` file with the detected hosts.

2. Query the NIST NVD database for relevant CVEs:
```bash
python scripts/cve-scripts/cve_api.py -i <input folder>
```
```<input folder>``` should be the folder produced by the previous script. Defaults to ```data/processing/results```. The output is stored in a folder named ```CVE``` inside the input folder.

In case the script fails during runtime, it can continue where it left off. If you want to run it from the start, make sure the produced ```<input folder>/CVE/progress.json``` is removed. 

The output needs to be parsed:
```bash
python scripts/cve-scripts/parse_api_results.py -i <input folder>
```
```<input folder>``` should be the folder produced by the previous script. Defaults to ```data/processing/results/CVE```.

3. Map the IPs to the CVEs
```bash
python scripts/cve-scripts/map_ip_to_cve.py -i <input_folder>
```
```<input folder>``` should be the folder produced by the parser.py script. Defaults to ```data/processing/results```.

This script produces two files for each type of software:

```<input folder>/<software name>/ip_cve.csv``` containing a row for each IP - CVE combination.

```<input folder>/<software name>/cve_counts.csv``` containing a count for each CVE found for this software.

4. Make graphs and tables.
```bash
python scripts/visualize-results/make_graphs.py -i <input_folder>
```
```<input folder>``` should be the folder produced by the parser.py script. Defaults to ```data/processing/results```.

Produces:

* Graphs of number of hosts per EoL date in ```<input_folder>/graphs```
* For each software:
    * Counts for all EoL dates found for this software in ```<input folder>/<software name>/counts_eol.csv```
    * Counts for all versions found for this software in ```<input folder>/<software name>/counts_versions.csv```
* A distribution of the highest severity level of all ips in ```<input folder>/host_severity_distribution.csv```

