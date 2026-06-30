## Introduction

This repository contains code for the [Research in Cyber Security (CS4710)](https://studyguide.tudelft.nl/courses/study-guide/educations/14429) course at Delft University of Technology (Netherlands, EU). We investigate the prevalence of end-of-life software out in the wild and its impact on security. In particular, we focus on uncovering end-of-life Nginx, MongoDB, and OpenSSL versions used in the Netherlands.

## Methodology

We use the open-source network measurement tools offered by [The ZMap Project](https://zmap.io/), namely ZMap, ZGrab, and ZTee. The process we follow is outlined in [this readme](https://github.com/zmap/.github/blob/main/wiki/getting-started-with-zmap-and-zgrab2.md). This repository helps orchestrate this process so that it remains transparent and reproducible to aid our research endeavours. The Netherlands IP ranges used throughout this study were obtained from [ScaniteX](https://scanitex.com/en/resources/ip-ranges/nl/download/cidr). An overview of our entire pipeline can be found below:

![Multi-stage Internet measurement pipeline](figures/pipeline.png)

## Setup container

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

## Host discovery and Software identification (Stage 1 and 2)

1. From inside the container, run stage 1 (host discovery):
```bash
./scripts/scan-ports/scan-ports.sh
```
By default, this will scan port 80 on the IP ranges listed in `nl-cidr.conf`, using a bandwidth of 1 Mbps. These values can be freely configured by passing the relevant arguments to the script. After the script finishes, check the `data/scan-ports/` directory for results.
After the script finishes, check the `data/` directory for results.

Alternatively, to find hosts related to Dutch government domains:
```bash
./scripts/resolve-dns/resolve-dns.sh <PATH TO LIST OF DOMAINS>
```

2. Run stage 2 (software identification):
```bash
./scripts/grab-banners/grab-banners.sh -i <PATH TO OUTPUT FILE FROM STAGE 1>
```
By default, this will send probes using 100 concurrent senders, configured with a 10 second timeout, to the hosts in the supplied input file. These values can be freely configured by passing the relevant arguments to the script. The script automatically processes the responses to the probes, and extracts software version information (if present), to an output csv located in `data/grab-banners/`.


## Processing results (Stage 3 and 4)

1. Output of the scans must be moved to a folder. Run `scripts/parse-scan-results/parser.py` to sort the results.
```bash
python3 scripts/parse-scan-results/parser.py -i <input folder> -o <output folder>
```
Running without arguments defaults to `data/input` as input and `data/processing/results` for output.
This will iterate through all scans in the input directory, remove duplicates, and identify whether the observed software versions are EoL using endoflife.date.
`parser.py` will make a folder for `nginx`, `mongodb` and `openssl`. Each will contain a `scanned_ips.csv` file with the detected hosts.

2. Query the NIST NVD database for relevant CVEs:
```bash
python3 scripts/cve-scripts/cve_api.py -i <input folder>
```
`<input folder>` should be the folder produced by the previous script. Defaults to `data/processing/results`. The output is stored in a folder named `CVE` inside the input folder.

Make sure to place a valid api key in `apikey.env`

In case the script fails during runtime, it can continue where it left off. If you want to run it from the start, make sure the produced `<input folder>/CVE/progress.json` is removed. 

The output needs to be parsed:
```bash
python3 scripts/cve-scripts/parse_api_results.py -i <input folder>
```
`<input folder>` should be the folder produced by the previous script. Defaults to `data/processing/results/CVE`.

3. Map the IPs to the CVEs
```bash
python3 scripts/cve-scripts/map_ip_to_cve.py -i <input_folder>
```
`<input folder>` should be the folder produced by the parser.py script. Defaults to `data/processing/results`.

This script produces two files for each type of software:

`<input folder>/<software name>/ip_cve.csv` containing a row for each IP - CVE combination.

`<input folder>/<software name>/cve_counts.csv` containing a count for each CVE found for this software.

4. Make graphs and tables.
```bash
python3 scripts/visualize-results/make_graphs.py -i <input_folder>
```
`<input folder>` should be the folder produced by the parser.py script. Defaults to `data/processing/results`.

Produces:

* Graphs of number of hosts per EoL date in `<input_folder>/graphs`
* For each software:
    * Counts for all EoL dates found for this software in `<input folder>/<software name>/counts_eol.csv`
    * Counts for all versions found for this software in `<input folder>/<software name>/counts_versions.csv`
* A distribution of the highest severity level of all ips in `<input folder>/host_severity_distribution.csv`
