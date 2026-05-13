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

3. From inside the container, run the orchestration script:
```bash
./scripts/
```

4. After the script finishes, check the `data/` directory for results.