FROM ghcr.io/zmap/zmap:4.3.4 AS zmap
FROM ghcr.io/zmap/zgrab2:latest AS zgrab

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libjson-c5 \
    libjudydebian1 \
    libgmp10 \
    ca-certificates \
    dumb-init \
    gzip \
    jq \
    python3 \
    python3-pip \
    python3-pandas \
    python3-matplotlib \
    python3-requests \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=zmap /opt/zmap /opt/zmap

COPY --from=zgrab /usr/bin/zgrab2 /usr/local/bin/zgrab2
COPY --from=zgrab /root/.config/zgrab2 /root/.config/zgrab2

ENV PATH="/opt/zmap/sbin:${PATH}"

WORKDIR /workspace

ENTRYPOINT ["/bin/bash"]