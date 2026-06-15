# Image for the datapath e2e: slim Python plus the netfilter + probing
# toolbox.  The ferm sources and the driver package are bind-mounted at
# run time, so the image never goes stale.
FROM debian:bookworm-slim

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       nftables iptables iproute2 nmap ncat conntrack procps python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
