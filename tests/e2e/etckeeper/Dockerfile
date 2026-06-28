# Image for the etckeeper integration e2e: a slim Debian with the real
# etckeeper + git VCS layer, nftables for a real apply, and python3.  The
# ferm sources and the driver are bind-mounted at run time, so the image
# never goes stale.
FROM debian:bookworm-slim

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        etckeeper git nftables python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
