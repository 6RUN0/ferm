# Image for the nft backend e2e: a slim Python plus nftables.  The ferm
# sources and the driver are bind-mounted at run time, so the image
# never goes stale.
FROM debian:bookworm-slim

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
