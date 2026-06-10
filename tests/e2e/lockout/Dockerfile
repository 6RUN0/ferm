# Image for the --interactive lockout e2e: a floor-version Python
# interpreter plus nft-backed iptables.  The ferm sources and the
# driver are bind-mounted at run time, so the image never goes stale.
FROM debian:bookworm-slim

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables python3 \
    && rm -rf /var/lib/apt/lists/*
