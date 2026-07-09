# Image for the nft readback-canon e2e: nftables plus a minimal Python.
# The driver is bind-mounted at run time, so the image never goes stale.
# Alpine is chosen over debian:bookworm because bookworm ships nftables
# 1.0.x, whose readback spelling predates the dscp lephb/va names this
# suite pins; alpine 3.22 ships 1.1.3, verified byte-identical to the
# 1.1.6 host capture the canon was taken from.
FROM alpine:3.22

# hadolint ignore=DL3018
RUN apk add --no-cache nftables python3
WORKDIR /work
