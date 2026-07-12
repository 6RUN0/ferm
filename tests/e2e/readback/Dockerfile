# Image for the nft readback-canon e2e: nftables plus a minimal Python.
# The driver is bind-mounted at run time, so the image never goes stale.
#
# The base must satisfy two constraints, both learned the hard way:
#  * the C library must resolve protocol names via /etc/protocols: nft maps
#    `meta l4proto mobility-header` (an ip6 line this suite pins) through
#    getprotobyname(), and musl (every alpine) returns "not found" for it
#    regardless of /etc/protocols, so an alpine base cannot even load the
#    fixture -- a glibc base is required.
#  * the readback spelling must match the host capture the canon was taken
#    from (nftables 1.1.6). debian:trixie ships 1.1.3 on glibc, verified by
#    this suite to read back byte-identically for the pinned vocabulary.
# If a future nftables bump changes a spelling, the pin fails loudly and the
# canon is re-captured.
FROM debian:trixie-slim

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
