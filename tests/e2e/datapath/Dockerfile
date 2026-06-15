# Image for the datapath e2e: a netfilter + probing toolbox on top of a
# selectable base distro.  The ferm sources and the driver package are
# bind-mounted at run time, so the image never goes stale.
#
# The base is a build ARG: a plain `docker build` (no --build-arg) yields
# the canonical Debian image, while the matrix passes `--build-arg BASE=...`
# to reuse this one Dockerfile for every distro.  install-toolbox.sh detects
# the package manager and installs the family's package names.
ARG BASE=debian:bookworm-slim
# hadolint ignore=DL3006
FROM ${BASE}

COPY install-toolbox.sh /tmp/install-toolbox.sh
RUN sh /tmp/install-toolbox.sh && rm /tmp/install-toolbox.sh
WORKDIR /work
