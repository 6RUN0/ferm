# Alpine build image for the native .apk. Digest-pinned (not just a tag): the
# produced .apk is installed and run as root on users' hosts, so the build's
# supply chain must be reproducible -- the apk package set is frozen by the base
# image digest. Tag-only would be a regression of the project's supply-chain
# floor (the .deb and .rpm images and the Nuitka image are digest-pinned too).
#
# frozen: alpine:3.24 2026-06-29
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# The apk toolchain is installed at IMAGE BUILD time (not when abuild runs):
# abuild then runs against an image that already carries alpine-sdk and the
# pyproject build backend. Unlike the Fedora image, no pip pinning is needed --
# Alpine's py3-trove-classifiers is recent enough to know the Python 3.13/3.14
# classifiers this project declares, so the apk-provided hatchling/hatch-vcs
# build the wheel directly. py3-installer materializes the wheel into the
# package root. apk versions are not pinned -- they are frozen by the base image
# digest above. community holds the py3-* build backends.
RUN sed -i 's|^#\(.*/community\)|\1|' /etc/apk/repositories \
    && apk add --no-cache \
        alpine-sdk \
        abuild \
        python3 \
        py3-gpep517 \
        py3-installer \
        py3-hatchling \
        py3-hatch-vcs \
        py3-setuptools_scm

WORKDIR /work
