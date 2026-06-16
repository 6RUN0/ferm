# Debian build image for the native .deb. Digest-pinned (not just a tag): the
# produced .deb is installed and run as root on users' hosts, so the build's
# supply chain must be reproducible -- the apt package set is frozen by the
# base image digest. Tag-only would be a regression of the project's
# supply-chain floor (the Nuitka image, packaging/Dockerfile, is digest-pinned
# too).
#
# frozen: debian:bookworm-slim 2026-06-16
FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

# The deb toolchain is installed at IMAGE BUILD time (not when dpkg-buildpackage
# runs): dpkg-buildpackage then runs offline against an image that already
# carries every Build-Depends. devscripts provides dch; lintian gates the
# result. apt versions are not pinned -- they are frozen by the base image
# digest above (DL3008).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        dpkg-dev \
        debhelper \
        dh-python \
        pybuild-plugin-pyproject \
        python3-all \
        python3-hatchling \
        python3-hatch-vcs \
        python3-setuptools-scm \
        python3-pip \
        devscripts \
        lintian \
    && rm -rf /var/lib/apt/lists/*

# The dynamic-version backend, pinned, installed over the apt set. bookworm's
# python3-hatchling is 1.12.2 -- too old: its vendored trove-classifier list
# predates the Python 3.13/3.14 classifiers this project declares (the build
# would fail "Unknown classifier"), and it does not use the trove-classifiers
# package. Pinning the current generation (hatchling + hatch-vcs over the
# vcs-versioning engine + a current trove-classifiers) into /usr/local --
# which precedes /usr/lib on sys.path -- gives pybuild a backend that knows
# the classifiers and honours SETUPTOOLS_SCM_PRETEND_VERSION. --break-system-
# packages is required by PEP 668 on this externally-managed interpreter.
RUN python3 -m pip install --no-cache-dir --break-system-packages \
        "hatchling==1.30.1" \
        "hatch-vcs==0.5.0" \
        "setuptools-scm==10.0.5" \
        "vcs-versioning==1.1.1" \
        "trove-classifiers==2026.6.1.19"

WORKDIR /work
