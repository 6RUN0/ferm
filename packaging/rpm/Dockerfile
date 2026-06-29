# Fedora build image for the native .rpm. Digest-pinned (not just a tag): the
# produced .rpm is installed and run as root on users' hosts, so the build's
# supply chain must be reproducible -- the dnf package set is frozen by the
# base image digest. Tag-only would be a regression of the project's
# supply-chain floor (the .deb image and the Nuitka image are digest-pinned
# too).
#
# frozen: fedora:43 2026-06-29
FROM fedora:43@sha256:762d73ba1c455232b0272c5d445a34f36c4b9f421cbc05ce8102552325b6a222

# The rpm toolchain is installed at IMAGE BUILD time (not when rpmbuild runs):
# rpmbuild then runs against an image that already carries the macros and the
# pyproject build backend. python3-hatchling/-hatch-vcs satisfy the rpm-level
# BuildRequires (python3dist(...)) that %pyproject_buildrequires emits; rpmlint
# gates the result. dnf versions are not pinned -- they are frozen by the base
# image digest above.
RUN dnf -y install \
        rpm-build \
        rpmlint \
        pyproject-rpm-macros \
        systemd-rpm-macros \
        python3-devel \
        python3-pip \
        python3-hatchling \
        python3-hatch-vcs \
        python3-setuptools_scm \
        git \
    && dnf clean all

# The dynamic-version backend, pinned, installed over the dnf set into
# /usr/local (which precedes /usr/lib on sys.path). Fedora's python3-hatchling
# can lag the trove-classifiers this project declares (the 3.13/3.14 entries),
# which would fail the build "Unknown classifier"; pinning the current
# generation gives the build a backend that knows the classifiers and honours
# SETUPTOOLS_SCM_PRETEND_VERSION. The dnf packages above still provide the
# rpm-level python3dist(...) BuildRequires; these shadow them only at build
# time. PEP 668 requires --break-system-packages on this managed interpreter.
#
# TODO(packaging): on Fedora 43 the dnf-native hatchling/hatch-vcs/setuptools-scm
# MAY now be current enough to know the declared classifiers, which would let
# this shadow layer be dropped in favour of the dnf set alone. Confirm with a
# real `nox -s build_rpm` against this base before removing it -- a wrong guess
# fails the wheel build "Unknown classifier", so it is left in place until then.
RUN python3 -m pip install --no-cache-dir --break-system-packages \
        "hatchling==1.30.1" \
        "hatch-vcs==0.5.0" \
        "setuptools-scm==10.0.5" \
        "vcs-versioning==1.1.1" \
        "trove-classifiers==2026.6.1.19"

WORKDIR /work
