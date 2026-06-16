# Build image for the Phase 3 standalone binary.
# manylinux_2_28 fixes the glibc floor at 2.28 and ships
# /opt/python/cp313-cp313 + a Nuitka-compatible devtoolset GCC + patchelf.
# Sources are bind-mounted at run time (dev mode) or git-archived in
# (release mode), so the image never goes stale.
#
# Digest pinned from:
#   docker buildx imagetools inspect quay.io/pypa/manylinux_2_28_x86_64:latest
# (source of truth for the GCC/devtoolset/patchelf toolchain).
FROM quay.io/pypa/manylinux_2_28_x86_64@sha256:893d0c9d73a8262503fa32f40160aae0299c10cecfc04396c9802a712cab1831

# Exact pins: Nuitka codegen changes between minors; dnspython is frozen
# with its transitive deps via constraints, not a floating >=. hatchling is
# the PEP 517 backend for ``pip install .``; pinning it here lets the
# in-container build run under --network=none (build isolation would
# otherwise fetch it from PyPI).
ARG NUITKA_VERSION=4.1.2
ARG DNSPYTHON_VERSION=2.8.0
ARG HATCHLING_VERSION=1.30.1

ENV PATH=/opt/python/cp313-cp313/bin:${PATH}
# Build cache home so the in-container build can run with --network=none.
# Spike B finding: with this pinned Nuitka on this image the first run
# downloads NOTHING -- the cache (module-cache/adapted_headers/
# ccache) is purely build-derived and regenerated each run, so an empty
# seed is sufficient for the offline build. The COPY below stays so a future
# ccache pre-seed (build-speed only, not correctness) is a one-line change.
ENV NUITKA_CACHE_DIR=/opt/nuitka-cache

# manylinux ships no shared libpython; Nuitka --standalone needs the static
# archive, which manylinux stages compressed. Extracting it in place is the
# image maintainer's documented step (the Nuitka FATAL message names this
# exact command), so static-libpython detection succeeds at compile time.
# A transient cd for one extract, not a directory worth a WORKDIR.
# hadolint ignore=DL3003
RUN cd /opt/_internal && tar xf static-libs-for-embedding-only.tar.xz

RUN python -m pip install --no-cache-dir \
        "nuitka==${NUITKA_VERSION}" \
        "dnspython==${DNSPYTHON_VERSION}" \
        "hatchling==${HATCHLING_VERSION}"

# A SEPARATE venv that has pytest but NOT pyferm: the verify-golden gate
# must run the golden harness from an interpreter where ``pyferm`` is
# absent, proving the binary pulls nothing from the host. The build python
# (/opt/python/cp313-cp313) gets ``pip install .`` and DOES carry pyferm, so
# it cannot serve double duty. Pinned for reproducibility; pre-installed so
# the gate runs under --network=none. The extra deps keep the venv pyferm-free
# (the self-containment property the gate asserts) while satisfying what the
# golden run needs from the repo's pytest config: hypothesis because the shared
# ``tests/conftest.py`` imports it at module load to register property-test
# profiles, and pytest-timeout because ``[tool.pytest.ini_options]`` declares
# ``timeout``/``timeout_method`` -- an unregistered config option there would
# raise PytestConfigWarning, which the repo's filterwarnings=error escalates
# into a collection-time failure.
ARG PYTEST_VERSION=9.1.0
ARG HYPOTHESIS_VERSION=6.155.2
ARG PYTEST_TIMEOUT_VERSION=2.4.0
RUN python -m venv /opt/golden-venv \
    && /opt/golden-venv/bin/pip install --no-cache-dir \
        "pytest==${PYTEST_VERSION}" "hypothesis==${HYPOTHESIS_VERSION}" \
        "pytest-timeout==${PYTEST_TIMEOUT_VERSION}"

# Cache directory for Nuitka's build artifacts (see NUITKA_CACHE_DIR above).
# Currently an empty placeholder (.gitkeep): Spike B verified this pinned
# Nuitka downloads nothing at build time, so --network=none passes without a
# pre-seed. Kept as a COPY so a ccache pre-seed (build-speed only) can drop in.
COPY nuitka-cache/ /opt/nuitka-cache/

WORKDIR /work
