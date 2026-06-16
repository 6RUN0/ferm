# Minimal image for the dnspython non-A resolve gate. It carries only an
# authoritative resolver (dnslib) and the gate scripts; the packaged ferm
# binary is bind-mounted at run time (via FERM_BINARY), never copied in, so
# the gate always exercises the shipped artifact.
FROM python:3.13-slim

# iptables is needed because the gate runs OUTSIDE --test: find_tool resolves
# a real iptables/iptables-save in PATH even under --noexec (that is how a
# zonefile-mocked --test run is avoided -- the lookup must hit the live
# resolver, not the test path).
# A pinned apt version on debian slim is brittle and this throwaway test
# image is never shipped, so leave iptables unpinned.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

# Pin dnslib: an unpinned resolver dependency drifts under the gate.
RUN pip install --no-cache-dir dnslib==0.9.26

COPY resolver.py /resolver.py
COPY check.ferm /check.ferm
COPY run.sh /run.sh

CMD ["sh", "/run.sh"]
