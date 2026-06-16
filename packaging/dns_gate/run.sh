#!/bin/sh
# Container CMD for the dnspython non-A resolve gate.
#
# Point the binary's dnspython at the local authoritative resolver, start that
# resolver, wait until it announces readiness, then run the packaged binary on
# a config that resolves a non-A (MX) record. A clean resolve prints
# DNS-GATE-OK and exits 0; any failure -- including a stub-resolver warning,
# which means the stdlib stub answered instead of the frozen dnspython -- is a
# non-zero exit.
set -eu

# dnspython reads /etc/resolv.conf; aim it at the local authoritative resolver.
printf 'nameserver 127.0.0.1\n' >/etc/resolv.conf

resolver_log=$(mktemp)
python /resolver.py >"$resolver_log" 2>&1 &
resolver_pid=$!

cleanup() {
    kill "$resolver_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Poll for the readiness line rather than sleeping a fixed interval, so the
# gate is robust to resolver start-up jitter.
ready=""
i=0
while [ "$i" -lt 100 ]; do
    if grep -q "DNS-GATE-READY" "$resolver_log" 2>/dev/null; then
        ready="yes"
        break
    fi
    if ! kill -0 "$resolver_pid" 2>/dev/null; then
        echo "resolver exited before becoming ready" >&2
        cat "$resolver_log" >&2
        exit 1
    fi
    i=$((i + 1))
    sleep 0.1
done

if [ -z "$ready" ]; then
    echo "resolver did not become ready in time" >&2
    cat "$resolver_log" >&2
    exit 1
fi

# Run the packaged binary on the non-A config, capturing stderr. --noexec
# --lines emits the generated rules without touching the kernel.
ferm_err=$(mktemp)
if ! "$FERM_BINARY" --noexec --lines /check.ferm 2>"$ferm_err"; then
    echo "ferm failed on the non-A resolve config" >&2
    cat "$ferm_err" >&2
    exit 1
fi

# A stub-resolver warning means dnspython did not actually serve the query.
if grep -qi "stub" "$ferm_err"; then
    echo "stub-resolver warning -- dnspython did not serve the non-A query" >&2
    cat "$ferm_err" >&2
    exit 1
fi

# Any other stderr noise is treated as a failure: a clean non-A resolve is
# silent.
if [ -s "$ferm_err" ]; then
    echo "unexpected stderr from the non-A resolve" >&2
    cat "$ferm_err" >&2
    exit 1
fi

echo "DNS-GATE-OK"
exit 0
