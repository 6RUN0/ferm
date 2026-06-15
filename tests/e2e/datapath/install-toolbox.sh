#!/bin/sh
# Install the datapath-e2e toolbox: the netfilter stack plus the probing
# tools the driver shells out to, on whichever distro the base image is.
# Detect the package manager via `command -v` so a new distro is a
# one-line addition to the matrix -- this script already speaks its
# family's package names.
#
# The Debian package set is canonical; each family maps it as follows:
#
#   Debian (apt)     family equivalents
#   ----------------------------------------------------------------
#   nftables      -> nftables        (every family)
#   iptables      -> iptables / iptables-nft   (+ ip6tables on apk)
#   iproute2      -> iproute2 / iproute  (real `ip netns`/`ss`;
#                                         busybox cannot)
#   nmap          -> nmap
#   ncat          -> nmap-ncat        (Arch ships ncat inside nmap)
#   conntrack     -> conntrack-tools  (provides `conntrack`)
#   procps        -> procps-ng        (real `sysctl -w` on a netns)
#   python3       -> python3 / python / python3.11 / python311
#                    (RHEL9 + Leap default python3 is too old for
#                     pyferm's `typing.TypeAlias`; pin 3.11 and expose
#                     it as `python3` on PATH)
set -eu

if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y --no-install-recommends \
        nftables iptables iproute2 nmap ncat conntrack procps python3
    rm -rf /var/lib/apt/lists/*
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y \
        nftables iptables-nft iproute nmap nmap-ncat \
        conntrack-tools procps-ng python3.11
    ln -sf "$(command -v python3.11)" /usr/local/bin/python3
    dnf clean all
elif command -v apk >/dev/null 2>&1; then
    # `mount` (util-linux) overrides busybox's mount applet, whose
    # fixed-size getmntent buffer truncates the long overlayfs line in
    # /proc/mounts and then fails to find /proc/sys for the driver's
    # `mount -o remount,rw /proc/sys`; the real binary parses it.
    apk add --no-cache \
        nftables iptables ip6tables iproute2 nmap nmap-ncat \
        conntrack-tools procps-ng mount python3
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm
    # iptables-nft replaces the stock iptables; --ask=4 answers the
    # conflict prompt non-interactively.
    pacman -S --noconfirm --ask=4 \
        nftables iptables-nft iproute2 nmap conntrack-tools python
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive refresh
    zypper --non-interactive install \
        nftables iptables iproute2 nmap ncat \
        conntrack-tools procps python311
    ln -sf "$(command -v python3.11)" /usr/local/bin/python3
    # Leap's `iptables` package defaults the alternatives to the legacy
    # xtables backend, which needs the ip_tables kernel module the test
    # host lacks (every other family here runs the nft engine).  The
    # nft-backed `xtables-nft-multi` ships in the same package but the
    # front-end symlinks point at legacy and `iptables-{restore,save}` are
    # not even alternatives-managed; repoint them at the nft multi-call
    # binary so the whole iptables front-end speaks nf_tables.
    for tool in iptables iptables-restore iptables-save \
                ip6tables ip6tables-restore ip6tables-save; do
        ln -sf xtables-nft-multi "/usr/sbin/$tool"
    done
else
    echo "unsupported package manager" >&2
    exit 1
fi
