"""
One-shot authoritative resolver for the dnspython non-A gate.

Serves a fixed zone for ``gate.example`` on ``127.0.0.1:53`` so the packaged
ferm's frozen dnspython makes a REAL non-A query through the container-local
``/etc/resolv.conf``. The MX answer points at ``mail.gate.example``, which
also has an A record: ferm resolves an MX exchange to an address in a second
pass, so both records must be served for the lookup to yield a usable rule.

stdlib + dnslib only (dnslib is installed into the gate image). The process
prints ``DNS-GATE-READY`` to stdout once the socket is bound and listening,
then serves until it is killed.
"""

from __future__ import annotations

import time

from dnslib import RR
from dnslib.server import DNSServer

# A fixed authoritative zone. The MX exchange (mail.gate.example) carries its
# own A record because ferm re-resolves an MX target to an address.
_ZONE = """
gate.example.       IN  MX  10 mail.gate.example.
mail.gate.example.  IN  A   192.0.2.10
"""

_records = RR.fromZone(_ZONE)


class _FixedZoneResolver:
    """Answer every query from the fixed in-memory zone."""

    def resolve(self, request, handler):  # noqa: ARG002 -- dnslib callback API
        """Return the matching records for the queried name and type."""
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        for record in _records:
            if record.rname == qname and record.rtype == qtype:
                reply.add_answer(record)
        return reply


def main() -> None:
    """Bind the authoritative resolver, announce readiness, then serve."""
    server = DNSServer(_FixedZoneResolver(), address="127.0.0.1", port=53)
    server.start_thread()
    print("DNS-GATE-READY", flush=True)
    try:
        while server.isAlive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
