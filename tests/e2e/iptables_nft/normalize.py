"""
Canonicalize ``nft list ruleset`` dumps for a cross-translator diff.

Both sides of this differential are kernel readback (``nft list
ruleset``): one after loading the port's own ``--nft`` script, the other
after loading the port's ``iptables-restore`` output through
``iptables-nft-restore`` -- the kernel's own iptables->nft translator.
The kernel canonicalises much on its own (dscp names, ct-state bit order,
named-set contents), so the two dumps already agree on most spellings.
What still diverges is a small, well-understood set of surface
conventions that this module folds away:

* ``counter packets N bytes M`` -- iptables-nft stamps a counter on every
  rule; the port emits none.
* the L4-dispatch spelling -- iptables-nft writes the family-specific
  ``ip protocol tcp`` / ``ip6 nexthdr tcp``; the port writes the
  family-agnostic ``meta l4proto tcp``.  For a final-header L4 match these
  are equivalent, so both fold to ``meta l4proto`` -- and drop entirely
  when a same-protocol payload match (``tcp dport ...``) already carries
  the dependency.
* hex width -- ``0x00000010`` vs ``0x10``.
* the default limit burst -- iptables-nft prints ``burst 5 packets``
  (the xt/nft default); the port omits it.
* element order inside anonymous sets and ``ct state``/``ct status``
  comma-lists -- semantically unordered.

Every fold here is an equivalence *assumption*: normalise too eagerly and
a real translation bug (``dport`` emitted as ``sport``) is hidden.  Each
rule below is therefore deliberately narrow, keyed to one spelling
divergence, and never rewrites the match *semantics* -- only its surface
form.  The curated case set is scalar by construction, so set-vs-scalar
rule-granularity divergence (the port collapses arrays into sets, the
iptables path unfolds them) never arises and is intentionally out of
scope.
"""

from __future__ import annotations

import re

#: A rule's inline counter, always stamped by iptables-nft, never by the
#: port.  Dropped wholesale before any other fold.
_COUNTER = re.compile(r"\bcounter packets \d+ bytes \d+ ?")

#: L4 protocols whose payload match (``tcp dport``, ``icmp type``, ...)
#: already implies the protocol, making a leading dispatch clause
#: redundant.  ``ipv6-icmp`` is nft's ``icmpv6``.
_L4_PROTOS = (
    "tcp",
    "udp",
    "udplite",
    "dccp",
    "sctp",
    "icmp",
    "icmpv6",
)

#: The three equivalent L4-dispatch spellings; captured proto goes to the
#: canonical ``meta l4proto`` form (or is dropped when redundant).
_L4_DISPATCH = re.compile(
    r"\b(?:ip protocol|ip6 nexthdr|meta l4proto) "
    r"(tcp|udp|udplite|dccp|sctp|icmp|icmpv6|ipv6-icmp)\b"
)

#: The default limit burst both xt and nft assume; the port omits it, so
#: fold it away when present with the default value.
_DEFAULT_BURST = re.compile(r" burst 5 packets\b")

#: Any hex literal, re-emitted zero-padding-free as ``0x%x``.
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")

#: An anonymous set ``{ a, b, c }`` whose element order is not semantic.
_ANON_SET = re.compile(r"\{ ([^{}]*?) \}")

#: ``ct state``/``ct status`` comma-lists, order-insensitive.
_CT_LIST = re.compile(r"\bct (state|status) ([a-z,]+)")

#: The iptables-nft ``ipv6-icmp`` proto name; nft's own spelling is
#: ``icmpv6`` and the port emits that.
_IPV6_ICMP = "ipv6-icmp"


def _norm_hex(text: str) -> str:
    return _HEX.sub(lambda m: f"0x{int(m.group(0), 16):x}", text)


def _fold_l4_dispatch(text: str) -> str:
    """
    Fold the three L4-dispatch spellings to one, dropping redundant ones.

    ``ip protocol tcp`` / ``ip6 nexthdr tcp`` / ``meta l4proto tcp`` all
    select the same packets for a final-header match.  When a
    same-protocol payload match follows (``... tcp dport 22``) the
    dispatch is pure redundancy the port never emits, so it is removed;
    otherwise it is rewritten to the canonical ``meta l4proto`` spelling.
    """

    def replace(match: re.Match[str]) -> str:
        proto = match.group(1)
        if proto == _IPV6_ICMP:
            proto = "icmpv6"
        payload = "icmpv6" if proto == "icmpv6" else proto
        # A payload keyword for the same protocol elsewhere in the rule
        # makes the dispatch redundant (``tcp dport`` implies tcp).
        rest = text[: match.start()] + text[match.end() :]
        if re.search(rf"\b{re.escape(payload)} \w", rest):
            return ""
        return f"meta l4proto {proto}"

    folded = _L4_DISPATCH.sub(replace, text)
    return re.sub(r"\s+", " ", folded).strip()


def _sort_anon_sets(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        elems = [e.strip() for e in match.group(1).split(",")]
        elems.sort(key=_sort_key)
        return "{ " + ", ".join(elems) + " }"

    return _ANON_SET.sub(replace, text)


def _sort_ct_lists(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        kind = match.group(1)
        flags = sorted(match.group(2).split(","))
        return f"ct {kind} {','.join(flags)}"

    return _CT_LIST.sub(replace, text)


def _sort_key(elem: str) -> tuple[int, object]:
    """Sort set elements numerically when possible, else lexically."""
    try:
        return (0, int(elem, 0))
    except ValueError:
        return (1, elem)


def canonicalize_rule(rule: str) -> str:
    """Fold one rule line to its cross-translator canonical form."""
    text = rule.strip()
    text = _COUNTER.sub("", text)
    text = _norm_hex(text)
    text = _DEFAULT_BURST.sub("", text)
    text = _fold_l4_dispatch(text)
    text = _sort_anon_sets(text)
    text = _sort_ct_lists(text)
    return re.sub(r"\s+", " ", text).strip()


def _is_base_chain_decl(line: str) -> bool:
    # ``type filter hook input priority 0; policy drop;`` -- the base
    # chain's declaration, not a rule.  Table name and priority spelling
    # diverge between the two sides, so it is never compared.
    return line.startswith("type ") and " hook " in line


#: iptables table concepts the port folds into its single ``ferm`` nft
#: table by prefixing the chain name (``nat_PREROUTING``); ``filter`` is
#: the default and stays unprefixed.  iptables-nft instead uses a
#: separate nft table per concept with bare chain names, so the concept
#: must key the comparison for the two sides to line up.
_FERM_TABLE = "ferm"
_TABLE_CONCEPTS = ("nat", "mangle", "raw", "security")


def _table_and_chain(nft_table: str, chain: str) -> tuple[str, str]:
    """
    Resolve the (table concept, bare chain) a dumped chain belongs to.

    iptables-nft names the nft table after the concept, so its chain
    names are already bare.  The port packs every concept into one
    ``ferm`` table and encodes the concept in a ``<concept>_`` chain
    prefix, so that prefix is peeled back off to recover the same pair.
    """
    if nft_table != _FERM_TABLE:
        return nft_table, chain
    for concept in _TABLE_CONCEPTS:
        prefix = f"{concept}_"
        if chain.startswith(prefix):
            return concept, chain[len(prefix) :]
    return "filter", chain


def parse_dump(dump: str) -> dict[tuple[str, str, str], list[str]]:
    """
    Reduce an ``nft list ruleset`` dump to comparable chains.

    Returns a mapping from ``(family, table, chain)`` to the
    canonicalised rule lines in emission order, where ``table`` is the
    iptables table *concept* (``filter``/``nat``/...) recovered
    identically from both sides via :func:`_table_and_chain`.  The nft
    table *name* is deliberately not compared: the port names its table
    ``ferm`` while iptables-nft names one table per concept.
    """
    chains: dict[tuple[str, str, str], list[str]] = {}
    family = ""
    key: tuple[str, str, str] | None = None
    nft_table = ""
    for raw in dump.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("table "):
            # ``table ip filter {``
            parts = line.split()
            family, nft_table = parts[1], parts[2]
            continue
        if line.startswith("chain "):
            table, chain = _table_and_chain(nft_table, line.split()[1])
            key = (family, table, chain)
            chains.setdefault(key, [])
            continue
        if line == "}":
            key = None
            continue
        if key is None or _is_base_chain_decl(line):
            continue
        chains[key].append(canonicalize_rule(line))
    return chains
