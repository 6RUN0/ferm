"""ferm ontology -> nft family/base-chain mapping and chain building."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, NamedTuple

from ...errors import FermError
from ...rules import (
    is_netfilter_builtin_chain,
)

if TYPE_CHECKING:
    from ...domains import (
        Family,
        TableInfo,
    )

from .model import NftBaseChain, NftRegularChain

#: An nft chain identifier (bare word; nft has no quoted-chain-name form).
_NFT_CHAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z][A-Za-z0-9_-]*\Z"
)


class BaseChainSpec(NamedTuple):
    """The nft base-chain declaration a ferm built-in chain maps to."""

    chain_type: str
    hook: str
    priority: int


#: (table, chain) -> (nft type, hook, priority).  Numeric priorities for
#: cross-version portability.
_BASE_CHAIN_MAP: Final[dict[tuple[str, str], BaseChainSpec]] = {
    ("filter", "INPUT"): BaseChainSpec("filter", "input", 0),
    ("filter", "FORWARD"): BaseChainSpec("filter", "forward", 0),
    ("filter", "OUTPUT"): BaseChainSpec("filter", "output", 0),
    ("nat", "PREROUTING"): BaseChainSpec("nat", "prerouting", -100),
    ("nat", "INPUT"): BaseChainSpec("nat", "input", 100),
    ("nat", "OUTPUT"): BaseChainSpec("nat", "output", -100),
    ("nat", "POSTROUTING"): BaseChainSpec("nat", "postrouting", 100),
    ("mangle", "PREROUTING"): BaseChainSpec("filter", "prerouting", -150),
    ("mangle", "INPUT"): BaseChainSpec("filter", "input", -150),
    ("mangle", "FORWARD"): BaseChainSpec("filter", "forward", -150),
    ("mangle", "OUTPUT"): BaseChainSpec("route", "output", -150),
    ("mangle", "POSTROUTING"): BaseChainSpec("filter", "postrouting", -150),
    ("raw", "PREROUTING"): BaseChainSpec("filter", "prerouting", -300),
    ("raw", "OUTPUT"): BaseChainSpec("filter", "output", -300),
}

#: arp supports only filter/INPUT and filter/OUTPUT.
_ARP_BASE_CHAIN_MAP: Final[dict[tuple[str, str], BaseChainSpec]] = {
    ("filter", "INPUT"): BaseChainSpec("filter", "input", 0),
    ("filter", "OUTPUT"): BaseChainSpec("filter", "output", 0),
}


def map_base_chain(
    domain: Family,
    table: str,
    chain: str,
) -> BaseChainSpec:
    """
    Map ``(table, built-in chain)`` to ``(nft type, hook, priority)``.

    A miss (broute/BROUTING, arp nat/mangle, unknown pair) raises
    :class:`~pyferm.errors.FermError` -- "built-in" does not imply
    "mappable".
    """
    table_map = _ARP_BASE_CHAIN_MAP if domain == "arp" else _BASE_CHAIN_MAP
    spec = table_map.get((table, chain))
    if spec is None:
        raise FermError(
            f"chain '{table}/{chain}' not yet supported by nft backend"
        )
    return spec


def nft_chain_name(table: str, chain: str) -> str:
    """
    Disambiguate a chain name inside the merged ``ferm`` table.

    The ``filter`` table keeps bare names (the common case, clean golden);
    every other table is prefixed ``<table>_<chain>`` so ``filter/INPUT``
    and ``mangle/INPUT`` do not collide.  Applied identically to chain
    definitions and to ``jump``/``goto`` targets.

    The final identifier is validated against nft's bare-word grammar (nft
    has no quoted-chain-name form): a name with whitespace/metacharacters
    would otherwise inject statements into ``add chain``/``jump`` -> a plain
    ferm error instead (review 2026-06-14, fix 1).
    """
    name = chain if table == "filter" else f"{table}_{chain}"
    if not _NFT_CHAIN_RE.match(name):
        raise FermError(f"chain name '{chain}' is not a valid nft identifier")
    return name


def build_chains(
    domain: Family,
    table: str,
    table_info: TableInfo,
) -> list[NftBaseChain | NftRegularChain]:
    """
    Build the sorted chain list for one table.

    :func:`is_netfilter_builtin_chain` selects the base-vs-user branch;
    :func:`map_base_chain` resolves the concrete hook (and errors on
    unmappable built-ins).  Policy is lowercased to nft spelling
    (``DROP`` -> ``drop``).  Names are disambiguated via
    :func:`nft_chain_name`.  Output is sorted for
    deterministic golden output.
    """
    chains: list[NftBaseChain | NftRegularChain] = []
    for name in sorted(table_info.chains):
        chain_info = table_info.chains[name]
        nft_name = nft_chain_name(table, name)
        if is_netfilter_builtin_chain(table, name):
            chain_type, hook, default_priority = map_base_chain(
                domain, table, name
            )
            # A config override (`chain X priority -1`) replaces the
            # hardcoded default; otherwise keep the _BASE_CHAIN_MAP value.
            priority = (
                chain_info.priority
                if chain_info.priority is not None
                else default_priority
            )
            policy = (
                chain_info.policy.lower()
                if chain_info.policy is not None
                else None
            )
            chains.append(
                NftBaseChain(
                    nft_name, chain_type, hook, priority, policy=policy
                )
            )
        else:
            if chain_info.priority is not None:
                raise FermError(
                    f"priority is only valid on a base chain, not "
                    f"user chain '{name}'"
                )
            chains.append(NftRegularChain(nft_name))
    return chains
