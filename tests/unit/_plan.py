"""
Shared builders for the ``plan/`` differ test cluster.

These wrap the two colliding local ``_tbl``/``_table_with_set`` helpers that
several plan test modules defined independently with the *same name but
different table keys* (``filter`` vs ``ferm``).  Splitting them into two
explicitly named builders removes that trap; ``plan_ip`` folds the ubiquitous
single-family ``Plan`` constructor.
"""

from __future__ import annotations

from pyferm.plan import ParsedChain, ParsedTable, Plan, PlanDiff


def filter_table(chains: dict[str, ParsedChain]) -> dict[str, ParsedTable]:
    """Wrap *chains* into a single ``filter`` table (iptables-style input)."""
    return {"filter": ParsedTable(chains=chains)}


def ferm_table(chains: dict[str, ParsedChain]) -> dict[str, ParsedTable]:
    """Wrap *chains* into a single ``ferm`` table (nft-style input)."""
    table = ParsedTable()
    table.chains.update(chains)
    return {"ferm": table}


def plan_ip(diff: PlanDiff) -> Plan:
    """Build a single-family (``ip``) :class:`Plan` around one *diff*."""
    return Plan(families={"ip": diff})
