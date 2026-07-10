"""
Read-only diff preview for ``ferm --plan``.

Provides three parsers that each produce a ``{table: ParsedTable}`` model:

- :func:`parse_save` -- parses an ``iptables-save`` dump (iptables backend,
  current side).
- :func:`parse_nft_script` -- parses a ``nft -f`` script produced by the
  nft backend (desired side).
- :func:`parse_nft_list` -- parses the output of ``nft list table <fam>
  ferm`` (nft backend, current side).

The diff engine (:func:`diff_tables`) and renderers
(:func:`render_structured`, :func:`render_unified`) are backend-agnostic and
consume whichever parser's output is passed to them.  Read-only by
construction: this module never runs a command -- the cli hands it text.
"""

from .delta import _build_desired_index as _build_desired_index
from .delta import _emit_chain_changes as _emit_chain_changes
from .delta import _emit_set_changes as _emit_set_changes
from .delta import build_nft_delta as build_nft_delta
from .delta import emit_delta_script as emit_delta_script
from .delta import needs_full_reload as needs_full_reload
from .diff import diff_tables as diff_tables
from .model import ChainRebuild as ChainRebuild
from .model import DesuetChain as DesuetChain
from .model import ForeignChain as ForeignChain
from .model import ParsedChain as ParsedChain
from .model import ParsedSet as ParsedSet
from .model import ParsedTable as ParsedTable
from .model import Plan as Plan
from .model import PlanDiff as PlanDiff
from .model import PolicyChange as PolicyChange
from .model import RuleChange as RuleChange
from .model import SetChange as SetChange
from .model import SetChangeKind as SetChangeKind
from .model import _DesiredIndex as _DesiredIndex
from .readback import _canonicalize_rule as _canonicalize_rule
from .readback import _join_multiline_elements as _join_multiline_elements
from .readback import canonicalize_nft_header as canonicalize_nft_header
from .readback import canonicalize_nft_rule as canonicalize_nft_rule
from .readback import parse_nft_list as parse_nft_list
from .readback import parse_nft_script as parse_nft_script
from .readback import parse_save as parse_save
from .render import _diff_blob as _diff_blob
from .render import render_plan as render_plan
from .render import render_structured as render_structured
from .render import render_unified as render_unified
from .render import summary_line as summary_line
