"""
The native nftables backend (Phase 2).

Translates each :class:`pyferm.rules.RenderedRule` to a small internal
nft-expression model and serializes it (``to_text``) into one atomic
``nft -f`` script over ``table <family> ferm`` only.

This ``__init__`` is the package's compatibility seam: it re-exports
every name the historical single-module ``backend.nft`` exposed to the
cli and the test suite, private helpers included, so the package split
stays pure code motion.
"""

from .assemble import (
    _collapse_chain_rules as _collapse_chain_rules,
)
from .assemble import _elements_equal as _elements_equal
from .assemble import _is_vmap_verdict as _is_vmap_verdict
from .assemble import _merge_run as _merge_run
from .assemble import _stmt_equal as _stmt_equal
from .assemble import _vmap_candidate as _vmap_candidate
from .assemble import translate_rule as translate_rule
from .backend import NftBackend as NftBackend
from .chains import BaseChainSpec as BaseChainSpec
from .chains import build_chains as build_chains
from .chains import map_base_chain as map_base_chain
from .chains import nft_chain_name as nft_chain_name
from .matches import _CT_STATE_RANK as _CT_STATE_RANK
from .matches import (
    _ICMP6_TYPE_BY_NUMBER as _ICMP6_TYPE_BY_NUMBER,
)
from .matches import _ICMP6_TYPE_MAP as _ICMP6_TYPE_MAP
from .matches import (
    _ICMP_TYPE_BY_NUMBER as _ICMP_TYPE_BY_NUMBER,
)
from .matches import _ICMP_TYPE_MAP as _ICMP_TYPE_MAP
from .matches import _ct_bitmask_expr as _ct_bitmask_expr
from .matches import _dscp_class_value as _dscp_class_value
from .matches import _dscp_value as _dscp_value
from .matches import _icmp_type_expr as _icmp_type_expr
from .matches import _iprange_bound as _iprange_bound
from .matches import _mark_value as _mark_value
from .matches import _masked_mark_expr as _masked_mark_expr
from .matches import _tcp_flags_expr as _tcp_flags_expr
from .matches import (
    _translate_match_parts as _translate_match_parts,
)
from .matches import (
    _translate_match_set as _translate_match_set,
)
from .matches import translate_match as translate_match
from .model import NFT_COMMENT_MAX as NFT_COMMENT_MAX
from .model import TOOL_NFT as TOOL_NFT
from .model import NftBaseChain as NftBaseChain
from .model import NftMatch as NftMatch
from .model import NftObjectRef as NftObjectRef
from .model import NftQuota as NftQuota
from .model import NftRegularChain as NftRegularChain
from .model import NftReset as NftReset
from .model import NftRule as NftRule
from .model import NftSetUpdate as NftSetUpdate
from .model import NftStatement as NftStatement
from .model import NftTable as NftTable
from .model import NftVerdict as NftVerdict
from .model import NftVmap as NftVmap
from .model import _nft_l4proto as _nft_l4proto
from .model import _nft_quote_string as _nft_quote_string
from .model import _nft_time_canon as _nft_time_canon
from .model import _validate_port as _validate_port
from .model import _validate_set_name as _validate_set_name
from .model import first_scalar as first_scalar
from .model import render_comment as render_comment
from .model import unwrap_value as unwrap_value
from .sets import NftSetType as NftSetType
from .sets import (
    _collect_set_declarations as _collect_set_declarations,
)
from .sets import (
    _collect_set_target_names as _collect_set_target_names,
)
from .sets import _DynSetDecl as _DynSetDecl
from .sets import _full_reload_text as _full_reload_text
from .sets import _ObjectDecl as _ObjectDecl
from .sets import (
    _references_empty_named_set as _references_empty_named_set,
)
from .sets import (
    _set_type_and_elements as _set_type_and_elements,
)
from .sets import _SetDecl as _SetDecl
from .sets import serialize_table as serialize_table
from .stateful import _TIME_OF_DAY_RE as _TIME_OF_DAY_RE
from .stateful import (
    _build_recent_specs as _build_recent_specs,
)
from .stateful import _clock_parts as _clock_parts
from .stateful import _connbytes_match as _connbytes_match
from .stateful import _connbytes_range as _connbytes_range
from .stateful import _connbytes_u64 as _connbytes_u64
from .stateful import _connlimit_count as _connlimit_count
from .stateful import _connlimit_update as _connlimit_update
from .stateful import _datetime_iso as _datetime_iso
from .stateful import (
    _finalize_connlimit_names as _finalize_connlimit_names,
)
from .stateful import _hashlimit_key as _hashlimit_key
from .stateful import (
    _hashlimit_key_implies_l4proto as _hashlimit_key_implies_l4proto,
)
from .stateful import _hashlimit_rate as _hashlimit_rate
from .stateful import _hashlimit_update as _hashlimit_update
from .stateful import (
    _prefix_length_mask as _prefix_length_mask,
)
from .stateful import _quota_canon as _quota_canon
from .stateful import _quota_statement as _quota_statement
from .stateful import _recent_update as _recent_update
from .stateful import _reduce_rate as _reduce_rate
from .stateful import _statistic_match as _statistic_match
from .stateful import _time_day_match as _time_day_match
from .stateful import _time_hour_match as _time_hour_match
from .stateful import _time_of_day as _time_of_day
from .verdicts import _masked_mark_set as _masked_mark_set
from .verdicts import _nat_has_port as _nat_has_port
from .verdicts import _netmap_verdict as _netmap_verdict
from .verdicts import _nflog_verdict as _nflog_verdict
from .verdicts import _nfqueue_verdict as _nfqueue_verdict
from .verdicts import _reject_for as _reject_for
from .verdicts import (
    _setmark_effective as _setmark_effective,
)
from .verdicts import _synproxy_verdict as _synproxy_verdict
from .verdicts import _tcpopt_nft_name as _tcpopt_nft_name
from .verdicts import _tproxy_verdict as _tproxy_verdict
from .verdicts import build_verdict as build_verdict
