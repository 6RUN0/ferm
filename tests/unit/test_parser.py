"""Unit tests for the parser (``enter`` and its helpers).

The parser ties the whole front end together, so these tests drive it
end to end: feed a ferm source string, run :meth:`Parser.enter`, and
inspect the resulting ``%domains`` state (the unfolded
:class:`~pyferm.rules.RenderedRule` lists, chain policies, preserve flags)
or the parser's hook lists.  Each test pins down a Perl-ism from the port:
copy-on-write scoping, the domain/table/chain array replay, deferred value
negation, function token splicing, ``@if``/``@else``, sub-chains, shortcuts,
``@preserve`` and the located error messages.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest

from pyferm.config import Options
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.functions import Evaluator
from pyferm.modules import TARGET_DEFS
from pyferm.parser import MAX_BLOCK_DEPTH, Parser, collect_filenames
from pyferm.rules import CORE_TARGETS
from pyferm.scope import Frame, OptionKind, Scope
from pyferm.tokenizer import Script, Tokenizer
from pyferm.values import Multi, Negated, Params, PreNegated

if TYPE_CHECKING:
    from pathlib import Path

    from pyferm.rules import RenderedRule


def _parse(source: str, *, options: Options | None = None) -> Parser:
    """Parse ``source`` and return the populated parser."""
    options = options if options is not None else Options(test=True)
    script = Script(filename="<test>", handle=io.StringIO(source))
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    evaluator = Evaluator(tokenizer, scope)
    parser = Parser(evaluator, {}, options)
    parser.enter(0, None)
    return parser


def _rules(
    parser: Parser, domain: Family, table: str, chain: str
) -> list[RenderedRule]:
    """Return the unfolded rules of one chain."""
    return parser.domains[domain].tables[table].chains[chain].rules


def _options(rule: RenderedRule) -> list[tuple[str, object, OptionKind]]:
    """Return a rule's options as ``(name, value, kind)`` tuples."""
    return [(opt.name, opt.value, opt.kind) for opt in rule.options]


# -- basic rules -----------------------------------------------------------


def test_basic_rule_records_options_and_kinds() -> None:
    parser = _parse("chain INPUT proto tcp dport 22 ACCEPT;")
    rules = _rules(parser, Family.IP, "filter", "INPUT")
    assert len(rules) == 1
    assert _options(rules[0]) == [
        ("protocol", "tcp", OptionKind.PROTO),
        ("dport", "22", OptionKind.OPTION),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]
    assert parser.domains[Family.IP].enabled


def test_suboptions_record_their_introducing_module() -> None:
    # The contract field Option.module links a sub-option to the module
    # whose merge_keywords introduced its keyword (a sanctioned
    # deviation); the match/jump elements themselves carry no module.
    parser = _parse("chain INPUT mod state state NEW ACCEPT;")
    options = _rules(parser, Family.IP, "filter", "INPUT")[0].options
    assert [(o.name, o.kind, o.module) for o in options] == [
        ("match", OptionKind.MATCH_MODULE, None),
        ("state", OptionKind.OPTION, "state"),
        ("jump", OptionKind.TARGET, None),
    ]


def test_target_module_suboptions_record_module() -> None:
    parser = _parse("table nat chain PREROUTING proto tcp DNAT to '10.0.0.1';")
    options = _rules(parser, Family.IP, "nat", "PREROUTING")[0].options
    assert ("to-destination", "DNAT") in [(o.name, o.module) for o in options]


def test_shortcut_suboptions_record_module() -> None:
    # the 'dports' shortcut implies 'mod multiport' and then its sub-option
    parser = _parse("chain INPUT proto tcp dports (22 80) ACCEPT;")
    options = _rules(parser, Family.IP, "filter", "INPUT")[0].options
    assert [(o.name, o.module) for o in options] == [
        ("protocol", None),
        ("match", None),
        ("destination-ports", "multiport"),
        ("jump", None),
    ]


def test_chain_defaults_to_ip_filter() -> None:
    parser = _parse("chain OUTPUT ACCEPT;")
    assert "filter" in parser.domains[Family.IP].tables
    assert _options(_rules(parser, Family.IP, "filter", "OUTPUT")[0]) == [
        ("jump", "ACCEPT", OptionKind.TARGET)
    ]


def test_explicit_table_is_used() -> None:
    parser = _parse("table nat chain POSTROUTING MASQUERADE;")
    rules = _rules(parser, Family.IP, "nat", "POSTROUTING")
    assert _options(rules[0]) == [("jump", "MASQUERADE", OptionKind.TARGET)]


def test_policy_sets_chain_policy_without_a_rule() -> None:
    parser = _parse("chain INPUT policy DROP;")
    chain = parser.domains[Family.IP].tables["filter"].chains["INPUT"]
    assert chain.policy == "DROP"
    assert chain.rules == []
    assert parser.domains[Family.IP].enabled


# -- domain handling -------------------------------------------------------


def test_domain_block_targets_one_family() -> None:
    parser = _parse("domain ip6 { chain INPUT proto tcp ACCEPT; }")
    assert "ip" not in parser.domains or not parser.domains[Family.IP].enabled
    rules = _rules(parser, Family.IP6, "filter", "INPUT")
    assert _options(rules[0])[0] == ("protocol", "tcp", OptionKind.PROTO)


def test_dual_stack_domain_replays_for_each_family() -> None:
    parser = _parse("domain (ip ip6) { chain INPUT ACCEPT; }")
    for family in (Family.IP, Family.IP6):
        rules = _rules(parser, family, "filter", "INPUT")
        assert _options(rules[0]) == [("jump", "ACCEPT", OptionKind.TARGET)]


def test_domain_filter_skips_other_families() -> None:
    parser = _parse(
        "domain ip6 { chain INPUT ACCEPT; }",
        options=Options(test=True, domain="ip"),
    )
    assert "ip6" not in parser.domains


# -- table / chain arrays --------------------------------------------------


def test_chain_array_emits_into_each_chain() -> None:
    parser = _parse("table filter chain (INPUT OUTPUT) ACCEPT;")
    for chain in ("INPUT", "OUTPUT"):
        rules = _rules(parser, Family.IP, "filter", chain)
        assert _options(rules[0]) == [("jump", "ACCEPT", OptionKind.TARGET)]


def test_table_array_replays_per_table() -> None:
    parser = _parse("table (filter mangle) chain FORWARD ACCEPT;")
    for table in ("filter", "mangle"):
        rules = _rules(parser, Family.IP, table, "FORWARD")
        assert _options(rules[0]) == [("jump", "ACCEPT", OptionKind.TARGET)]


def _comment(rule: RenderedRule) -> object:
    """Return the value of a rule's ``comment`` option, if any."""
    return {opt.name: opt.value for opt in rule.options}.get("comment")


def test_chain_auto_var_expands_to_chain_name() -> None:
    # The header records the chain in ``auto["CHAIN"]`` so ``$CHAIN`` resolves
    # to the current chain name.
    parser = _parse("chain INPUT mod comment comment $CHAIN ACCEPT;")
    assert _comment(_rules(parser, Family.IP, "filter", "INPUT")[0]) == "INPUT"


def test_chain_array_auto_var_expands_per_chain() -> None:
    # Each chain in an array gets its own ``auto["CHAIN"]`` entry, so
    # ``$CHAIN`` differs per replay.
    parser = _parse("chain (INPUT OUTPUT) mod comment comment $CHAIN ACCEPT;")
    for chain in ("INPUT", "OUTPUT"):
        assert _comment(_rules(parser, Family.IP, "filter", chain)[0]) == chain


def test_table_auto_var_expands_to_table_name() -> None:
    parser = _parse(
        "table nat chain POSTROUTING mod comment comment $TABLE ACCEPT;"
    )
    rule = _rules(parser, Family.IP, "nat", "POSTROUTING")[0]
    assert _comment(rule) == "nat"


def test_table_array_auto_var_expands_per_table() -> None:
    parser = _parse(
        "table (filter mangle) chain FORWARD "
        "mod comment comment $TABLE ACCEPT;"
    )
    for table in ("filter", "mangle"):
        rule = _rules(parser, Family.IP, table, "FORWARD")[0]
        assert _comment(rule) == table


def test_duplicate_table_specification_warns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _parse("table filter table nat chain INPUT ACCEPT;")
    assert "Table is already specified" in capsys.readouterr().err


def test_lowercase_builtin_chain_name_is_rejected() -> None:
    with pytest.raises(FermError, match="upper case"):
        _parse("chain input ACCEPT;")


def test_chain_name_too_long_is_rejected() -> None:
    with pytest.raises(FermError, match="29 characters"):
        _parse(f"chain {'x' * 30} ACCEPT;")


def test_chain_name_at_29_chars_is_accepted() -> None:
    # The cap rejects names *longer* than 29 (``> 29``); a 29-char name is
    # the boundary that must still parse -- the off-by-one ``>= 29`` would
    # wrongly reject the longest legal name.
    name = "x" * 29
    parser = _parse(f"chain {name} ACCEPT;")
    assert len(_rules(parser, Family.IP, "filter", name)) == 1


# -- variables and functions ----------------------------------------------


def test_variable_expansion() -> None:
    parser = _parse("@def $p = 22; chain INPUT proto tcp dport $p ACCEPT;")
    rules = _rules(parser, Family.IP, "filter", "INPUT")
    assert ("dport", "22", OptionKind.OPTION) in _options(rules[0])


def test_function_body_is_spliced_into_the_stream() -> None:
    parser = _parse(
        "@def &allow($port) = proto tcp dport $port ACCEPT;"
        "chain INPUT &allow(22);"
    )
    rules = _rules(parser, Family.IP, "filter", "INPUT")
    assert _options(rules[0]) == [
        ("protocol", "tcp", OptionKind.PROTO),
        ("dport", "22", OptionKind.OPTION),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]


def test_function_wrong_arity_errors() -> None:
    with pytest.raises(FermError, match="Wrong number of parameters"):
        _parse("@def &f($a) = ACCEPT; chain INPUT &f(1, 2);")


def test_function_interpolates_param_inside_quoted_token() -> None:
    # A $param inside a double-quoted body token is string-interpolated
    # (not spliced as a separate token), so "pre-$x" becomes "pre-hi".
    parser = _parse(
        '@def &c($x) = mod comment comment "pre-$x" ACCEPT;chain INPUT &c(hi);'
    )
    rule = _rules(parser, Family.IP, "filter", "INPUT")[0]
    assert _comment(rule) == "pre-hi"


def test_function_binds_each_parameter_positionally() -> None:
    parser = _parse(
        "@def &f($a, $b) = proto tcp sport $a dport $b ACCEPT;"
        "chain INPUT &f(11, 22);"
    )
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert options == [
        ("protocol", "tcp", OptionKind.PROTO),
        ("sport", "11", OptionKind.OPTION),
        ("dport", "22", OptionKind.OPTION),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]


def test_function_expands_list_argument_into_each_rule() -> None:
    # A list argument is spliced back as "( ... )" so the callee unfolds it
    # into one rule per element.
    parser = _parse(
        "@def &f($p) = proto tcp dport $p ACCEPT;chain INPUT &f((22 80));"
    )
    dports = [
        value
        for name, value, _ in [
            opt
            for rule in _rules(parser, Family.IP, "filter", "INPUT")
            for opt in _options(rule)
        ]
        if name == "dport"
    ]
    assert dports == ["22", "80"]


def test_function_substitutes_param_at_end_of_body() -> None:
    # When a $param is the last token of the body, the interpolation loop's
    # look-ahead must still see the following name token; an off-by-one there
    # leaves a bare "$" in the stream.
    parser = _parse("@def &g($t) = proto tcp jump $t;chain INPUT &g(ACCEPT);")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert options == [
        ("protocol", "tcp", OptionKind.PROTO),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]


def test_block_function_call_consumes_trailing_semicolon() -> None:
    # A function whose body contains a { } block is a "block" function; its
    # call site consumes the trailing ";" (expect_token(";")).
    parser = _parse(
        "@def &b($p) = proto $p { dport 22 ACCEPT; }chain INPUT &b(tcp);"
    )
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert options == [
        ("protocol", "tcp", OptionKind.PROTO),
        ("dport", "22", OptionKind.OPTION),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]


# -- conditionals ----------------------------------------------------------


def test_if_true_keeps_body() -> None:
    parser = _parse("@if 1 { chain INPUT ACCEPT; }")
    assert _rules(parser, Family.IP, "filter", "INPUT")


def test_if_false_with_else_takes_else() -> None:
    parser = _parse(
        "@if 0 { chain INPUT ACCEPT; } @else { chain OUTPUT DROP; }"
    )
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert "INPUT" not in chains
    assert _options(chains["OUTPUT"].rules[0]) == [
        ("jump", "DROP", OptionKind.TARGET)
    ]


def test_if_false_without_else_drops_body() -> None:
    parser = _parse("@if 0 { chain INPUT ACCEPT; }")
    tables = parser.domains.get(Family.IP)
    assert tables is None or "filter" not in tables.tables


def test_if_false_keeps_following_non_else_statement() -> None:
    # When @if is false and the token after the swallowed then-block is a
    # normal statement (not @else), that statement must stream unchanged --
    # the @else shim only consumes a literal ``@else`` token.
    parser = _parse("@if 0 { chain INPUT ACCEPT; } chain OUTPUT DROP;")
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert "INPUT" not in chains
    assert _options(chains["OUTPUT"].rules[0]) == [
        ("jump", "DROP", OptionKind.TARGET)
    ]


# -- negation --------------------------------------------------------------


def test_value_negation_wraps_the_value() -> None:
    parser = _parse("chain INPUT proto tcp dport ! 22 ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, Family.IP, "filter", "INPUT")[0]
        )
    }
    assert options["dport"] == Negated("22")


def test_proto_negation_is_not_a_module_merge() -> None:
    parser = _parse("chain INPUT proto ! tcp ACCEPT;")
    rule = _rules(parser, Family.IP, "filter", "INPUT")[0]
    name, value, kind = _options(rule)[0]
    assert (name, kind) == ("protocol", OptionKind.PROTO)
    assert value == Negated("tcp")


def _option_values(parser: Parser, chain: str) -> dict[str, object]:
    return {
        name: value
        for name, value, _ in _options(
            _rules(parser, Family.IP, "filter", chain)[0]
        )
    }


def test_pre_negation_is_tagged_distinctly() -> None:
    # A "!" that precedes a value on a pre-negatable keyword yields a
    # PreNegated value (tagged "pre_negated"), distinct from an ordinary
    # value negation -- the tag drives per-family iptables rendering.
    parser = _parse("chain INPUT mod conntrack ctstate ! ESTABLISHED ACCEPT;")
    assert _option_values(parser, "INPUT")["ctstate"] == PreNegated(
        "ESTABLISHED"
    )


def test_multi_code_keyword_collects_every_param() -> None:
    # A keyword with several letter codes (tcp-flags is "s s") gathers one
    # value per code into a Params list; dropping the list empties it.
    parser = _parse("chain INPUT proto tcp tcp-flags (SYN ACK) SYN ACCEPT;")
    assert _option_values(parser, "INPUT")["tcp-flags"] == Params(
        ["SYN,ACK", "SYN"]
    )


def test_m_param_keyword_keeps_all_values() -> None:
    # An "m" (repeated multi) parameter passes the family plus every value to
    # realize_deferred; dropping the family argument swallows the first value.
    parser = _parse(
        "table nat chain POSTROUTING proto tcp "
        "SNAT to-source (1.2.3.4 5.6.7.8);"
    )
    values = {
        name: value
        for name, value, _ in _options(
            _rules(parser, Family.IP, "nat", "POSTROUTING")[0]
        )
    }
    assert values["to-source"] == Multi(["1.2.3.4", "5.6.7.8"])


def test_negation_on_unsupported_keyword_errors() -> None:
    with pytest.raises(FermError, match="Doesn't support negation"):
        _parse("chain INPUT ! proto tcp ACCEPT;")


# -- sub-chains ------------------------------------------------------------


def test_subchain_creates_auto_chain_and_jump() -> None:
    parser = _parse("chain INPUT proto tcp @subchain { dport 22 ACCEPT; }")
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert "ferm_auto_1" in chains
    parent = _options(chains["INPUT"].rules[0])
    assert ("jump", "ferm_auto_1", OptionKind.TARGET) in parent
    sub = _options(chains["ferm_auto_1"].rules[0])
    assert ("dport", "22", OptionKind.OPTION) in sub


def test_named_subchain_uses_given_name() -> None:
    parser = _parse(
        'chain INPUT proto tcp @subchain "ssh" { dport 22 ACCEPT; }'
    )
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert "ssh" in chains


def test_named_subchain_registers_jump_and_body() -> None:
    # The parent rule jumps to the given name, and that name's chain holds the
    # body -- pins the quoted-name extraction and the per-table registration.
    parser = _parse(
        'chain INPUT proto tcp @subchain "mysub" { dport 22 ACCEPT; }'
    )
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert ("jump", "mysub", OptionKind.TARGET) in _options(
        chains["INPUT"].rules[0]
    )
    assert _options(chains["mysub"].rules[0]) == [
        ("protocol", "tcp", OptionKind.PROTO),
        ("dport", "22", OptionKind.OPTION),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]


def test_subchain_registers_in_the_rules_table() -> None:
    # The sub-chain must be created in the rule's own table, not "filter".
    parser = _parse(
        "table nat chain PREROUTING proto tcp "
        '@subchain "redir" { REDIRECT to-ports 8080; }'
    )
    nat_chains = parser.domains[Family.IP].tables["nat"].chains
    assert "redir" in nat_chains
    assert ("jump", "redir", OptionKind.TARGET) in _options(
        nat_chains["PREROUTING"].rules[0]
    )


def test_subchain_body_sees_chain_auto_var() -> None:
    # Inside the sub-chain, ``$CHAIN`` resolves to the sub-chain's own name
    # (the frame's auto["CHAIN"] is rebound on entry).
    parser = _parse(
        'chain INPUT proto tcp @subchain "mysub" '
        "{ mod comment comment $CHAIN ACCEPT; }"
    )
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert _comment(chains["mysub"].rules[0]) == "mysub"


def test_bareword_subchain_uses_value_as_name() -> None:
    # An unquoted sub-chain name is read as a value (getvar); the parent jumps
    # to it and the body lands in that chain -- pins the non-quoted branch.
    parser = _parse(
        "chain INPUT proto tcp @subchain vsub { dport 22 ACCEPT; }"
    )
    chains = parser.domains[Family.IP].tables["filter"].chains
    assert ("jump", "vsub", OptionKind.TARGET) in _options(
        chains["INPUT"].rules[0]
    )
    assert _options(chains["vsub"].rules[0]) == [
        ("protocol", "tcp", OptionKind.PROTO),
        ("dport", "22", OptionKind.OPTION),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]


def test_subchain_replays_into_each_table(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A sub-chain under a table array is registered once per table (the
    # per-table ``setdefault`` loop keyed by the table name); registering
    # under the wrong key re-creates it and warns "already exists".
    parser = _parse(
        "table (filter mangle) chain FORWARD proto tcp "
        '@subchain "s" { ACCEPT; }'
    )
    for table in ("filter", "mangle"):
        chains = parser.domains[Family.IP].tables[table].chains
        assert "s" in chains
        assert ("jump", "s", OptionKind.TARGET) in _options(
            chains["FORWARD"].rules[0]
        )
    assert "already exists" not in capsys.readouterr().err


def test_subchain_without_preceding_rule_names_keyword() -> None:
    # A sub-chain with no rule before it is rejected, and the message names
    # the sub-chain keyword (``subchain`` -> ``@subchain``).
    with pytest.raises(
        FermError, match="No rule specified before '@subchain'"
    ):
        _parse('chain INPUT @subchain "x" { ACCEPT; }')


def test_bare_subchain_keyword_normalised_in_error() -> None:
    # The bare ``subchain`` keyword is normalised to ``@subchain`` for
    # diagnostics via re.sub(r"^sub", "@sub", ...).
    with pytest.raises(
        FermError, match="No rule specified before '@subchain'"
    ):
        _parse('chain INPUT subchain "x" { ACCEPT; }')


def test_subchain_without_chain_is_rejected() -> None:
    with pytest.raises(FermError, match="Chain must be specified"):
        _parse('@subchain "x" { ACCEPT; }')


def test_subchain_requires_brace_after_keyword() -> None:
    with pytest.raises(FermError, match=r'"\{" or chain name expected'):
        _parse('chain INPUT proto tcp @subchain "x" y ACCEPT;')


# -- shortcuts and modules -------------------------------------------------


def test_comment_shortcut_loads_module() -> None:
    parser = _parse('chain INPUT comment "hi" ACCEPT;')
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert ("match", "comment", OptionKind.MATCH_MODULE) in options
    assert ("comment", "hi", OptionKind.OPTION) in options


def test_mod_loads_match_module() -> None:
    parser = _parse("chain INPUT mod conntrack ctstate ESTABLISHED ACCEPT;")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert ("match", "conntrack", OptionKind.MATCH_MODULE) in options
    assert ("ctstate", "ESTABLISHED", OptionKind.OPTION) in options


def test_shortcut_module_deduped_against_explicit_mod() -> None:
    # The shortcut records its match module in rule.match, so a later explicit
    # "mod multiport" is deduped: only one "match multiport" is emitted.
    parser = _parse("chain INPUT proto tcp dports (80) mod multiport ACCEPT;")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    matches = [
        opt
        for opt in options
        if opt == ("match", "multiport", OptionKind.MATCH_MODULE)
    ]
    assert len(matches) == 1


def test_address_magic_realizes_a_list() -> None:
    parser = _parse("chain INPUT saddr 1.2.3.4 ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, Family.IP, "filter", "INPUT")[0]
        )
    }
    assert options["source"] == "1.2.3.4"


def test_address_magic_internal_negation() -> None:
    parser = _parse("chain INPUT saddr ! 1.2.3.4 ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, Family.IP, "filter", "INPUT")[0]
        )
    }
    assert options["source"] == Negated(["1.2.3.4"])


def test_multiport_shortcut_chunks_ports() -> None:
    ports = " ".join(str(n) for n in range(1, 20))
    parser = _parse(f"chain INPUT proto tcp dports ({ports}) ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, Family.IP, "filter", "INPUT")[0]
        )
    }
    # 19 single ports split into chunks of <= 15 -> an array (unfolds).
    assert isinstance(options.get("destination-ports"), str)


def test_goto_action() -> None:
    parser = _parse("chain FORWARD; chain INPUT proto tcp goto FORWARD;")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert ("goto", "FORWARD", OptionKind.TARGET) in options


def test_nop_is_a_valid_action() -> None:
    # NOP satisfies the "no action defined" check (has_action) without
    # emitting a target option -- the rule keeps only its matches.
    parser = _parse("chain INPUT proto tcp NOP;")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert options == [("protocol", "tcp", OptionKind.PROTO)]


def test_protocol_long_form_keyword() -> None:
    # "protocol" is the long form of "proto"; both reach the same branch.
    parser = _parse("chain INPUT protocol tcp ACCEPT;")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert ("protocol", "tcp", OptionKind.PROTO) in options


def test_module_long_form_keyword() -> None:
    # "module" is the long form of "mod"; both load a match module.
    parser = _parse("chain INPUT module conntrack ctstate ESTABLISHED ACCEPT;")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert ("match", "conntrack", OptionKind.MATCH_MODULE) in options


def test_semicolon_carries_chain_context_to_next_rule() -> None:
    # After ";" the next rule is re-seeded from the block's prev frame, so it
    # inherits the chain; losing that seed would leave it with no chain.
    parser = _parse("chain INPUT { proto tcp ACCEPT; proto udp ACCEPT; }")
    rules = _rules(parser, Family.IP, "filter", "INPUT")
    assert len(rules) == 2
    assert _options(rules[1]) == [
        ("protocol", "udp", OptionKind.PROTO),
        ("jump", "ACCEPT", OptionKind.TARGET),
    ]


# -- @preserve -------------------------------------------------------------


def test_preserve_flags_a_chain() -> None:
    parser = _parse("chain INPUT @preserve;")
    chain = parser.domains[Family.IP].tables["filter"].chains["INPUT"]
    assert chain.preserve is True


def test_preserve_regex_records_a_pattern() -> None:
    # A regex chain is a quoted ``/.../`` token (the bare form cannot
    # tokenize, since ``^``/``$`` are not token characters); the oracle's
    # own preserve tests use quotes (``reference/test/preserve/regex.ferm``).
    parser = _parse('chain "/^ferm_/" @preserve;')
    table = parser.domains[Family.IP].tables["filter"]
    assert len(table.preserve_regexes) == 1
    assert "/^ferm_/" not in table.chains


def test_preserve_requires_fast_mode() -> None:
    options = Options(test=True, fast=False)
    with pytest.raises(FermError, match="not implemented for --slow"):
        _parse("chain INPUT @preserve;", options=options)


# -- deprecated keywords and hooks -----------------------------------------


def test_deprecated_realgoto_maps_to_goto() -> None:
    parser = _parse("chain FORWARD; chain INPUT proto tcp realgoto FORWARD;")
    options = _options(_rules(parser, Family.IP, "filter", "INPUT")[0])
    assert ("goto", "FORWARD", OptionKind.TARGET) in options


def test_hook_records_command() -> None:
    parser = _parse('@hook pre "echo before";')
    assert parser.pre_hooks == ["echo before"]
    assert parser.post_hooks == []


def test_bare_hook_warns_verbatim_and_still_runs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The wording is byte-parity with the oracle (Perl ``:2211``), NOT the
    # DEPRECATED_KEYWORDS "please use ... instead" template.
    parser = _parse('hook pre "echo x";')
    assert "'hook' is deprecated, use '@hook'" in capsys.readouterr().err
    assert parser.pre_hooks == ["echo x"]


def test_negated_bare_hook_reports_the_remapped_keyword() -> None:
    # The dispatcher remaps shown_keyword to '@hook', so the leftover
    # negation names the canonical form, as the oracle does.
    with pytest.raises(FermError, match="Doesn't support negation: @hook"):
        _parse('! hook pre "echo x";')


# -- error diagnostics -----------------------------------------------------


def test_missing_chain_errors() -> None:
    with pytest.raises(FermError, match="Chain must be specified"):
        _parse("proto tcp ACCEPT;")


def test_missing_action_errors() -> None:
    with pytest.raises(FermError, match="No action defined"):
        _parse("chain INPUT proto tcp;")


def test_missing_semicolon_at_eof_errors() -> None:
    with pytest.raises(FermError, match="Missing semicolon"):
        _parse("chain INPUT ACCEPT")


def test_unrecognized_keyword_errors() -> None:
    with pytest.raises(FermError, match="Unrecognized keyword"):
        _parse("chain INPUT florble ACCEPT;")


def test_leaf_actions_disjoint_from_target_namespaces() -> None:
    # The staged _LEAF_ACTIONS table sits above the core-target and
    # module-target predicates in handle(), lifting NOP/proto/protocol/
    # sport/dport over them; that reorder is equivalent only while the
    # key sets stay disjoint.
    assert not Parser._LEAF_ACTIONS.keys() & set(CORE_TARGETS)
    module_names = {name for family in TARGET_DEFS.values() for name in family}
    assert not Parser._LEAF_ACTIONS.keys() & module_names


def test_two_actions_error() -> None:
    with pytest.raises(FermError, match="only one action"):
        _parse("chain INPUT ACCEPT DROP;")


# -- command-grammar diagnostics -------------------------------------------
#
# The high-level command grammar (domain/table/chain conflicts, policy, hook,
# def, @preserve, TCPMSS) funnels through ``enter``/``_enter_body``; each of
# these error sinks was previously unpinned by any unit test.  One tiny source
# per sink, asserted by its located ``FermError`` message.

_GRAMMAR_DIAGNOSTICS = [
    # Note: "Cannot combine non-IP domains" (parser.py:331) is not surface
    # reachable -- the ``domain`` keyword replays a list value per item, so a
    # mixed-family list never reaches that branch of ``set_domain``; it is left
    # to the differential fuzzer rather than pinned here.
    pytest.param(
        "domain ip domain ip6 chain INPUT ACCEPT;",
        "Domain is already specified",
        id="domain-respecified",
    ),
    pytest.param(
        ";",
        'Empty rule before ";" not allowed',
        id="empty-rule",
    ),
    pytest.param(
        "chain INPUT ACCEPT; }",
        'Unmatched "}"',
        id="unmatched-brace",
    ),
    pytest.param(
        "chain INPUT proto tcp policy ACCEPT;",
        "Cannot specify matches for policy",
        id="policy-with-matches",
    ),
    pytest.param(
        "chain INPUT policy BOGUS;",
        "Invalid policy target",
        id="invalid-policy-target",
    ),
    pytest.param(
        'chain INPUT @hook pre "echo hi";',
        '"hook" must be the first token in a command',
        id="hook-not-first",
    ),
    pytest.param(
        '@hook bogus "echo hi";',
        "Invalid hook position",
        id="invalid-hook-position",
    ),
    pytest.param(
        "chain INPUT proto tcp def $x = 1;",
        '"def" must be the first token in a command',
        id="def-not-first",
    ),
    pytest.param(
        "def $ = 1;",
        "invalid variable name",
        id="invalid-variable-name",
    ),
    pytest.param(
        "def & = 1;",
        "invalid function name",
        id="invalid-function-name",
    ),
    pytest.param(
        "def foo = 1;",
        r'\(variable\) or "&" \(function\) expected',
        id="def-needs-sigil",
    ),
    pytest.param(
        "&nope();",
        "no such function",
        id="call-undefined-function",
    ),
    pytest.param(
        "@preserve;",
        "@preserve without chain",
        id="preserve-without-chain",
    ),
    pytest.param(
        "chain INPUT proto tcp @preserve;",
        "Cannot specify matches for @preserve",
        id="preserve-with-matches",
    ),
    pytest.param(
        "table mangle chain FORWARD TCPMSS set-mss 1400;",
        "No protocol specified before TCPMSS",
        id="tcpmss-without-proto",
    ),
    pytest.param(
        "table mangle chain FORWARD proto udp TCPMSS set-mss 1400;",
        'TCPMSS not available for protocol "udp"',
        id="tcpmss-wrong-proto",
    ),
    pytest.param(
        "chain INPUT proto icmp dport 22 ACCEPT;",
        "To use sport or dport",
        id="dport-without-port-proto",
    ),
]


@pytest.mark.parametrize(("source", "match"), _GRAMMAR_DIAGNOSTICS)
def test_grammar_diagnostic_raises(source: str, match: str) -> None:
    with pytest.raises(FermError, match=match):
        _parse(source)


def test_log_prefix_is_not_truncated() -> None:
    # The 29-char truncation lives only in ``parse_keyword``'s ``params == 1``
    # branch, but ``LOG``'s ``log-prefix`` takes the target default ``"s"`` and
    # so parses through the letter-code branch: the truncation is vestigial and
    # never fires (verified against the oracle).  The value is kept whole.
    long_prefix = "x" * 40
    parser = _parse(f'chain INPUT LOG log-prefix "{long_prefix}";')
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, Family.IP, "filter", "INPUT")[0]
        )
    }
    assert options["log-prefix"] == long_prefix


# -- collect_filenames -----------------------------------------------------


def test_collect_filenames_relative_to_parent(tmp_path: Path) -> None:
    included = tmp_path / "rules.ferm"
    included.write_text("", encoding="utf-8")
    parent = str(tmp_path / "main.ferm")
    assert collect_filenames(parent, ["rules.ferm"]) == [str(included)]


def test_collect_filenames_directory_sorts_and_filters(
    tmp_path: Path,
) -> None:
    (tmp_path / "b.ferm").write_text("", encoding="utf-8")
    (tmp_path / "a.ferm").write_text("", encoding="utf-8")
    (tmp_path / ".hidden").write_text("", encoding="utf-8")
    (tmp_path / "back~").write_text("", encoding="utf-8")
    parent = str(tmp_path / "main.ferm")
    result = collect_filenames(parent, [f"{tmp_path}/"])
    assert result == [str(tmp_path / "a.ferm"), str(tmp_path / "b.ferm")]


def test_include_pulls_in_another_file(tmp_path: Path) -> None:
    included = tmp_path / "sub.ferm"
    included.write_text("chain INPUT ACCEPT;\n", encoding="utf-8")
    main = tmp_path / "main.ferm"
    main.write_text(f'@include "{included}";\n', encoding="utf-8")

    options = Options(test=True)
    handle = main.open(encoding="utf-8")
    script = Script(filename=str(main), handle=handle)
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    evaluator = Evaluator(tokenizer, scope)
    parser = Parser(evaluator, {}, options)
    parser.enter(0, None)
    handle.close()

    rules = parser.domains[Family.IP].tables["filter"].chains["INPUT"].rules
    assert _options(rules[0]) == [("jump", "ACCEPT", OptionKind.TARGET)]


def _parse_file(main: Path, *, options: Options | None = None) -> Parser:
    """Parse a ferm file from disk (the @include tests' harness)."""
    options = options if options is not None else Options(test=True)
    handle = main.open(encoding="utf-8")
    script = Script(filename=str(main), handle=handle)
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    evaluator = Evaluator(tokenizer, scope)
    parser = Parser(evaluator, {}, options)
    # finally: like cli.main, close the whole include chain even when a
    # parse abort is the expected outcome (ResourceWarning is an error).
    try:
        parser.enter(0, None)
    finally:
        node: Script | None = tokenizer.script
        while node is not None:
            node.close()
            node = node.parent
    return parser


def test_include_pipe_parses_command_output(tmp_path: Path) -> None:
    main = tmp_path / "main.ferm"
    main.write_text(
        "@include \"echo 'chain INPUT ACCEPT;'|\";\n", encoding="utf-8"
    )
    parser = _parse_file(main)
    rules = parser.domains[Family.IP].tables["filter"].chains["INPUT"].rules
    assert _options(rules[0]) == [("jump", "ACCEPT", OptionKind.TARGET)]


def test_include_pipe_nonzero_exit_aborts(tmp_path: Path) -> None:
    # Perl checks ``close $script->{handle}`` and aborts (:2311) so a
    # generator that dies cannot install a truncated ruleset.
    main = tmp_path / "main.ferm"
    main.write_text(
        "@include \"echo 'chain INPUT ACCEPT;'; exit 3|\";\n", encoding="utf-8"
    )
    with pytest.raises(FermError, match="exit status is not 0"):
        _parse_file(main)


# -- enter depth limit (a sanctioned deviation) ----------------------------


def _nested(depth: int) -> str:
    """A config whose parse needs ``depth`` block frames past top level."""
    return (
        "table filter chain INPUT "
        + "proto tcp { " * depth
        + "ACCEPT;"
        + " }" * depth
    )


def test_enter_depth_at_limit_parses() -> None:
    # top-level enter is frame 1; each "{" adds one: MAX-1 braces fit
    parser = _parse(_nested(MAX_BLOCK_DEPTH - 1))
    assert parser._block_depth == 0


def test_enter_depth_over_limit_is_located_ferm_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(FermError, match=r"too many nested blocks \(max 100\)"):
        _parse(_nested(MAX_BLOCK_DEPTH))
    # error() located the diagnostic, no bare RecursionError traceback
    assert "Error in <test> line" in capsys.readouterr().err


def test_enter_depth_counter_recovers_after_error() -> None:
    script = Script(
        filename="<test>", handle=io.StringIO(_nested(MAX_BLOCK_DEPTH))
    )
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    parser = Parser(Evaluator(tokenizer, scope), {}, Options(test=True))
    with pytest.raises(FermError):
        parser.enter(0, None)
    # the finally chain unwound every frame
    assert parser._block_depth == 0


def test_enter_array_replay_does_not_reset_depth() -> None:
    # domain/table/chain arrays replay their block via enter(0, ...)
    # (_replay_array): a limit derived from ``level`` would restart from
    # zero inside each replay.  Each array level costs TWO frames (the
    # replay's enter(0, ...) plus the block's "{"), so the deepest path
    # here holds 1 + 3*2 + (MAX-3) = MAX+4 frames -- the counter must
    # overflow while the deepest ``level`` stays at MAX-2, below the
    # limit a level-derived guard would use.
    inner = (
        "proto tcp { " * (MAX_BLOCK_DEPTH - 3)
        + "ACCEPT;"
        + " }" * (MAX_BLOCK_DEPTH - 3)
    )
    source = (
        "domain (ip ip6) { table (filter nat) { chain (one two) { "
        + inner
        + " } } }"
    )
    with pytest.raises(FermError, match="too many nested blocks"):
        _parse(source)


def test_enter_sequential_replays_release_depth() -> None:
    # each array element replays the same block in sequence: without the
    # finally-decrement the second element would inherit the first's
    # depth.  The deepest path is 1 + 3*2 + inner braces, so MAX-7 inner
    # braces sit exactly at the limit -- legal once, overflowing if any
    # earlier replay leaked frames.
    inner = (
        "proto tcp { " * (MAX_BLOCK_DEPTH - 7)
        + "ACCEPT;"
        + " }" * (MAX_BLOCK_DEPTH - 7)
    )
    source = (
        "domain (ip ip6) { table (filter nat) { chain (one two) { "
        + inner
        + " } } }"
    )
    parser = _parse(source)
    assert parser._block_depth == 0


# -- mutation-hardening (killed mutmut survivors) --------------------------


def test_chain_name_too_long_message_text() -> None:
    """The over-long-chain diagnostic keeps its 'Chain name too long' text."""
    with pytest.raises(FermError, match=r"^Chain name too long, must be "):
        _parse(f"chain {'x' * 30} ACCEPT;")


def test_collect_filenames_skips_dpkg_but_keeps_later_file(
    tmp_path: Path,
) -> None:
    """A dpkg backup is 'continue'-skipped; a following real file survives."""
    (tmp_path / "a.dpkg-old").write_text("", encoding="utf-8")
    (tmp_path / "b.ferm").write_text("", encoding="utf-8")
    parent = str(tmp_path / "main.ferm")
    assert collect_filenames(parent, [f"{tmp_path}/"]) == [
        str(tmp_path / "b.ferm")
    ]


def test_collect_filenames_trailing_slash_non_directory_rejected(
    tmp_path: Path,
) -> None:
    """A trailing-slash include on a missing path is 'is not a directory'."""
    parent = str(tmp_path / "main.ferm")
    with pytest.raises(FermError, match="is not a directory"):
        collect_filenames(parent, [f"{tmp_path}/nope/"])


def test_collect_filenames_bare_directory_suggests_slash(
    tmp_path: Path,
) -> None:
    """A bare directory path suggests the trailing '/' form at text end."""
    subdir = tmp_path / "sub"
    subdir.mkdir()
    parent = str(tmp_path / "main.ferm")
    with pytest.raises(FermError, match=r"to include a directory\?$"):
        collect_filenames(parent, [str(subdir)])


def test_collect_filenames_non_file_rejected(tmp_path: Path) -> None:
    """A plain path that is not a regular file is 'is not a file'."""
    parent = str(tmp_path / "main.ferm")
    with pytest.raises(FermError, match="is not a file"):
        collect_filenames(parent, [str(tmp_path / "missing")])


def test_ipv6_base_match_keyword_recognized() -> None:
    """ip6 folds to the 'ip' family so base match keywords like saddr parse."""
    parser = _parse("domain ip6 { chain INPUT saddr ::1 ACCEPT; }")
    rules = _rules(parser, Family.IP6, "filter", "INPUT")
    assert ("source", "::1", OptionKind.OPTION) in _options(rules[0])


def test_domain_filter_flat_form_skips_rest_of_statement() -> None:
    """A --domain-filtered flat ``domain`` drops the whole statement."""
    parser = _parse(
        "domain ip6 chain INPUT ACCEPT;",
        options=Options(test=True, domain="ip"),
    )
    assert not any(
        chain.rules
        for domain in parser.domains.values()
        for table in domain.tables.values()
        for chain in table.chains.values()
    )


def test_gotosubchain_emits_goto_target() -> None:
    """@gotosubchain routes via 'goto' (keyword startswith '@go')."""
    parser = _parse('chain INPUT proto tcp @gotosubchain "foo" { ACCEPT; }')
    rules = _rules(parser, Family.IP, "filter", "INPUT")
    assert ("goto", "foo", OptionKind.TARGET) in _options(rules[0])


def test_new_subchain_name_does_not_warn(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A first-seen sub-chain is created silently (``subchain in chains`` is
    False), with no 'already exists' warning."""
    _parse('chain INPUT proto tcp @subchain "fresh" { ACCEPT; }')
    assert "already exists" not in capsys.readouterr().err


def test_duplicate_subchain_name_warns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A second sub-chain of the same name warns 'already exists'."""
    _parse(
        'chain INPUT { proto tcp @subchain "dup" { ACCEPT; } '
        'proto udp @subchain "dup" { DROP; } }'
    )
    assert "Chain dup already exists" in capsys.readouterr().err


def test_function_multi_token_arg_realigns_later_param() -> None:
    """A multi-token array arg is parenthesised (``len(tokens) != 1``) before
    splicing so ``dport`` sees ``(22 80)`` and a later ``$b`` still binds."""
    parser = _parse(
        "@def &two($a, $b) = proto tcp dport $a sport $b ACCEPT;"
        "chain INPUT &two((22 80), 53);"
    )
    pairs = {
        (
            {o.name: o.value for o in rule.options}.get("dport"),
            {o.name: o.value for o in rule.options}.get("sport"),
        )
        for rule in _rules(parser, Family.IP, "filter", "INPUT")
    }
    assert pairs == {("22", "53"), ("80", "53")}


def test_def_two_param_function_accepts_comma_separator() -> None:
    """A ',' between params is required (``token != ','`` guard) to parse."""
    parser = _parse(
        "@def &two($a, $b) = proto tcp dport $a sport $b ACCEPT;"
        "chain INPUT &two(22, 53);"
    )
    options = {
        o.name: o.value
        for o in _rules(parser, Family.IP, "filter", "INPUT")[0].options
    }
    assert options["dport"] == "22"
    assert options["sport"] == "53"
