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
from pyferm.errors import FermError
from pyferm.functions import Evaluator
from pyferm.parser import MAX_BLOCK_DEPTH, Parser, collect_filenames
from pyferm.scope import Frame, Scope
from pyferm.tokenizer import Script, Tokenizer
from pyferm.values import Negated

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
    parser: Parser, domain: str, table: str, chain: str
) -> list[RenderedRule]:
    """Return the unfolded rules of one chain."""
    return parser.domains[domain].tables[table].chains[chain].rules


def _options(rule: RenderedRule) -> list[tuple[str, object, str]]:
    """Return a rule's options as ``(name, value, kind)`` tuples."""
    return [(opt.name, opt.value, opt.kind) for opt in rule.options]


# -- basic rules -----------------------------------------------------------


def test_basic_rule_records_options_and_kinds() -> None:
    parser = _parse("chain INPUT proto tcp dport 22 ACCEPT;")
    rules = _rules(parser, "ip", "filter", "INPUT")
    assert len(rules) == 1
    assert _options(rules[0]) == [
        ("protocol", "tcp", "proto"),
        ("dport", "22", "option"),
        ("jump", "ACCEPT", "target"),
    ]
    assert parser.domains["ip"].enabled


def test_suboptions_record_their_introducing_module() -> None:
    # The contract field Option.module links a sub-option to the module
    # whose merge_keywords introduced its keyword (design, sanctioned
    # deviation #2); the match/jump elements themselves carry no module.
    parser = _parse("chain INPUT mod state state NEW ACCEPT;")
    options = _rules(parser, "ip", "filter", "INPUT")[0].options
    assert [(o.name, o.kind, o.module) for o in options] == [
        ("match", "match_module", None),
        ("state", "option", "state"),
        ("jump", "target", None),
    ]


def test_target_module_suboptions_record_module() -> None:
    parser = _parse("table nat chain PREROUTING proto tcp DNAT to '10.0.0.1';")
    options = _rules(parser, "ip", "nat", "PREROUTING")[0].options
    assert ("to-destination", "DNAT") in [(o.name, o.module) for o in options]


def test_shortcut_suboptions_record_module() -> None:
    # the 'dports' shortcut implies 'mod multiport' and then its sub-option
    parser = _parse("chain INPUT proto tcp dports (22 80) ACCEPT;")
    options = _rules(parser, "ip", "filter", "INPUT")[0].options
    assert [(o.name, o.module) for o in options] == [
        ("protocol", None),
        ("match", None),
        ("destination-ports", "multiport"),
        ("jump", None),
    ]


def test_chain_defaults_to_ip_filter() -> None:
    parser = _parse("chain OUTPUT ACCEPT;")
    assert "filter" in parser.domains["ip"].tables
    assert _options(_rules(parser, "ip", "filter", "OUTPUT")[0]) == [
        ("jump", "ACCEPT", "target")
    ]


def test_explicit_table_is_used() -> None:
    parser = _parse("table nat chain POSTROUTING MASQUERADE;")
    rules = _rules(parser, "ip", "nat", "POSTROUTING")
    assert _options(rules[0]) == [("jump", "MASQUERADE", "target")]


def test_policy_sets_chain_policy_without_a_rule() -> None:
    parser = _parse("chain INPUT policy DROP;")
    chain = parser.domains["ip"].tables["filter"].chains["INPUT"]
    assert chain.policy == "DROP"
    assert chain.rules == []
    assert parser.domains["ip"].enabled


# -- domain handling -------------------------------------------------------


def test_domain_block_targets_one_family() -> None:
    parser = _parse("domain ip6 { chain INPUT proto tcp ACCEPT; }")
    assert "ip" not in parser.domains or not parser.domains["ip"].enabled
    rules = _rules(parser, "ip6", "filter", "INPUT")
    assert _options(rules[0])[0] == ("protocol", "tcp", "proto")


def test_dual_stack_domain_replays_for_each_family() -> None:
    parser = _parse("domain (ip ip6) { chain INPUT ACCEPT; }")
    for family in ("ip", "ip6"):
        rules = _rules(parser, family, "filter", "INPUT")
        assert _options(rules[0]) == [("jump", "ACCEPT", "target")]


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
        rules = _rules(parser, "ip", "filter", chain)
        assert _options(rules[0]) == [("jump", "ACCEPT", "target")]


def test_table_array_replays_per_table() -> None:
    parser = _parse("table (filter mangle) chain FORWARD ACCEPT;")
    for table in ("filter", "mangle"):
        rules = _rules(parser, "ip", table, "FORWARD")
        assert _options(rules[0]) == [("jump", "ACCEPT", "target")]


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
    assert len(_rules(parser, "ip", "filter", name)) == 1


# -- variables and functions ----------------------------------------------


def test_variable_expansion() -> None:
    parser = _parse("@def $p = 22; chain INPUT proto tcp dport $p ACCEPT;")
    rules = _rules(parser, "ip", "filter", "INPUT")
    assert ("dport", "22", "option") in _options(rules[0])


def test_function_body_is_spliced_into_the_stream() -> None:
    parser = _parse(
        "@def &allow($port) = proto tcp dport $port ACCEPT;"
        "chain INPUT &allow(22);"
    )
    rules = _rules(parser, "ip", "filter", "INPUT")
    assert _options(rules[0]) == [
        ("protocol", "tcp", "proto"),
        ("dport", "22", "option"),
        ("jump", "ACCEPT", "target"),
    ]


def test_function_wrong_arity_errors() -> None:
    with pytest.raises(FermError, match="Wrong number of parameters"):
        _parse("@def &f($a) = ACCEPT; chain INPUT &f(1, 2);")


# -- conditionals ----------------------------------------------------------


def test_if_true_keeps_body() -> None:
    parser = _parse("@if 1 { chain INPUT ACCEPT; }")
    assert _rules(parser, "ip", "filter", "INPUT")


def test_if_false_with_else_takes_else() -> None:
    parser = _parse(
        "@if 0 { chain INPUT ACCEPT; } @else { chain OUTPUT DROP; }"
    )
    chains = parser.domains["ip"].tables["filter"].chains
    assert "INPUT" not in chains
    assert _options(chains["OUTPUT"].rules[0]) == [("jump", "DROP", "target")]


def test_if_false_without_else_drops_body() -> None:
    parser = _parse("@if 0 { chain INPUT ACCEPT; }")
    tables = parser.domains.get("ip")
    assert tables is None or "filter" not in tables.tables


# -- negation --------------------------------------------------------------


def test_value_negation_wraps_the_value() -> None:
    parser = _parse("chain INPUT proto tcp dport ! 22 ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, "ip", "filter", "INPUT")[0]
        )
    }
    assert options["dport"] == Negated("22")


def test_proto_negation_is_not_a_module_merge() -> None:
    parser = _parse("chain INPUT proto ! tcp ACCEPT;")
    rule = _rules(parser, "ip", "filter", "INPUT")[0]
    name, value, kind = _options(rule)[0]
    assert (name, kind) == ("protocol", "proto")
    assert value == Negated("tcp")


def test_negation_on_unsupported_keyword_errors() -> None:
    with pytest.raises(FermError, match="Doesn't support negation"):
        _parse("chain INPUT ! proto tcp ACCEPT;")


# -- sub-chains ------------------------------------------------------------


def test_subchain_creates_auto_chain_and_jump() -> None:
    parser = _parse("chain INPUT proto tcp @subchain { dport 22 ACCEPT; }")
    chains = parser.domains["ip"].tables["filter"].chains
    assert "ferm_auto_1" in chains
    parent = _options(chains["INPUT"].rules[0])
    assert ("jump", "ferm_auto_1", "target") in parent
    sub = _options(chains["ferm_auto_1"].rules[0])
    assert ("dport", "22", "option") in sub


def test_named_subchain_uses_given_name() -> None:
    parser = _parse(
        'chain INPUT proto tcp @subchain "ssh" { dport 22 ACCEPT; }'
    )
    chains = parser.domains["ip"].tables["filter"].chains
    assert "ssh" in chains


# -- shortcuts and modules -------------------------------------------------


def test_comment_shortcut_loads_module() -> None:
    parser = _parse('chain INPUT comment "hi" ACCEPT;')
    options = _options(_rules(parser, "ip", "filter", "INPUT")[0])
    assert ("match", "comment", "match_module") in options
    assert ("comment", "hi", "option") in options


def test_mod_loads_match_module() -> None:
    parser = _parse("chain INPUT mod conntrack ctstate ESTABLISHED ACCEPT;")
    options = _options(_rules(parser, "ip", "filter", "INPUT")[0])
    assert ("match", "conntrack", "match_module") in options
    assert ("ctstate", "ESTABLISHED", "option") in options


def test_address_magic_realizes_a_list() -> None:
    parser = _parse("chain INPUT saddr 1.2.3.4 ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, "ip", "filter", "INPUT")[0]
        )
    }
    assert options["source"] == "1.2.3.4"


def test_address_magic_internal_negation() -> None:
    parser = _parse("chain INPUT saddr ! 1.2.3.4 ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, "ip", "filter", "INPUT")[0]
        )
    }
    assert options["source"] == Negated(["1.2.3.4"])


def test_multiport_shortcut_chunks_ports() -> None:
    ports = " ".join(str(n) for n in range(1, 20))
    parser = _parse(f"chain INPUT proto tcp dports ({ports}) ACCEPT;")
    options = {
        name: value
        for name, value, _ in _options(
            _rules(parser, "ip", "filter", "INPUT")[0]
        )
    }
    # 19 single ports split into chunks of <= 15 -> an array (unfolds).
    assert isinstance(options.get("destination-ports"), str)


def test_goto_action() -> None:
    parser = _parse("chain FORWARD; chain INPUT proto tcp goto FORWARD;")
    options = _options(_rules(parser, "ip", "filter", "INPUT")[0])
    assert ("goto", "FORWARD", "target") in options


# -- @preserve -------------------------------------------------------------


def test_preserve_flags_a_chain() -> None:
    parser = _parse("chain INPUT @preserve;")
    chain = parser.domains["ip"].tables["filter"].chains["INPUT"]
    assert chain.preserve is True


def test_preserve_regex_records_a_pattern() -> None:
    # A regex chain is a quoted ``/.../`` token (the bare form cannot
    # tokenize, since ``^``/``$`` are not token characters); the oracle's
    # own preserve tests use quotes (``reference/test/preserve/regex.ferm``).
    parser = _parse('chain "/^ferm_/" @preserve;')
    table = parser.domains["ip"].tables["filter"]
    assert len(table.preserve_regexes) == 1
    assert "/^ferm_/" not in table.chains


def test_preserve_requires_fast_mode() -> None:
    options = Options(test=True, fast=False)
    with pytest.raises(FermError, match="not implemented for --slow"):
        _parse("chain INPUT @preserve;", options=options)


# -- deprecated keywords and hooks -----------------------------------------


def test_deprecated_realgoto_maps_to_goto() -> None:
    parser = _parse("chain FORWARD; chain INPUT proto tcp realgoto FORWARD;")
    options = _options(_rules(parser, "ip", "filter", "INPUT")[0])
    assert ("goto", "FORWARD", "target") in options


def test_hook_records_command() -> None:
    parser = _parse('@hook pre "echo before";')
    assert parser.pre_hooks == ["echo before"]
    assert parser.post_hooks == []


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


def test_two_actions_error() -> None:
    with pytest.raises(FermError, match="only one action"):
        _parse("chain INPUT ACCEPT DROP;")


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
            _rules(parser, "ip", "filter", "INPUT")[0]
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

    rules = parser.domains["ip"].tables["filter"].chains["INPUT"].rules
    assert _options(rules[0]) == [("jump", "ACCEPT", "target")]


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
    rules = parser.domains["ip"].tables["filter"].chains["INPUT"].rules
    assert _options(rules[0]) == [("jump", "ACCEPT", "target")]


def test_include_pipe_nonzero_exit_aborts(tmp_path: Path) -> None:
    # Perl checks ``close $script->{handle}`` and aborts (:2311) so a
    # generator that dies cannot install a truncated ruleset.
    main = tmp_path / "main.ferm"
    main.write_text(
        "@include \"echo 'chain INPUT ACCEPT;'; exit 3|\";\n", encoding="utf-8"
    )
    with pytest.raises(FermError, match="exit status is not 0"):
        _parse_file(main)


# -- enter depth limit (sanctioned deviation #6) ----------------------------


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
    assert parser._block_depth == 0  # noqa: SLF001 -- counter under test


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
    assert parser._block_depth == 0  # noqa: SLF001 -- counter under test


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
    assert parser._block_depth == 0  # noqa: SLF001 -- counter under test
