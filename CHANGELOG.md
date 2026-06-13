# Changelog

All notable changes to the **Python port** of ferm are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

For the history of the original Perl implementation (versions up to and
including `v2.8`), see [`reference/NEWS`](reference/NEWS).

## [Unreleased]

The Python port (`src/pyferm/`). Phase 1 reproduces the Perl
implementation's behaviour and emits `iptables` rulesets; its output is
validated byte-for-byte against the Perl oracle kept in `reference/`.

### Added

- **Configuration language front end** ported from Perl: tokenizer and
  lazy token stream, the recursive-descent `enter()` parser over blocks,
  scopes and keywords, copy-on-write variable/function/array scoping, and
  deferred value realization (`@resolve()`, `@ipfilter()` and friends
  expand late).
- **Module-definition registry** and the compact option-encoding DSL
  (`add_proto_def` / `add_match_def` / `add_target_def` equivalents), so
  supported netfilter modules carry over from the Perl tables.
- **Rule assembly** — rule structure, unfolding into the cartesian product
  of option lists, `format_option` and byte-faithful `shell_escape`.
- **Per-family domains and the frozen `Options` model**, with the
  domains → backend injection seam.
- **iptables backend** with both execution paths: `--fast` (build a save
  file and pipe it to `iptables-restore`, atomic) and `--slow` (one
  `iptables` call per rule), plus `--shell` script emission.
- **CLI and top-level flow**, including `--noexec`, `--lines`,
  `--interactive` rollback with confirmation timeout, and the
  `ip` / `ip6` / `arp` / `eb` families.
- **`import-ferm`** — converts an `iptables-save` dump into a ferm
  configuration (save → ferm → save round-trip).
- **`@resolve` name resolver** backed by `dnspython`.

### Testing & tooling

- **Golden-file test harness** validated against the Perl oracle, with
  canonicalisation of the non-deterministic table/chain output order.
- **Differential fuzzing against the Perl oracle** (Hypothesis):
  tokenizer, `shell_escape`, import lexing, backtick splitting, `@substr`,
  option tokens, previous-state reader, and whole grammar-generated
  configs — driving fixes for `\s` Unicode handling (`re.ASCII`), Perl
  numification, the `substr`/undef model and byte-faithful save-dump
  regexes.
- **Real-world config corpus** compiled against the oracle (fast + slow).
- **`atheris` crash fuzzing** of both parsers and a **containerised
  anti-lockout e2e** for `--interactive` (both opt-in), plus a periodic
  **`mutmut` mutation** session.
- **Diagnostics parity** goldens pinning stderr for negative / params /
  warning cases.
- **Byte-faithful I/O**: config, backtick, zonefile and `--def` (`argv`)
  input read as latin-1 bytes and carried across the CLI, restore and
  `import-ferm` boundaries.
- **`MAX_BLOCK_DEPTH`** bound on parser block nesting and **`MAX_VALUE_DEPTH`**
  bound on value-reader nesting, both failing with a located diagnostic
  instead of a stack overflow.

### Project infrastructure

- Python project scaffolded at the repo root (`uv` + `src-layout`,
  `hatchling`), declaring support for Python **3.11–3.14**.
- The original Perl implementation relocated to `reference/` as the
  semantic oracle.
- `nox`-orchestrated gates (lint, tests, typecheck, coverage floor,
  matrix, fuzz, build, deps-lowest, workflow lint) wired into a binding
  `preflight` and into GitHub Actions CI (static checks split out, patch
  gate on PRs, weekly audit + Dependabot).

[Unreleased]: https://github.com/6RUN0/ferm/tree/develop
