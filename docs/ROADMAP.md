# ferm roadmap

This is the high-level roadmap for evolving ferm from the original Perl
program into a Python implementation with a native `nftables` backend. It
summarises the strategy and phase breakdown.

**Current status:** Phase 1 (faithful Perl → Python port, still emitting
`iptables`) is complete. See [`CHANGELOG.md`](../CHANGELOG.md).

## Guiding principle: one variable per phase

Each phase changes exactly one thing, so regressions stay attributable and
the Perl oracle in `reference/` can keep guarding behaviour:

- **Phase 1** changes only the *language* (Perl → Python; output stays
  iptables).
- **Phase 2** changes only the *output target* (iptables → native nft).
- **Phase 3** changes only the *packaging*.

## North star — invariants that must not be lost

These are why ferm is chosen over ufw / firewalld, and they migrate
verbatim. Eroding any of them is a regression, not progress:

- **An expressive DSL** — variables, functions, nested blocks. This is
  ferm's core (`enter()` evaluator with copy-on-write scopes); it ports
  1:1 and is guarded by golden tests.
- **Completeness** — essentially everything iptables can express (~99.99%
  of the module vocabulary). Completeness is what distinguishes ferm from
  the "simple" wrappers; this is why the nft backend will translate to
  *native* nft expressions rather than ride the `iptables-nft` compat
  layer.
- **Declarative + atomic application** — no imperative up/down shell
  scripts. The port preserves atomic application (`execute_fast` today → a
  future `flush table inet ferm`).

## Phases

### Phase 0 — Scaffolding & restructuring ✅

Relocate the Perl code to `reference/` (history preserved; it stays the
semantic oracle) and stand up the Python project at the repo root:
`src/pyferm/`, `tests/`, `pyproject.toml`, `noxfile.py`, `pre-commit`.
Toolchain: `uv`, `nox`, `ruff`, `mypy`/`pyright`, `pytest`, `hatchling`
src-layout, two console scripts (`ferm`, `import-ferm`).

### Phase 1 — Faithful Perl → Python port (output stays iptables) ✅

Port both `ferm` and `import-ferm`, preserving behaviour. Key
architectural seam: the final option formatting moves out of the core into
a `Backend` interface (`render` / `commit` / `rollback` /
`capture_previous`), so the core hands the backend a structured rule
`(name, values, kind, module)` + family. The `iptables` backend formats
it; in Phase 2 an `nft.py` adapter sits over the same seam without
touching the core. Five sanctioned deviations from a literal 1:1 port are
documented and none change default behaviour (so golden tests stay green).

### Phase 2 — Native nft backend

Translate the structured rule into **native nft expressions** (not
`iptables-nft` compat), preserving the full module vocabulary, atomic
application, `@preserve` and rollback. The entry debt from Phase 1 review
(dead `read_previous` seam, eb snapshot behind the backend, parser-depth
limit, latin-1 decoding policy) is paid down first — completed. Open
questions: nft text vs. JSON libnftables as the generation format; the
`@preserve` strategy over nft.

### Phase 3 — Binary packaging (optional)

Optionally ship a self-contained binary (Nuitka). Order-independent: can
land any time after Phase 1.

### Phase 4 — Operational safety (diff/apply engine)

Depends on Phase 2 (native nft: handles + atomic transactions). A
`commit` strategy that computes and applies a delta rather than a full
flush-replace, plus richer config history/backup. A cheap seed
(`--backup-dir`) was pulled forward into Phase 1.

### Phase 5 — nft-native expressiveness

Depends on Phase 2 — the payoff for going native: sets, maps, intervals,
concatenations, native `reject-with`, and the performance wins on
router/NAT boxes.

### Phase 6 — Standard rule library (ready-made patterns)

An includable `.ferm` macro library with a search path (e.g.
`@forward_port`, `@masquerade`); richer recipes (`@block_country`,
`@detect_ssh_brute`, `@allow_icmpv6_essentials`) build on the Phase 5
primitives. A basic version is possible on ferm functions right after
Phase 1.

### Phase 7 — Tooling / DX (static analysis on the AST)

Depends on Phase 1 as the fidelity oracle. AST refactor of the parser
first (today's port is a streaming interpreter), then post-port
golden-guarded simplifications, a richer linter / `--check`,
`--list-modules` / `--describe`, and visualisation. Cheap seeds were
pulled into Phase 1.

### Phase 8 — Ecosystem & alternative front end

Depends on the clean model from Phase 1 (and Phase 2 for import). A
programmable Python-config front end (classes, inheritance, composition)
alongside the DSL — a different audience from the Phase 7 AST tools, not a
replacement — gated behind a mandatory security review (it executes user
code).

## Cross-cutting: IPv6

IPv6 support improves *across* phases rather than as one block: Phase 1
preserves family-dependent formatting verbatim (oracle: `test/ipv6/`),
Phase 5 adds native expressiveness, and Phase 6 adds anti-lockout
helpers. There is deliberately no standalone "IPv6 phase".
