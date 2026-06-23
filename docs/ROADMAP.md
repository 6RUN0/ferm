# ferm roadmap

This is the high-level roadmap for evolving ferm from the original Perl
program into a Python implementation with a native `nftables` backend. It
summarises the strategy and phase breakdown.

**Current status:** Phase 1 (faithful Perl → Python port, still emitting
`iptables`) is complete. Phase 2 (native `nft` backend behind `--nft`) is
available but **opt-in / experimental** — functional and adversarially
reviewed, but without a Perl-oracle differential test and with the
documented DROP-policy and `@preserve` differences. The default backend
stays `iptables`. See [`CHANGELOG.md`](../CHANGELOG.md).

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

### Phase 2 — Native nft backend ✅

Translate the structured rule into **native nft expressions** (not
`iptables-nft` compat), preserving the full module vocabulary and atomic
application. The entry debt from Phase 1 review (dead `read_previous`
seam, eb snapshot behind the backend, parser-depth limit, latin-1
decoding policy) was paid down first.

Resolved decisions and their consequences:

- **Generation format: nft text, not JSON.** The backend emits the nft
  *text* wire and applies it atomically via `nft -f -`, with no
  dependency on nft's JSON / `libjansson` build. Text is chosen as the
  *portable floor*: it works on any `nft`, which matters for the Phase 3
  static binary calling whatever `nft` the user has — JSON support, while
  near-universal in distro builds, is a build-time option that some builds
  (e.g. Gentoo with the `json` USE flag off) ship without. A
  runtime-detected JSON pipe (`nft -j -f -`) with a text fallback is
  deferred to Phase 4/5, not ruled out. `--nft` is strictly opt-in; the
  default stays `iptables`.
- **DROP-policy semantic shift under the own-table model.** The backend
  owns a single `table <family> ferm` and does not take over the
  monolithic kernel `INPUT` / `FORWARD` / `OUTPUT` chains. ferm's base
  chains coexist with other tables' base chains on the same hook (ordered
  by priority), so a packet may be accepted by a higher-priority foreign
  chain before reaching ferm's chain; a `policy DROP` in `table ip ferm`
  therefore behaves differently from iptables' monolithic `INPUT DROP`.
  This is the documented, expected behaviour of the own-table model.
  Admins who need the exact monolithic-DROP semantics stay on the default
  `iptables` backend.
- **`@preserve` is not supported under `--nft`** — using it is a clean,
  explicit error, a deliberate opt-in-backend regression. The default
  `iptables` backend keeps `@preserve` unchanged.
- **Port-bearing NAT requires a transport match** — `DNAT`/`SNAT` to an
  `addr:port`, or `REDIRECT`/`MASQUERADE to-ports`, without a preceding
  `proto tcp`/`udp` is a clean translate-time error, since nft rejects the
  mapping at apply.

A post-merge adversarial review (3 cycles) closed the remaining gaps: the
protocol operand is now validated like every other sink (it was the last
fail-open injection), `--nft --interactive --shell` emits a real
anti-lockout snapshot/restore, a failed rollback snapshot aborts instead
of deleting an existing table, and golden coverage gained negation,
dual-stack and port-NAT cases. `--nft` stays opt-in/experimental: it has
no Perl-oracle differential test (only the golden + `nft -c` harness), and
the DROP-policy shift and `@preserve` regression above are by design — the
default `iptables` backend is unchanged.

### Phase 3 — Binary packaging (optional)

Optionally ship a self-contained binary (Nuitka). Order-independent: can
land any time after Phase 1.

Three release artifacts now ship from one source and one git-tag version
(`hatch-vcs`, scoped to the port's `py-v<PEP440>` tags): the standalone
Nuitka binary, a **PyPI wheel + sdist** (`uv build`/`uv publish` via Trusted
Publishing, no token secrets), and a **native `.deb`** (`debhelper`/
`dh-python`, drop-in over the upstream Perl `ferm` via
`Provides/Conflicts/Replaces`). The `.deb` ships a starter `/etc/ferm/ferm.conf`
and a systemd unit that is **not** enabled on install (anti-lockout); the
admin opts in with `systemctl enable --now ferm`. Build-provenance
attestation covers all three.

#### Deferred packaging debt

The following items are explicitly **out of Phase 3 scope** and recorded
here so they are not lost.

**YAGNI deferrals** (low-demand or easily addable later):

- *One-file binary* — a single-file bundle (e.g. `--onefile` Nuitka mode)
  rather than the extracted `*.dist/` directory layout.
- *aarch64 wheel/binary* — the build driver is parametrised by `--arch` for
  the artifact name, but a real aarch64 leg is more than a matrix row: the
  driver currently hard-fails on any non-`x86_64` arch, and the build image
  is digest-pinned to `manylinux_2_28_x86_64`. It needs an aarch64 base image
  (own digest), a `--platform`/QEMU or native arm runner, and lifting the
  arch guard.
- *musl / fully-static builds* — for Alpine-style or completely glibc-free
  environments.
- *Slim variant without dnspython* — a smaller binary that drops the
  optional DNS resolver dependency for users who never use `@resolve()`.
- *Alternative bundlers* (PyInstaller, staticx) — Nuitka is the chosen
  tool; alternatives are not blocked, just not prioritised.
- *GPG / Sigstore signing with maintainer keys* — build-provenance
  attestation (SLSA via GitHub Actions) already ships in Phase 3; keyring
  signing is a separate, deferred step.
- *man page from POD* — the POD source exists only for the Perl version;
  the `.deb`'s unit points `Documentation=man:ferm(1)` forward to a man page
  not yet generated for the port.
- *Own apt repository* (reprepro/aptly) — the `.deb` ships as a GitHub
  Release asset; a signed apt repo is a separate distribution-lifecycle step.

**CVE-rebuild of bundled native libraries (debt with an automatable
trigger):**

`pip-audit` covers only Python-layer dependencies. It does *not* scan the
native shared objects frozen into the distribution — the OpenSSL, zlib,
libffi, and libexpat copies pulled in by the stdlib `ssl` module and
parsers. The OpenSSL bundled by the `manylinux_2_28` build base image is
the **1.1.x series, which is end-of-life upstream**, making an automatable
CVE-rebuild trigger especially important.

To give the recall mechanism an automatable trigger rather than relying on
manual advisory-feed monitoring: add a weekly image scan (e.g. `trivy
image` or `grype`) of the pinned `@sha256:` build/dist image to `audit.yml`
or a dedicated cron workflow. Such a scan alerts on CVEs in the native
libraries specifically; the `.so` versions recorded in the build manifest
give precise inputs for cross-referencing. On a hit: bump the image
`@sha256:` pin and re-release (yank and re-release the affected artifact).
This is the "full distribution lifecycle" owner's ongoing debt.

**Runtime guard of dist directory permissions (optional, deferred):**

The installation README instructs users to unpack the binary into a
root-owned, non-world-writable directory. That instruction is necessary but
user-dependent. A lightweight guard in `packaging/entry.py` — checking that
the `*.dist/` directory is root-owned and not world- or group-writable
before loading sibling shared objects — is possible and does not conflict
with the Phase 3 invariant (`entry.py` lives in `packaging/`, not in
`src/pyferm/`). It is deliberately deferred because it catches a
world-writable dist directory but not a shared object that has already been
planted there (a time-of-check / time-of-use gap). Recorded as "possible
and deferred", not "impossible".

**Exact-vs-normalized `.so` allow-list (minor residual):**

The allow-list normalizes a SONAME's minor version (`libssl.so.1.1` →
`libssl.so.1`), so a hypothetical `libssl.so.1.0` would still pass the gate.
This is mitigated today by the digest-pinned build image (the exact `.so`
set is fixed by the image), so it is recorded as a residual to tighten if
the normalization ever outlives the digest pin, not an open hole.

### Phase 4 — Operational safety (diff/apply engine)

Depends on Phase 2 (native nft: handles + atomic transactions). A
`commit` strategy that computes and applies a delta rather than a full
flush-replace, plus richer config history/backup. A cheap seed
(`--backup-dir`) was pulled forward into Phase 1.

### Phase 5 — nft-native expressiveness

Depends on Phase 2 — the payoff for going native: sets, maps, intervals,
concatenations, native `reject-with`, and the performance wins on
router/NAT boxes.

The first slice — **anonymous-set collapse** under `--nft` — is implemented
on the `python-port` branch (not yet released): adjacent leaf rules that
differ in exactly one set-eligible value fold into a single rule carrying an
anonymous set (`tcp dport { 22, 80, 443 }`), and `ferm --plan --nft` is honest
about the folded form. Negated matches and per-rule-distinct statements stay
linear (safe-bias); the `iptables` backend and the ferm core are untouched.

The second slice — **named sets** (`@set` / `SetRef`) — is also implemented on
`python-port` (not yet released): a ferm `@set` definition emits a native
`add set` / `add element` declaration, references translate to an `@name`
operand, and `ferm --plan --nft` parses kernel-side `add set` / `add element`
blocks so set additions, element-set changes, and removals each surface as a
`SetChange`. Names and elements are validated at the emit border (fail-closed);
the `iptables` backend keeps expanding the values inline at parse time, so a
named set is a no-op there.

The third slice — **interval sets** under `--nft` — is also implemented on
`python-port` (not yet released): a set element written as an address range
(`10.0.0.0-10.0.0.255`, IPv6 ranges) or a CIDR prefix marks the set
`flags interval`, alongside the numeric port ranges (`1024-2048`) already
supported. Because the kernel rewrites elements on readback (a prefix-aligned
range collapses to a CIDR, host bits are masked, a `/32`-`/128` host drops its
prefix), the plan diff canonicalizes both sides to that stored form, so a
`ferm --plan --nft` over an unchanged interval set converges rather than
showing a phantom diff. nft rejects overlapping intervals at apply time
(`nft -c`), so overlap detection stays the kernel's job (fail-closed).

The fourth slice — **native `reject-with`** under `--nft` — is also
implemented on `python-port` (not yet released): every `reject-with` value
that `iptables`/`ip6tables -j REJECT` accepts (all canonical icmp/icmpv6
types and their short aliases such as `net-unreach`, `tcp-rst`, `no-route`)
translates to a native nft `reject with icmp[v6] type ...` /
`reject with tcp reset`. nft spells the iptables name `icmp-proto-unreachable`
as `prot-unreachable`; the spellings are checked against a live `nft -c`. An
unknown value stays a translate-time error (fail-closed) rather than being
silently applied.

The fifth slice — **verdict maps (vmap)** under `--nft` — is also implemented
on `python-port` (not yet released): a run of adjacent single-key leaf rules
that differ in both the key and the verdict folds into one verdict map
(`tcp dport vmap { 22 : accept, 80 : drop }`), the verdict-carrying counterpart
of the anonymous-set collapse. Only pure verdicts (`accept`/`drop`/`return`/
`jump`/`goto`) are eligible — `reject`, `log`, and NAT statements
nft forbids inside a vmap break the run and stay linear — and a duplicate key
ends the run (nft rejects a vmap with duplicate keys). Members are ordered by
the key's canonical rank (nft stores a vmap key-ordered, like a set), and an
IPv6 address key (which carries its own colons) is split on the ` : ` member
separator and canonicalized, so `ferm --plan --nft` over an unchanged ruleset
converges. Multi-match rules and mixing a folded set with singles are
deliberately deferred.

To keep `ferm --plan --nft` honest, the desired ruleset is pre-validated with
`nft -c` before the diff in a real run (skipped under `--test`, which uses a
fake nft): an un-appliable plan — for example an `arp` chain carrying a `tcp`
match nft rejects with "conflicting protocols" — aborts with nft's own
diagnostic and exit 1, instead of being presented as an actionable change.

With anonymous, named, and interval sets, verdict maps, and native
`reject-with` shipped, Phase 5's native-expressiveness payoff is substantively
complete. The two map/concatenation items from the phase header are the
deliberate, documented exceptions recorded below.

#### Deferred debt

The following items are explicitly **out of scope** of the anonymous-set
slice and recorded here so they are not lost.

- *iptables port-range form (`lo-hi` vs `lo:hi`)* — ferm emits an iptables
  `--dport lo-hi` (dash) form that modern `nft`-backed `iptables-restore`
  rejects (it wants `lo:hi`). This is inherited faithfully from the Perl
  oracle, so changing it is a deliberate behaviour decision, not a bug fix:
  it makes the iptables port-range data path untestable on `nft`-backed
  distros. Track as an oracle-divergence decision.
- *Concatenation folding* — a composite-key set (`ip saddr . tcp dport
  { 1.2.3.4 . 22, ... }`) would fold adjacent rules that co-vary across two
  selectors at once (the "diagonal" case the cartesian set collapse leaves
  linear). It is semantically safe and nft-expressible (verified on a live
  `nft`), but deferred as a low-value optimization: ferm configs are written as
  per-service rule lists, so the diagonal pattern rarely arises, and the fold
  adds a parse/canon surface for little real-world gain. Revisit if a concrete
  config motivates it.
- *Named maps* — not applicable: ferm's language has no map construct, so the
  backend has nothing to emit as a named map, and ferm owns (flush-replaces)
  its own table, so a kernel readback never contains one. Recorded so the
  "maps" item from the Phase 5 header is explicitly accounted for, not lost.

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
