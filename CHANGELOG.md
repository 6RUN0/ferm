# Changelog

All notable changes to the **Python port** of ferm are documented in this
file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

For the history of the original Perl implementation, see
[`reference/NEWS`](reference/NEWS).

## [Unreleased]

## [0.1.0a6] - 2026-06-30

### Added

- **Read-only plan mode (`--plan`).** `ferm --plan` computes the ruleset and
  reports what would change against the live kernel without applying anything,
  for both the default `iptables` backend and `--nft`. `--plan-format` selects
  a `structured` summary (default) or a unified `diff`. The run is exit-coded:
  `0` when nothing would change, non-zero otherwise. `@preserve` is reported as
  unsupported under `--plan`.
- **Config history and rollback via etckeeper.** When
  [etckeeper](https://etckeeper.branchable.com/) manages `/etc`, every
  successful apply records a commit in the `/etc` history with a semantic
  message describing the kernel-ruleset delta (for example `filter/INPUT:
  +3 -1`). `ferm rollback`, `rollback --list`, and `rollback --to <sha>` revert
  `/etc/ferm` to an earlier revision and re-apply it (git-only; the source is
  restored and regenerated, not the exact prior bytes). On by default when
  etckeeper is installed; `--no-etckeeper` turns it off for a single run.
- **Named nft sets via `@set`.** A `@set $name = (...)` declaration binds a
  reusable set of ports, addresses, or interface names. Under `--nft` the set
  is emitted as a first-class nft object (`add set` + `add element`) and the
  rule references it by name (`tcp dport @name`); a port set with a range
  carries `flags interval`. Under the default `iptables` backend the same
  `@set` reference is expanded back to its element list, so the rule unfolds to
  the identical cartesian product a literal list would produce — a config using
  `@set` works on both backends. `ferm --plan --nft` reports set additions,
  removals, and element changes alongside chain and rule diffs.
- **Base-chain priority knob (`--nft`).** A built-in chain may carry an
  explicit nft priority, written after the chain name: `chain FORWARD
  priority -1 { ... }`. The priority may be a plain integer or an nft
  landmark name with an optional offset, mirroring nft's own spelling:
  `priority filter`, `priority dstnat - 10`, `priority security + 1`
  (landmarks resolve per family). It overrides the hardcoded default (e.g. a
  filter forward chain's `0`) so ferm's table can be ordered deterministically
  against a coexisting one — for instance ahead of docker's forward chain,
  which also sits at priority `0`. nft-only: the integer is rejected under the
  `iptables` backend (chains have no priority there) and on a non-base chain.
  A delta-apply that changes an existing chain's priority deletes and recreates
  that chain (its counters reset; siblings are untouched), since nft cannot
  redeclare a chain with a different priority in place; `ferm --plan` reports
  it as a chain rebuild.
- **Chain and table names are validated against a safe alphabet.** A
  config-supplied chain or table name must match `[A-Za-z0-9_.+-]`; anything
  outside it is rejected at the backend border before any save text or
  command line is built. This is defense-in-depth for the slow path (one
  `iptables`/`ebtables` call per rule), where `eb`/`arp` rules run by default:
  a name carrying a shell metacharacter is refused rather than interpolated
  into the command. Valid configs are unaffected.

### Changed

- **`--nft` applies an incremental delta by default.** Instead of flushing and
  rebuilding ferm's table on every apply, the `--nft` backend now diffs the
  desired ruleset against the live one and applies only the changed sets,
  chains, and rules in a single atomic `nft -f -` transaction, preserving
  untouched counters. `--full-reload` restores the previous flush-and-rebuild
  behaviour. A first apply, an empty live snapshot, or a set retype falls back
  to a full reload automatically; a delta that would delete a set falls back
  too (the delta path never deletes a set).
- The `--nft` backend folds adjacent rules that differ in a single value
  into anonymous nft sets (`tcp dport { 22, 80, 443 }`), producing more compact
  output. Negated matches and per-rule-distinct statements stay linear.
- **`--nft` folds single-key rules with distinct verdicts into a verdict map**
  (`tcp dport vmap { 22 : accept, 80 : drop }`) and collapses address ranges
  into interval sets, for more compact output.

### Packaging

- **Native `.rpm` and `.apk` packages.** Alongside the PyPI wheel/sdist, the
  `.deb`, and the standalone binary, RPM (`.rpm`, for RPM-based distros) and
  Alpine (`.apk`, OpenRC) packages are now built and smoke-tested. Like the
  `.deb` they replace a prior `ferm` and ship the starter config un-applied
  (anti-lockout); the Alpine package carries a posture-downgrade advisory
  across the two-transaction `apk` migration.

### Security

- **The standalone binary refuses to run from a writable dist directory.**
  Run as root, it verifies its own `ferm.dist/` directory is owned by root and
  not group- or world-writable before loading its bundled shared objects,
  otherwise printing how to fix the permissions. This blocks a local attacker
  from planting a malicious shared object next to the binary.
  `FERM_SKIP_DIST_PERM_CHECK=1` overrides it for a deliberately non-standard
  layout.

### Notes

- **The first `ferm --plan --nft` after upgrading may show a one-time large
  diff.** When a config adopts `@set` or rule/verdict-map folding, the live
  kernel still holds the previous linear rules, so each affected rule appears
  as a change (for folding, `remove (N linear) + add (1 set)`) until the next
  apply. This is expected and resolves on the first apply.

## [0.1.0a3] - 2026-06-16

The Python port (`src/pyferm/`). Phase 1 reproduces the Perl
implementation's behaviour and emits `iptables` rulesets; its output is
validated byte-for-byte against the Perl oracle kept in `reference/`.

Phase 2 adds an **opt-in native `nftables` backend** behind `--nft`. The
default backend stays `iptables`, so existing configurations and output
are unchanged unless `--nft` is passed.

### Added — packaging

- **PyPI wheel and sdist** (`pip install ferm`). Built with `uv build` and
  published via Trusted Publishing — no token secrets stored in CI. The
  package name on PyPI is `ferm`; the `dns` extra (`pip install ferm[dns]`)
  pulls in `dnspython` for full record-type support in `@resolve()`. Version
  is derived from the `py-v<PEP440>` git tag through `hatch-vcs`, so the
  wheel version and the tag are always the same source.
- **Native `.deb` package** (`pyferm`). Installs `/usr/bin/ferm` and
  `/usr/bin/import-ferm` and declares `Provides: ferm`, `Conflicts: ferm`,
  `Replaces: ferm` so it is a drop-in replacement for the Perl `ferm` Debian
  package — installing `pyferm` removes the Perl package and satisfies any
  dependency that requires `ferm`. The `.deb` ships a starter
  `/etc/ferm/ferm.conf` (DROP policy on `INPUT`; only SSH on port 22 by the
  `ssh` service name and the RFC 4890 ICMPv6 essentials subset are accepted)
  and a `ferm.service` unit that is **not** enabled or started on install
  (anti-lockout). Drop-in fragments under `/etc/ferm/ferm.d/*.conf` are
  merged at runtime. See the installation section of the
  [README](README.md) for safety notes before enabling the service.
- **Standalone binary distribution** for **Linux x86_64** (glibc **2.28**
  or newer), published as `ferm-<version>-linux-x86_64.tar.gz`. It bundles
  its own Python runtime and `dnspython`, so the target host needs no
  Python install; it does not bundle `iptables` / `nft`, which must be
  present at runtime. Unpacking yields a `ferm.dist/` directory with the
  `ferm` binary and an `import-ferm` symlink. **Install invariant:** the
  binary loads bundled shared objects from its own directory, so keep it
  inside `ferm.dist/` and link to it (don't copy the bare binary out);
  unpack into a root-owned, non-world-writable directory. See the
  installation section of the [README](README.md) for the full provenance
  and threat-model notes.
- **Dynamic release version from git tag (`hatch-vcs`).** The distribution
  version is derived from the `py-v<PEP440>` git tag via `hatch-vcs`, so
  the wheel, sdist, binary, and `.deb` all carry the same version as the tag
  with no manual edit required. The build verifies the tag and the derived
  version agree before publishing.
- **Bundled third-party license texts.** The tarball ships a `LICENSES/`
  directory with the verbatim license text of every native library frozen
  into the binary (CPython, dnspython, OpenSSL, libffi, bzip2, xz, mpdecimal)
  plus a manifest. The build fails closed if any bundled library has no
  license text, so the artifact is never published without its notices.
- **glibc-floor release gate.** Releases now load the packaged binary on a
  pinned glibc 2.28 image (not the build image), so a symbol above the
  advertised floor fails the release rather than a user's old distro.

### Added — Phase 2 (native nft backend)

- **Opt-in `--nft` native nftables backend.** Translates the structured
  rule into a native nft ruleset and applies it atomically via
  `nft -f -`. It uses the nft *text* wire only and has no dependency on
  nft's JSON / `libjansson` build. `--nft` is strictly opt-in; the
  default remains the `iptables` backend.
- **`--nft` validates the ruleset with `nft -c -f -` before applying.**
  The applier runs nft's text `--check` (a netlink validation that
  installs nothing) first and only pipes the real `nft -f -` once it
  passes, surfacing nft's own diagnostic *before* any kernel change
  instead of a generic apply failure.
- **`--nft --interactive --shell` emits a working anti-lockout net.** The
  generated shell script snapshots ferm's table (`nft list table`) before
  applying, and after the confirmation timeout deletes the freshly-applied
  table and reloads the snapshot (`nft -f`) — mirroring the live rollback,
  so an admin who never confirms is restored. The script also echoes the
  rollback to stderr, so the otherwise-silenced restores (`2>/dev/null`)
  no longer revert a timed-out admin without a word.

### Changed — Phase 2 (native nft backend)

- **`policy DROP` semantics differ under `--nft`.** The nft backend owns
  a single `table <family> ferm` and does not take over the monolithic
  kernel `INPUT` / `FORWARD` / `OUTPUT` chains the way the flat iptables
  ruleset effectively does. ferm's base chains therefore coexist with
  other tables' base chains on the same hook (ordered by priority), so a
  packet may be accepted by a higher-priority foreign chain before
  reaching ferm's chain. A `policy DROP` in `table ip ferm` consequently
  behaves differently from iptables' monolithic `INPUT DROP`. This is the
  documented, expected behaviour of the own-table model, not a bug;
  admins who need the exact monolithic-DROP semantics should stay on the
  default `iptables` backend.

### Removed / not supported — Phase 2 (native nft backend)

- **`@preserve` is not supported by the `--nft` backend.** Using
  `@preserve` together with `--nft` is a clean, explicit error rather
  than a silent no-op. This is a deliberate, opt-in-backend regression;
  the default `iptables` backend supports `@preserve` exactly as before.

- **Port-bearing NAT requires a transport match under `--nft`.** A NAT
  verdict that maps a port (`DNAT to ...:port`, `SNAT to ...:port`,
  `REDIRECT`/`MASQUERADE to-ports`) with no preceding `proto tcp`/`udp`
  match is now a clean ferm error at translate time, because nft rejects
  such a mapping at apply (`transport protocol mapping is only valid after
  transport protocol match`) and would otherwise force a rollback. Add a
  protocol match to the rule.

### Security — Phase 2 (native nft backend)

- **`--nft` operands are escaped or validated before they reach the save
  script.** A config value carrying whitespace, `;`, `#`, or a double
  quote could previously break out of its nft token — for example
  `saddr "1.2.3.4 accept;#" DROP` rendered as
  `ip saddr 1.2.3.4 accept;# drop`, silently turning a `DROP` rule into
  `accept` (a form `nft -c` validates without complaint). Interface names
  are now emitted as escaped nft quoted strings (the `*` wildcard is
  preserved); addresses, ports, **protocols**, rate limits, and chain
  identifiers are grammar-validated, raising a plain ferm error rather
  than a ruleset nft would mis-apply. The protocol operand specifically
  (`proto "tcp accept;#" DROP` → `meta l4proto tcp accept;# drop`) was the
  last unguarded sink and is now validated like the others. The default
  `iptables` backend already escaped these operands and was never affected.
- **A failed rollback snapshot no longer degrades into a destructive
  delete.** The `--nft` rollback deletes ferm's own table when there is no
  previous snapshot (a genuine first run); a transient `nft list table`
  failure on an *existing* table is now distinguished from a real first run
  (by its non-`ENOENT` error) and aborts before any kernel change, instead
  of being mistaken for "no previous table" and deleting it on rollback.

### Fixed

- nft backend: render `reject-with tcp-reset` in the `ip6` family (it was
  only mapped for `ip`), matching the default backend and nftables' own
  family-agnostic `reject with tcp reset`.

### Changed

- `dnspython` is now an optional dependency (`pip install ferm[dns]`).
  Without it, `@resolve` uses the system stub resolver (`getaddrinfo`) and
  supports only `A`/`AAAA` records; `NS`/`MX` and other types raise a clear
  error. **Migration:** installs that relied on the previously-transitive
  `dnspython` get the stub backend after upgrading; reinstall with
  `ferm[dns]` to restore `NS`/`MX` support.

### Added — Phase 1 (faithful port)

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
- **Containerised data-plane e2e** (`nox -s datapath_e2e`, opt-in): drives
  real traffic with `nmap --reason` / `ncat` through ferm-installed rules
  across a three-netns topology, asserting ACCEPT / DROP / REJECT / state /
  NAT behaviour and parity between the `--nft` and default backends. An
  extensible distro matrix (`nox -s datapath_e2e_matrix`) reruns the same
  suite on Debian (bookworm + trixie), Ubuntu, Fedora, Arch, Rocky and
  openSUSE Leap, detecting the package manager (apt / dnf / apk / pacman /
  zypper) so adding a distro is a one-line entry.
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

[Unreleased]: https://github.com/6RUN0/ferm/compare/py-v0.1.0a6...develop
[0.1.0a6]: https://github.com/6RUN0/ferm/compare/py-v0.1.0a3...py-v0.1.0a6
[0.1.0a3]: https://github.com/6RUN0/ferm/releases/tag/py-v0.1.0a3
