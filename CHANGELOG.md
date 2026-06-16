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

Phase 2 adds an **opt-in native `nftables` backend** behind `--nft`. The
default backend stays `iptables`, so existing configurations and output
are unchanged unless `--nft` is passed.

### Added — packaging

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
- **Static release version.** The distribution version is pinned in the
  project metadata; a release is the tag `vX.Y.Z` matching that version,
  and the build verifies the two agree before publishing.
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

- `dnspython` is now an optional dependency (`pip install pyferm[dns]`).
  Without it, `@resolve` uses the system stub resolver (`getaddrinfo`) and
  supports only `A`/`AAAA` records; `NS`/`MX` and other types raise a clear
  error. **Migration:** installs that relied on the previously-transitive
  `dnspython` get the stub backend after upgrading; reinstall with
  `pyferm[dns]` to restore `NS`/`MX` support.

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

[Unreleased]: https://github.com/6RUN0/ferm/tree/develop
