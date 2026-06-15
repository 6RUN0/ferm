# ferm (Python port)

`ferm` ("For Easy Rule Making", pronounced "firm") is a frontend for
`iptables`. It reads firewall rules from a structured, high-level
configuration language — with variables, functions, arrays, blocks and
includes — and installs them into the running kernel by calling
`iptables(8)` / `iptables-restore`. It also drives the `ip6tables`,
`arptables` and `ebtables` families.

The goal is to make rules easy to write *and* easy to read, so the
administrator spends time designing good rules rather than transcribing
them.

## Project status

This repository is **mid-migration** from the original Perl
implementation to Python:

- **`src/pyferm/`** — the Python port. **Phase 1 is complete**: it parses
  the full ferm configuration language and emits `iptables` rulesets
  (`ip`, `ip6`, `arp`, `eb` families), with both the fast
  (`iptables-restore`) and slow (per-rule) execution paths, the
  `--interactive` rollback safety net, and the `import-ferm` save-file
  round-trip. Output is validated **byte-for-byte against the Perl
  oracle**.
- **`reference/`** — the original Perl implementation, kept verbatim as
  the semantic oracle. Run its own test suite with
  `make -C reference check`.

**Phase 2 (opt-in / experimental)**: a native `nftables` backend behind
`--nft` translates the same configuration into a native nft ruleset and
applies it atomically via `nft -f -`. The default backend stays
`iptables`, so existing configurations and output are unchanged unless
`--nft` is passed. `--nft` is opt-in and experimental: it carries
documented semantic differences (a `policy DROP` shift under the own-table
model, `@preserve` unsupported) and has golden + `nft -c` coverage but no
Perl-oracle differential test. The roadmap lives in
[`docs/ROADMAP.md`](docs/ROADMAP.md).

### Branches

- **`main`** — the new default branch (release line).
- **`develop`** — active development; branch your work from here.
- **`python-port`** — the porting-process branch.
- **`master`** — frozen; kept for historical reference only.

## Requirements

- Python **3.11–3.14**
- `iptables` (including `iptables-save` / `iptables-restore`) and a
  netfilter-capable kernel, at runtime
- [`uv`](https://docs.astral.sh/uv/) for development

There are no required runtime dependencies. `@resolve()` uses
[`dnspython`](https://www.dnspython.org/) when it is installed (full record
vocabulary, including `NS`/`MX`); otherwise it falls back to the system stub
resolver (`getaddrinfo`, honouring `/etc/nsswitch.conf`), which answers only
`A`/`AAAA` records — other types then raise a clear error. Install the `dns`
extra (`pip install pyferm[dns]`) for the full set of record types. The stub
resolver consults system sources such as `/etc/hosts` and mDNS that dnspython
bypasses, so the two backends can diverge when those local sources differ from
authoritative DNS.

## Usage

```sh
# Inspect the generated rules without touching the kernel (the safe way):
uv run ferm --noexec --lines /etc/ferm/ferm.conf

# Install the ruleset into the running kernel (needs root):
uv run ferm /etc/ferm/ferm.conf

# Convert an existing firewall into a ferm config:
uv run import-ferm > /etc/ferm/ferm.conf
```

Be careful not to lock yourself out of a remote machine — use the
interactive mode (`--interactive`, `-i`) often. It installs the new
ruleset, then rolls back to the previous one unless you confirm in time.

The `ferm(1)` man page (authored in `reference/doc/ferm.pod`) is the
extensive reference for the configuration syntax.

## Development

The project is managed entirely with `uv` and orchestrated with `nox`:

```sh
uv sync                              # create .venv from uv.lock
uv run nox -s lint tests typecheck   # the everyday inner loop
uv run nox -s preflight              # the full binding gate
```

Selected `nox` sessions:

| Session         | Purpose                                                         |
| --------------- | --------------------------------------------------------------- |
| `lint`          | `ruff` lint + format check                                      |
| `tests`         | unit + golden-file suite                                        |
| `typecheck`     | `mypy` + `pyright` (`verifytypes` 100%)                         |
| `golden_oracle` | golden output diffed against the Perl oracle + differential fuzz |
| `coverage`      | coverage with an enforced floor                                 |
| `matrix`        | the suite across Python 3.11–3.14                               |
| `fuzz`          | Hypothesis differential fuzzing vs. the oracle                  |
| `crashfuzz`     | `atheris` crash fuzzing of both parsers (opt-in)                |
| `mutation`      | `mutmut` mutation testing (opt-in, nightly)                     |
| `lockout`       | containerised anti-lockout `--interactive` e2e (opt-in)         |

### Testing

The suite is golden-file ("expected output") based: each fixture pairs a
`.ferm` input with a checked-in expected output, and ferm's output is
diffed after canonicalisation (tables/chains emit in non-deterministic
order). On top of that, the port is continuously checked **differentially
against the Perl oracle** — both on a corpus of real-world configs and on
Hypothesis-generated inputs — so divergences are caught automatically.

## License

GPL-2.0-or-later. See `reference/COPYING`.

Original authors: Auke Kok and Max Kellermann. Python port maintained by
Boris Talovikov.
