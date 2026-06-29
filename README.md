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

## Installation

Three distribution forms are available. All carry the same version derived
from the same git tag.

### WARNING: the default configuration blocks all inbound traffic

Before enabling the `ferm` systemd service, read this section carefully.

The starter `/etc/ferm/ferm.conf` installed by the `.deb` package applies a
**DROP policy to the `INPUT` chain**. Only two narrow exceptions are open by
default: SSH on port 22 (identified by the service name `ssh`) and the
ICMPv6 essentials required by RFC 4890 (neighbour discovery, etc.). Any
other inbound traffic is dropped immediately on service start.

**Before running `systemctl enable --now ferm`:**

- Add every service you need to reachable through your firewall as a
  drop-in fragment in `/etc/ferm/ferm.d/` (for example, HTTP/HTTPS,
  custom application ports).
- If SSH runs on a port other than 22, edit `$SSH_PORT` in
  `/etc/ferm/ferm.conf` before enabling. Enabling the service with the
  wrong SSH port will lock you out of a remote machine.
- Fragments in `/etc/ferm/ferm.d/*.conf` are executed as root. Keep them
  owned by `root:root` with permissions `0644` or stricter. A
  world-writable fragment is a privilege-escalation vector.

**Migrating from the Perl `ferm` package:** the `pyferm` `.deb` installs
over the Perl package via `Provides/Conflicts/Replaces: ferm`, but it does
**not** automatically enable or start `ferm.service`. If you relied on the
Perl package having the service enabled, you must re-enable it explicitly
after installing `pyferm`. This is intentional: the default configuration
above would otherwise lock you out on first boot.

**Third-party packages that declare `Depends: ferm`** (automation tooling,
configuration managers) will have their dependency satisfied by `pyferm`,
but any `systemctl enable ferm` those tools may run will apply the default
DROP configuration. Audit what your automation does before installing.

**Alpine (`.apk`, OpenRC):** the posture-downgrade advisory (a breadcrumb
warning that the firewall will no longer auto-apply after migrating) works
across the usual two-transaction migration (`apk del ferm` then
`apk add pyferm`), even though `apk` has no pre-removal hook. The OpenRC
runlevel symlink is admin state, not a package-owned file, so `apk del ferm`
leaves it in place (the upstream Alpine `ferm` aport ships no deinstall
scriptlet that would remove it), and `apk add pyferm` lays its own service
down before its post-install runs, so the symlink is present at probe time.
Detection uses `[ -L ]` (lstat), so it holds whether the symlink is live or
dangling. Fail-safe regardless — `pyferm` ships its service un-added to any
runlevel, so even a missed advisory never causes a lockout. The `.deb`/`.rpm`
packages snapshot the prior posture in a pre-install hook (which runs before
the legacy package is removed) across systemd, SysV and `systemctl
is-enabled`.

### PyPI (pip)

```sh
pip install ferm
```

For full DNS record-type support in `@resolve()` (including `NS`/`MX`),
install the `dns` extra:

```sh
pip install ferm[dns]
```

The `ferm` and `import-ferm` console scripts are placed on `PATH` by pip.

### Native .deb package

Download `pyferm_<version>_all.deb` from the
[GitHub Releases](https://github.com/6RUN0/ferm/releases) page and install
it:

```sh
sudo apt install ./pyferm_<version>_all.deb
```

`apt install ./...` (with the explicit `./` path) resolves dependencies
automatically. Do not use `dpkg -i` directly unless you handle dependencies
yourself.

The package name is `pyferm` but it declares `Provides: ferm`,
`Conflicts: ferm`, and `Replaces: ferm`. Installing it removes any
existing Perl `ferm` package and satisfies packages that depend on `ferm`.

When migrating from the Perl `ferm`, your edited `/etc/ferm/ferm.conf` is
kept: an interactive `apt` prompts you to keep it (the default), and for an
unattended upgrade pass `-o Dpkg::Options::=--force-confold` to keep it
without prompting.

After installation the service is **not** enabled. Review the warning above,
customise `/etc/ferm/ferm.conf` and add fragments to `/etc/ferm/ferm.d/`,
then opt in:

```sh
systemctl enable --now ferm
```

**Applying changes — reload, don't restart:** after editing
`/etc/ferm/ferm.conf` or a fragment, run `systemctl reload ferm`. `reload`
re-applies the ruleset atomically (via `iptables-restore`) with no window in
which the firewall is down. `restart` first runs the unit's `ExecStop`, which
**flushes** the rules (`ferm -F`) and briefly leaves the host open before they
are re-applied.

**Coexisting with other firewall tools:** ferm owns every table it manages and
replaces that table wholesale on each apply. Rules another daemon (Docker,
fail2ban, libvirt) writes into a ferm-managed table are therefore dropped on
the next reload unless you carry them across explicitly with the `@preserve`
keyword. The native `--nft` backend instead manages a single
`table <family> ferm` and leaves other tables untouched — but it does not
support `@preserve`.

### Installation (standalone binary)

A self-contained binary is published for **Linux x86_64** (glibc **2.28**
or newer). It carries its own Python runtime and a bundled `dnspython`,
so no Python installation is needed on the target host. It does **not**
bundle `iptables` or `nft` — those must already be present on the system,
because ferm calls them to install the rules.

Download the release tarball `ferm-<version>-linux-x86_64.tar.gz` and
unpack it, preserving symlinks:

```sh
tar xzf ferm-<version>-linux-x86_64.tar.gz
```

This produces a `ferm.dist/` directory containing the `ferm` binary and,
next to it, an `import-ferm` symlink.

### Keep the binary inside its directory

The `ferm` binary loads its bundled shared objects from its own directory
(via an `$ORIGIN`-relative runtime path). **Do not move or copy the bare
`ferm` binary out of `ferm.dist/`** — a lone copy can no longer find its
libraries and will fail to start. To run it from a directory on `PATH`,
create a **symlink** to the binary instead of copying it; `$ORIGIN` still
resolves through the symlink:

```sh
ln -s /opt/ferm/ferm.dist/ferm /usr/local/bin/ferm
```

### Unpack into a root-owned directory

ferm runs as root. Because the binary loads shared objects from its own
directory, a world- or group-writable dist directory lets a local
attacker plant a malicious shared object next to the binary that then
runs with root privileges. **Unpack into a directory owned by root and
not writable by other users** (for example `/opt/ferm`, mode `0755`,
owner `root`), and verify the permissions *before* the first run as root:

```sh
sudo install -d -o root -g root -m 0755 /opt/ferm
sudo tar xzf ferm-<version>-linux-x86_64.tar.gz -C /opt/ferm
ls -ld /opt/ferm /opt/ferm/ferm.dist
```

As a backstop, the standalone binary checks this itself: when run as root it
refuses to start if its own dist directory is not owned by root or is group-
or world-writable, printing how to fix the permissions. This is a safety net,
not a substitute for a correct install — it cannot detect a malicious shared
object already planted before the check. Set `FERM_SKIP_DIST_PERM_CHECK=1` to
override it for a deliberately non-standard layout.

### Verifying the download

The release ships a `SHA256SUMS` file. It guards against accidental
corruption in transfer — **integrity, not authenticity.** A matching
checksum does **not** prove the file was not maliciously substituted,
because an attacker who can replace the tarball can replace the checksum
file too.

For authenticity, verify the build provenance attestation with the GitHub
CLI:

```sh
gh attestation verify ferm-<version>-linux-x86_64.tar.gz --repo 6RUN0/ferm
```

Attestation only protects those who actually run the check, so verify
every download rather than trusting the file blindly.

### `@resolve()` and the host resolver

`@resolve()` looks names up through the host's `/etc/resolv.conf`, and
ferm runs as root. If a rule's correctness depends on the resolved
address (for example, restricting access to a named host), a tampered or
spoofed DNS answer can change which addresses the installed ruleset
trusts. For security-significant rules, use a trusted or local resolver,
or write static addresses directly.

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

### Config history and rollback (etckeeper)

When [etckeeper](https://etckeeper.branchable.com/) manages `/etc`, every
successful apply records a commit in the `/etc` history with a **semantic**
message describing what changed in the kernel ruleset (for example
`filter/INPUT: +3 -1`), not just the textual diff of the `.ferm` files. This
is on by default whenever `etckeeper` is installed; pass `--no-etckeeper` to
turn it off for a single run.

```sh
# Show the ferm config's revision history (git-only):
ferm rollback --list

# Undo the last change: revert /etc/ferm to the previous revision and
# re-apply (shows the diff and asks for confirmation):
ferm rollback

# Roll back to an exact revision:
ferm rollback --to <sha>
```

Notes and boundaries:

- **Rollback is git-only.** The commit side works with any VCS etckeeper
  supports; rollback needs git (other VCS report it as unavailable with a
  clear message).
- **Rollback restores the source, then regenerates.** It reverts the
  `/etc/ferm` config and re-applies it — it does not restore the exact bytes
  that were live before (those may differ after a ferm/nftables upgrade or a
  `@resolve()` drift). For a firewall this is usually what you want; a
  byte-exact restore is not promised.
- **The commit captures all of `/etc`** (etckeeper's nature), so unrelated
  uncommitted `/etc` changes are swept into the ferm-attributed commit.
- **Content and message are separate axes.** The commit records the `/etc`
  *source*; the message describes the *kernel delta*. Editing a `.ferm` file
  with no effect on the kernel yields an empty message body, and a clean tree
  (a reboot, `systemctl reload`, or an idempotent re-run) is committed
  silently as nothing-to-commit.
- Rollback refuses to run if `/etc/ferm` has uncommitted changes (the
  checkout would overwrite them) — commit or stash them first.
- If you roll back under `--interactive` and then do **not** confirm, the
  kernel reverts to its pre-rollback state while the worktree stays rolled
  back; re-run `ferm` to resync.

The `ferm(1)` man page (authored in `reference/doc/ferm.pod`) is the
extensive reference for the configuration syntax.

### Using the nftables backend

ferm's default backend drives `iptables`/`iptables-restore`. There are two
ways to have your rules end up in the kernel's `nft` subsystem instead.

**1. Point the system `iptables` at its nft variant (recommended, stable).**
On Debian / Ubuntu the `iptables` command is itself an alternative between a
legacy and an nft implementation. Select the nft variant and ferm needs no
change — its `iptables-restore` then writes straight into the nft kernel
tables:

```sh
sudo update-alternatives --set iptables  /usr/sbin/iptables-nft
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
# or pick interactively: sudo update-alternatives --config iptables
```

**2. ferm's native `--nft` backend (opt-in, experimental).** This translates
the config into a native nft ruleset (see *Project status* above). Install
`nftables` (a Recommends of the deb/rpm package; the apk declares no
recommends, so on Alpine install it explicitly with `apk add nftables`) and
pass `--nft`:

```sh
ferm --noexec --lines --nft /etc/ferm/ferm.conf   # inspect
sudo ferm --nft /etc/ferm/ferm.conf               # apply
```

To make the **systemd** service use it, add a drop-in override with
`sudo systemctl edit ferm` (the empty assignments clear the unit's values
before resetting them — systemd requires this to override `ExecStart`):

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/ferm --nft /etc/ferm/ferm.conf
ExecReload=
ExecReload=/usr/bin/ferm --nft /etc/ferm/ferm.conf
ExecStop=
ExecStop=/usr/bin/ferm --nft -F /etc/ferm/ferm.conf
```

On Alpine (**OpenRC**), add `--nft` to the `ferm` invocations in `start()` and
`stop()` in `/etc/init.d/ferm`; `reload()` delegates to `start()`, so it
inherits the flag automatically.

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
