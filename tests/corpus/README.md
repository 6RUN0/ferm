# Real-world ferm config corpus

Configurations collected from public repositories and compiled by both
the frozen Perl oracle and the Python port; see `test_corpus.py` for the
comparison contract and `provenance.yaml` for each file's upstream
source, commit pin, license, and exercised features. They are included
solely for interoperability testing of this port against real-world
usage; each file remains under its source repository's terms.

The upstream examples (`reference/examples/*.ferm`) are part of the same
suite but are run in place, except `resolve.ferm`, which is copied here
as `upstream-resolve.ferm` so its mock DNS `zonefile` can live next to
it.

## Multi-file entries

When a config's `@include` targets exist in the source repository at the
pinned commit, the whole tree is vendored as a directory entry:
`configs/<name>/<name>.ferm` is the entry point and the include files
(including `conf.d/`-style directory includes) sit beside it, so the
`@include` lines stay live and the differential exercises the real
multi-file resolution path. `test_provenance.py` verifies every live
include is relative and resolves inside its entry directory.

## Translated adversarial configs

`translated/*.ferm` are not harvested: they are real-world iptables/nft
setups rewritten into ferm by hand, chosen for structure the wild
configs barely exercise -- chain-dispatch mazes with `goto`/`RETURN`,
multi-stage and hairpin NAT, QoS marking cascades in `mangle`,
`raw`-table conntrack bypass, boundary values at the edges of the
accepted ranges, pathologically deep nesting, and rarely used language
forms (deprecated keywords, aliases, negation) whose stderr warnings
the differential pins byte-for-byte. Each file documents its source pattern in
an `Origin:` header (enforced by `test_provenance.py`); they run through
the same oracle differential as the harvested corpus.

## nft gate

`test_corpus_nft.py` pushes every corpus-owned config through the nft
backend (`--nft --test --lines`). There is no oracle on that side, so
the contract is a pinned dichotomy: a config either translates -- and
the result must then pass a live `nft -c` in a rootless namespace when
one is available -- or is refused with a clean one-line ferm error.
The refusing set is pinned in `_EXPECTED_NFT_REFUSALS`; growing the
backend must shrink that list in the same change.

## Sanitization

Every edit made to a fetched file is marked inline with a
`[corpus: ...]` comment:

* `@include` lines whose target does not exist upstream (machine-local
  files) are commented out and variables they were supposed to define
  are stubbed with documentation-range addresses; includes vendored in a
  multi-file entry stay live;
* backtick command substitutions are replaced with literal values (ferm
  executes backticks even under `--noexec`);
* one syntax error in an editor-plugin example (`@def &func(...) {`
  missing its `=`) is fixed so the file exercises rule emission.

Template files (Jinja2/ERB `ferm.conf` templates) were rejected during
collection.

## Provenance

Each config's upstream repository, in-repo path, best-effort commit pin,
license, and the features it exercises live in `provenance.yaml` -- the
single source of truth, validated by `test_provenance.py` (which also
enforces that every config keeps its sanitization sinks neutralized).
The per-file `sanitized` field there records the edits made to that
fetched copy.
