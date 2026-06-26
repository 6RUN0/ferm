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

## Sanitization

Every edit made to a fetched file is marked inline with a
`[corpus: ...]` comment:

* `@include` lines are commented out (the included files are not part of
  the corpus) and variables they were supposed to define are stubbed
  with documentation-range addresses;
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
