# Crash fuzzing (atheris)

Coverage-guided crash fuzzers for the two parsers in the port, complementing
the Hypothesis differential suite under `tests/property/`.

| Axis | Differential fuzzers (`tests/property/`) | Crash fuzzers (here) |
| --- | --- | --- |
| Question | Does the port *agree with* the Perl oracle? | Does any input make the port *crash or hang*? |
| Engine | Hypothesis, grammar-driven | atheris/libFuzzer, coverage-driven mutation |
| Oracle | the Perl `ferm`/`import-ferm` | none (an unhandled exception is the bug) |

Coverage feedback drives libFuzzer into tokenizer / `enter` / scope / deferred
branches a grammar never reaches by construction, so the two approaches find
different classes of defect.

## Harnesses

- `fuzz_config.py` — drives the config parser in-process, *below* the CLI.
  Three parse-stage constructs reach a shell, the filesystem or the network
  and are neutralized so fuzz input can never cause side effects: backticks
  (`Evaluator._run_shell` stubbed), `@include` (`open_script` blocked), and
  `@resolve` (no resolver provider installed). The allow-list of
  non-findings is `FermError` and `RecursionError`.
- `fuzz_import.py` — drives `import-ferm`'s `Importer.run` on arbitrary
  byte streams. This is the port's only parser fed genuinely external text
  (the stdout of the system `iptables-save`). `Importer.run` is pure, so no
  guards are needed.

Both decode input with `ConsumeUnicodeNoSurrogates`: the file-open path uses
strict UTF-8, so non-UTF-8 bytes are a separate (documented) Phase 2 concern,
not a parser crash. The unbounded recursive descent (`RecursionError` on deep
nesting) is likewise a tracked Phase 2 depth-limit item; the oracle recurses
the same way, so it is allow-listed here rather than treated as a finding.

## Running

```sh
uv run nox -s crashfuzz            # both targets, 60s each (default)
uv run nox -s crashfuzz -- 300     # both targets, 300s each
```

Standalone (any libFuzzer flag works):

```sh
uv run --group crashfuzz python fuzz/fuzz_config.py \
    fuzz/corpus/config tests/corpus/configs -max_total_time=60
uv run --group crashfuzz python fuzz/fuzz_import.py \
    fuzz/corpus/import fuzz/seeds/import -max_total_time=60
```

`atheris` ships cp311–cp313 wheels only, so the session pins Python 3.13.

## Layout

- `seeds/import/` — committed iptables-save seeds for `fuzz_import.py`.
  The config target seeds from the wild configs in `tests/corpus/configs/`.
- `corpus/` — the working corpus libFuzzer grows across runs (gitignored).
- `crashes/` — saved reproducers for any finding (gitignored).

When a run finds a crash, minimize it and promote it into a `tests/unit`
(or golden) regression test by hand rather than committing the raw artifact.
