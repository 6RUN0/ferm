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
  non-findings is `FermError`.
- `fuzz_import.py` — drives `import-ferm`'s `Importer.run` on arbitrary
  byte streams. This is the port's only parser fed genuinely external text
  (the stdout of the system `iptables-save`). `Importer.run` is pure, so no
  guards are needed. Its allow-list also accepts `RecursionError`, raised by
  `_optimize`'s recursion on common-prefix blocks.

Both decode input as latin-1, a bijective byte-to-char mapping, so the
fuzzers exercise the full byte range exactly as the latin-1 byte model on
the port's I/O boundaries delivers it. The config parser's two recursive
readers are now depth-bounded (`MAX_BLOCK_DEPTH` for `enter`,
`MAX_VALUE_DEPTH` for `getvalues`/`_read_array`), so deep nesting fails with
a located `FermError` rather than a stack overflow. `import-ferm`'s
`_optimize` still recurses on common-prefix blocks — the oracle nests the
same way — so `RecursionError` stays on that one harness's allow-list.

## Running

```sh
uv run nox -s crashfuzz            # both targets, 60s each (default)
uv run nox -s crashfuzz -- 300     # both targets, 300s each
```

Standalone (any libFuzzer flag works):

```sh
uv run --group crashfuzz --python 3.13 python fuzz/fuzz_config.py \
    fuzz/corpus/config tests/corpus/configs -max_total_time=60
uv run --group crashfuzz --python 3.13 python fuzz/fuzz_import.py \
    fuzz/corpus/import fuzz/seeds/import -max_total_time=60
```

`atheris` ships cp311–cp313 wheels only, so pin Python 3.13 (the `crashfuzz`
nox session does this for you).

## Layout

- `seeds/import/` — committed iptables-save seeds for `fuzz_import.py`.
  The config target seeds from the wild configs in `tests/corpus/configs/`.
- `corpus/` — the working corpus libFuzzer grows across runs (gitignored).
- `crashes/` — saved reproducers for any finding (gitignored).

When a run finds a crash, minimize it and promote it into a `tests/unit`
(or golden) regression test by hand rather than committing the raw artifact.
