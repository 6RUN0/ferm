"""Shared CLI-level differential helper: run one config through the port and
the Perl oracle with --test --noexec --lines and assert byte-parity under the
corpus contract (exit verdict + normalized stderr + canonicalized stdout).
Reuses the compilers of test_config_differential; used by the diagnostic-order
gate and the walk-slicing / header parity tests. NOT a self-snapshot.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from tests.corpus.canon import canonicalize
from tests.property.test_config_differential import (
    _compile_oracle,
    _compile_port,
    _normalize_stderr,
)


def assert_cli_parity(
    config: str, *, extra_args: tuple[str, ...] = ()
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "input.ferm"
        path.write_text(config, encoding="utf-8")
        args = ["--test", "--noexec", "--lines", *extra_args, str(path)]
        port = _compile_port(args)
        oracle = _compile_oracle(args)
    assert port[0] == oracle[0], (  # exit verdict (bool), not numeric code
        f"exit verdict differs\nconfig:\n{config}\n"
        f"port stderr:\n{port[2]}\noracle stderr:\n{oracle[2]}"
    )
    assert _normalize_stderr(port[2]) == _normalize_stderr(oracle[2]), (
        f"stderr order differs\nconfig:\n{config}\n"
        f"port:\n{port[2]}\noracle:\n{oracle[2]}"
    )
    assert canonicalize(port[1]) == canonicalize(oracle[1]), (
        f"stdout differs\nconfig:\n{config}"
    )
