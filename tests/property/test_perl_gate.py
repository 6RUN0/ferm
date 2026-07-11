"""
Wiring gate: every oracle-driven test module opts into require_perl.

The perl guard is opt-in (``pytestmark = usefixtures("require_perl")``) so
the oracle-free tests keep running on hosts without perl.  The flip side:
a module that shells out to the oracle but forgets the marker dies with a
bare ``FileNotFoundError`` on such hosts instead of skipping.  Pin the
wiring across the whole suite: any test module importing one of the
perl-spawning seams must carry the marker.  Imports are resolved from the
AST (not a regex) so aliased, bare and relative spellings cannot evade
the gate.
"""

from __future__ import annotations

import ast
from pathlib import Path

_TESTS_ROOT = Path(__file__).resolve().parents[1]

#: Importing these modules in any form means the module spawns the oracle.
_PERL_MODULES = frozenset(
    {
        "tests.property.differential_cli",
        "tests.property.oracle",
    }
)
#: From this seam only the oracle command prefix implies perl; its other
#: names (compile_config over PORT_FERM, ORACLE_ENV) run without it.
_MIXED_SEAM = "tests._oracle"
_PERL_NAMES = frozenset({"oracle_ferm", "*"})
_MARKER = 'pytest.mark.usefixtures("require_perl")'


def _package_of(path: Path) -> str:
    """Dotted package of a test module, e.g. ``tests.property``."""
    rel = path.relative_to(_TESTS_ROOT.parent)
    return ".".join(rel.parts[:-1])


def _resolve_from(node: ast.ImportFrom, package: str) -> str:
    """Absolute module targeted by a (possibly relative) ``from`` import."""
    if node.level == 0:
        return node.module or ""
    base = package.split(".")[: -(node.level - 1) or None]
    if node.module:
        base.append(node.module)
    return ".".join(base)


def _spawns_perl(tree: ast.Module, package: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _PERL_MODULES or alias.name == _MIXED_SEAM:
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = _resolve_from(node, package)
            if module in _PERL_MODULES:
                return True
            if module == _MIXED_SEAM and any(
                alias.name in _PERL_NAMES for alias in node.names
            ):
                return True
            # ``from tests.property import oracle`` / ``from tests import
            # _oracle`` bind the seam module itself; attribute use is
            # invisible here, so treat the mixed seam conservatively.
            for alias in node.names:
                dotted = f"{module}.{alias.name}" if module else alias.name
                if dotted in _PERL_MODULES or dotted == _MIXED_SEAM:
                    return True
    return False


def test_oracle_driven_modules_declare_require_perl() -> None:
    missing = []
    for path in sorted(_TESTS_ROOT.rglob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        if _spawns_perl(tree, _package_of(path)) and _MARKER not in source:
            missing.append(str(path.relative_to(_TESTS_ROOT)))
    assert not missing, (
        "oracle-driven test modules missing the require_perl marker: "
        f"{missing}"
    )
