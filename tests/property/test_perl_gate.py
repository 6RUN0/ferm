"""Wiring gate: every oracle-driven property module opts into require_perl.

The perl guard is opt-in (``pytestmark = usefixtures("require_perl")``) so
the oracle-free property tests keep running on hosts without perl.  The
flip side: a module that shells out to the oracle but forgets the marker
dies with a bare ``FileNotFoundError`` on such hosts instead of skipping.
Pin the wiring: any module importing one of the oracle seams must carry
the marker.
"""

from __future__ import annotations

import re
from pathlib import Path

_HERE = Path(__file__).resolve().parent

#: Importing any of these seams means the module spawns the Perl oracle.
_ORACLE_SEAM_IMPORT = re.compile(
    r"^from (?:tests\.property\.differential_cli"
    r"|\.oracle"
    r"|tests\._oracle) import",
    re.MULTILINE,
)
_MARKER = 'pytest.mark.usefixtures("require_perl")'


def test_oracle_driven_modules_declare_require_perl() -> None:
    missing = []
    for path in sorted(_HERE.glob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        if _ORACLE_SEAM_IMPORT.search(source) and _MARKER not in source:
            missing.append(path.name)
    assert not missing, (
        "oracle-driven property modules missing the require_perl marker: "
        f"{missing}"
    )
