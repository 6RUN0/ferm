"""
Host validation of datapath scenario configs (no docker, no kernel).

Renders every scenario config under both ferm backends with
``--test --noexec --lines`` -- a hermetic parse that proves each config
is literal valid ferm before the container ever runs it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Module-level (not a monkeypatch fixture): the parametrization below
# reads scenarios.SCENARIOS at COLLECTION time, before any fixture runs,
# so the import and its path setup must happen at module load.
_DATAPATH_DIR = Path(__file__).resolve().parents[1] / "e2e" / "datapath"
sys.path.insert(0, str(_DATAPATH_DIR))

import scenarios  # noqa: E402

_REPO_SRC = Path(__file__).resolve().parents[2] / "src"


def _render(
    config: str, backend: str, tmp_path: Path
) -> subprocess.CompletedProcess[str]:
    cfg = tmp_path / "scenario.ferm"
    cfg.write_text(config, encoding="utf-8")
    cmd = [sys.executable, "-m", "pyferm", "--test", "--noexec", "--lines"]
    if backend == "nft":
        cmd.append("--nft")
    cmd.append(str(cfg))
    env = {"PYTHONPATH": str(_REPO_SRC)}
    return subprocess.run(
        cmd, capture_output=True, encoding="utf-8", check=False, env=env
    )


@pytest.mark.parametrize(
    "scenario", scenarios.SCENARIOS, ids=lambda s: s["name"]
)
@pytest.mark.parametrize("backend", ["nft", "iptables"])
def test_scenario_config_is_valid_ferm(
    scenario: dict, backend: str, tmp_path: Path
) -> None:
    result = _render(scenario["config"], backend, tmp_path)
    assert result.returncode == 0, (
        f"{scenario['name']} ({backend}) did not parse:\n{result.stderr}"
    )


def test_every_scenario_has_required_keys() -> None:
    for scenario in scenarios.SCENARIOS:
        assert scenario["type"] in {"probe", "stateful"}
        assert scenario["name"]
        assert scenario["config"]
        assert scenario["backends"]
        assert isinstance(scenario["probes"], list)
        for probe in scenario["probes"]:
            assert isinstance(probe, scenarios.Probe)
        if scenario["type"] == "stateful":
            assert "established_check" in scenario
