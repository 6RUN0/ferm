"""Gates over the packaged default config, on both backends.

``packaging/deb/ferm.conf`` is the starter ruleset every package (deb,
rpm, apk) installs as ``/etc/ferm/ferm.conf``, and
``ssh-throttle.conf.example`` is the optional ``ferm.d/`` drop-in it
advertises.  A regression here ships a broken firewall to every new
install, so unlike the wild corpus these first-party files get the
strict contract on both backends:

* the iptables path must compile bug-for-bug with the Perl oracle
  (same verdict, stderr, canonicalized ruleset) -- and that verdict
  must be *success*, never a matching failure;
* the nft path must translate cleanly (these files must never join
  ``_EXPECTED_NFT_REFUSALS``) and keep the security-relevant shape:
  default-drop INPUT/FORWARD, SSH and ICMP admitted, the throttle's
  calibrated recent limit;
* whatever translates must pass a live ``nft -c`` where ``unshare
  -rn``/``nft`` are available (same degradation as the corpus gate).

Each test deploys the config into a temporary directory exactly as the
package does (``ferm.conf`` beside an empty ``ferm.d/``; the throttle
layout drops the example in as ``ferm.d/10-ssh-throttle.conf``), so the
``@include 'ferm.d/'`` tail is exercised in both the empty and the
populated form.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.corpus.canon import canonicalize
from tests.corpus.test_corpus_nft import _NFT_LINE, _live_nft_usable

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
PACKAGED_CONF = REPO_ROOT / "packaging" / "deb" / "ferm.conf"
THROTTLE_EXAMPLE = (
    REPO_ROOT / "packaging" / "deb" / "examples" / "ssh-throttle.conf.example"
)

_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

#: Deployment layouts: the pristine install, and the install after the
#: user copies the advertised throttle example into ``ferm.d/``.
_LAYOUTS = ["bare", "throttle"]


@pytest.fixture(params=_LAYOUTS)
def deployed_conf(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    """Copy the packaged config into tmp the way the package installs it."""
    conf = tmp_path / "ferm.conf"
    shutil.copy(PACKAGED_CONF, conf)
    dropins = tmp_path / "ferm.d"
    dropins.mkdir()
    if request.param == "throttle":
        shutil.copy(THROTTLE_EXAMPLE, dropins / "10-ssh-throttle.conf")
    return conf


def _compile(
    prefix: tuple[str, ...], args: list[str]
) -> tuple[bool, str, str]:
    proc = subprocess.run(  # fixed argv, no shell
        [*prefix, *args],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=_ENV,
        cwd=REPO_ROOT,
    )
    return proc.returncode == 0, proc.stdout, proc.stderr


@pytest.mark.parametrize("mode_args", [[], ["--slow"]], ids=["fast", "slow"])
def test_packaged_config_matches_oracle(
    deployed_conf: Path, mode_args: list[str]
) -> None:
    args = ["--test", "--noexec", "--lines", *mode_args, str(deployed_conf)]
    oracle = _compile(
        ("perl", str(REPO_ROOT / "reference" / "src" / "ferm")), args
    )
    port = _compile((sys.executable, "-m", "pyferm"), args)

    # The packaged default must actually compile, not merely agree with
    # the oracle on a failure.
    assert oracle[0], f"oracle refused the packaged config\n{oracle[2]}"
    assert port[0], f"port refused the packaged config\n{port[2]}"
    assert port[2] == oracle[2], "stderr differs"
    assert canonicalize(port[1]) == canonicalize(oracle[1])


def _translate_nft(conf: Path) -> str:
    ok, stdout, stderr = _compile(
        (sys.executable, "-m", "pyferm"),
        ["--nft", "--test", "--lines", str(conf)],
    )
    assert ok, f"nft backend refused the packaged config\n{stderr}"
    return stdout


def test_packaged_config_translates_to_nft(deployed_conf: Path) -> None:
    output = _translate_nft(deployed_conf)
    for family in ("ip", "ip6"):
        for chain, policy in (
            ("INPUT", "drop"),
            ("FORWARD", "drop"),
            ("OUTPUT", "accept"),
        ):
            assert (
                f"add chain {family} ferm {chain} "
                f"{{ type filter hook {chain.lower()} priority 0; "
                f"policy {policy}; }}" in output
            )
        assert f"add rule {family} ferm INPUT tcp dport 22 accept" in output
        assert (
            f"add rule {family} ferm INPUT ct state established,related "
            "accept" in output
        )
    assert "add rule ip ferm INPUT icmp type echo-request accept" in output
    # The RFC 4890 set must survive translation, respelled to the
    # kernel-readback names.
    assert (
        "add rule ip6 ferm INPUT icmpv6 type nd-neighbor-solicit accept"
        in output
    )
    if (deployed_conf.parent / "ferm.d" / "10-ssh-throttle.conf").exists():
        # The composed throttle: three rules per family share one
        # calibrated element spec (T=3 rules x H=10 hits -> rate over
        # 30/minute burst 29).
        for family, addr in (("ip", "ip saddr"), ("ip6", "ip6 saddr")):
            assert (
                f"add set {family} ferm recent_SSH_THROTTLE "
                f"{{ type ipv{'4' if family == 'ip' else '6'}_addr; "
                "size 65535; flags dynamic,timeout; }" in output
            )
            assert (
                f"update @recent_SSH_THROTTLE {{ {addr} timeout 1m "
                "limit rate over 30/minute burst 29 packets } "
                'log prefix "ferm-ssh-throttle: "' in output
            )


@pytest.mark.skipif(
    not _live_nft_usable(), reason="needs unshare -rn plus nft"
)
def test_packaged_config_live_nft_accepts(deployed_conf: Path) -> None:
    output = _translate_nft(deployed_conf)
    script = "\n".join(
        line for line in output.splitlines() if _NFT_LINE.match(line)
    )
    assert script, "empty nft ruleset"
    check = subprocess.run(  # fixed argv, no shell
        ["unshare", "-rn", "nft", "-c", "-f", "-"],
        input=script + "\n",
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert check.returncode == 0, f"live nft -c rejected:\n{check.stderr}"
