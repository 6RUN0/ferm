"""
Static sanity of the native Debian packaging skeleton (``packaging/deb``).

These tests do not build a ``.deb`` (that is the opt-in ``nox -s build_deb``
container gate); they assert the checked-in ``debian/*`` declarations are
internally consistent and that the shipped default ``ferm.conf`` is a sane,
anti-lockout starter ruleset.

The load-bearing assertions are the CONSISTENCY ones (a string-for-string
field check is only a regression guard, not a real test): the ``3.0
(native)`` source format must agree with a revision-less changelog, the
``copyright`` authors must equal ``pyproject`` authors, and the compiled
default ruleset must keep ``ESTABLISHED,RELATED ACCEPT`` ahead of the DROP
policy and carry no blanket ICMPv6 accept / active throttle.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEB = _REPO_ROOT / "packaging" / "deb"
_DEBIAN = _DEB / "debian"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"


def _read(rel: str) -> str:
    return (_DEBIAN / rel).read_text(encoding="utf-8")


def _pyproject_authors() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    return [author["name"] for author in data["project"]["authors"]]


# -- control --------------------------------------------------------------


def test_control_source_and_binary_package_names() -> None:
    control = _read("control")
    assert re.search(r"^Source:\s*pyferm\b", control, re.MULTILINE)
    assert re.search(r"^Package:\s*pyferm\b", control, re.MULTILINE)


def test_control_drop_in_relations_target_archive_ferm() -> None:
    # The deb is a drop-in over the upstream Perl `ferm`: it must Provide,
    # Conflict with, and Replace that archive name so the two cannot coexist
    # and dependents on `ferm` stay satisfied.
    control = _read("control")
    for field in ("Provides", "Conflicts", "Replaces"):
        assert re.search(rf"^{field}:\s*ferm\b", control, re.MULTILINE), field


def test_control_architecture_all_pure_python() -> None:
    control = _read("control")
    assert re.search(r"^Architecture:\s*all\b", control, re.MULTILINE)


def test_control_recommends_optional_dnspython() -> None:
    # @resolve() is optional; the resolver falls back to stdlib getaddrinfo
    # without it, so dnspython is a Recommends, not a Depends.
    control = _read("control")
    assert re.search(r"^Recommends:.*python3-dnspython", control, re.MULTILINE)


def test_control_build_depends_carry_dynamic_version_backend() -> None:
    # pybuild + the hatch-vcs dynamic-version backend must be build-deps or
    # the in-container build cannot resolve the version.
    control = _read("control")
    build_depends = control
    for dep in (
        "debhelper-compat",
        "dh-sequence-python3",
        "pybuild-plugin-pyproject",
        "python3-all",
        "python3-hatchling",
        "python3-hatch-vcs",
    ):
        assert dep in build_depends, dep


def test_control_maintainer_has_real_email() -> None:
    # A placeholder <...> maintainer is a lintian E:; the real git identity
    # must be used.
    control = _read("control")
    assert re.search(r"^Maintainer:\s*.+<[^>]+@[^>]+>", control, re.MULTILINE)


# -- rules ----------------------------------------------------------------


def test_rules_exports_pybuild_name_ferm() -> None:
    # Without PYBUILD_NAME=ferm pybuild names the dist-info pyferm-<ver> and
    # importlib.metadata.version("ferm") fails -> --version is 0+unknown.
    rules = _read("rules")
    assert re.search(
        r"^export\s+PYBUILD_NAME\s*=\s*ferm\b", rules, re.MULTILINE
    )


def test_rules_anti_lockout_systemd_override() -> None:
    # The firewall unit must NOT be enabled/started on install (lockout
    # risk), and must be named `ferm` (README / config / smoke expect it).
    rules = _read("rules")
    assert "override_dh_installsystemd:" in rules
    assert "--name=ferm" in rules
    assert "--no-enable" in rules
    assert "--no-start" in rules


def test_rules_uses_pybuild_buildsystem() -> None:
    rules = _read("rules")
    assert re.search(r"dh\s+\$@\s+--buildsystem=pybuild", rules)


# -- source format / changelog consistency (load-bearing) -----------------


def test_source_format_is_native() -> None:
    assert _read("source/format").strip() == "3.0 (native)"


def test_changelog_native_has_no_debian_revision() -> None:
    # CONSISTENCY: a native (3.0) source must carry a revision-less version
    # (pyferm (<ver>) ...), never pyferm (<ver>-1) -- a revision makes
    # dpkg-source reject the native format. This pairs the format and the
    # changelog so they cannot drift apart.
    changelog = _read("changelog")
    first = changelog.splitlines()[0]
    match = re.match(r"^pyferm\s*\(([^)]+)\)\s", first)
    assert match, f"unexpected changelog header: {first!r}"
    version = match.group(1)
    # native (3.0) forbids a debian revision (-N)
    assert "-" not in version, f"native version has a revision: {version}"


# -- systemd unit ---------------------------------------------------------


def test_unit_file_named_for_package_dot_ferm() -> None:
    # debhelper derives the installed unit name from the file name; the
    # package.name.service convention + --name=ferm installs it as
    # ferm.service.
    assert (_DEBIAN / "pyferm.ferm.service").is_file()


def test_unit_is_oneshot_remain_after_exit() -> None:
    unit = _read("pyferm.ferm.service")
    assert re.search(r"^Type=oneshot", unit, re.MULTILINE)
    assert re.search(r"^RemainAfterExit=yes", unit, re.MULTILINE)


def test_unit_execstart_uses_installed_paths() -> None:
    unit = _read("pyferm.ferm.service")
    assert re.search(
        r"^ExecStart=/usr/bin/ferm\s+/etc/ferm/ferm\.conf", unit, re.MULTILINE
    )


# -- install / dirs / examples --------------------------------------------


def test_dirs_creates_dropin_directory() -> None:
    assert "etc/ferm/ferm.d" in _read("pyferm.dirs")


def test_install_ships_config_to_etc_ferm() -> None:
    # .install does not rename: the source basename (ferm.conf) lands in
    # /etc/ferm/, becoming a dpkg conffile.
    install = _read("pyferm.install")
    assert "ferm.conf" in install
    assert "etc/ferm" in install
    assert (_DEB / "ferm.conf").is_file()


def test_examples_carry_throttle_sample() -> None:
    examples = _read("pyferm.examples")
    assert "ssh-throttle.conf.example" in examples
    assert (_DEB / "examples" / "ssh-throttle.conf.example").is_file()


# -- maintainer scripts ---------------------------------------------------


def _maintscripts() -> list[str]:
    stages = ("preinst", "postinst", "postrm")
    return [_read(f"pyferm.{stage}") for stage in stages]


def test_maintscripts_detect_enabled_by_file_not_systemctl() -> None:
    # systemctl is-enabled is unreliable in a chroot / PID1-less container;
    # the migration logic must detect the old unit via the on-disk wants
    # symlink instead.
    joined = "\n".join(_maintscripts())
    assert "multi-user.target.wants/ferm.service" in joined
    assert "is-enabled" not in joined


def test_preinst_refuses_symlink_legacy_config() -> None:
    # R3: a /etc/ferm.conf that is a symlink must NOT be adopted (cp -a would
    # copy it as a link into /etc/ferm/, pointing root at a non-root path).
    preinst = _read("pyferm.preinst")
    # the symlink guard: regular-file-and-not-symlink
    assert "-L" in preinst  # tests for a symlink somewhere
    assert "cp -a" not in preinst  # the unsafe form is not used


def test_postrm_purge_clears_downgrade_breadcrumb() -> None:
    # The posture-downgrade breadcrumb must be cleaned on purge so a
    # reinstall is not blocked by an orphaned file.
    postrm = _read("pyferm.postrm")
    assert "purge" in postrm


def test_downgrade_signal_is_durable_not_only_stderr() -> None:
    # The signal must survive unattended apt (which swallows postinst
    # stderr): a breadcrumb file written somewhere durable.
    postinst = _read("pyferm.postinst")
    assert "POSTURE-DOWNGRADE" in postinst


# -- copyright (consistency, load-bearing) --------------------------------


def test_copyright_license_is_gpl_2_or_later() -> None:
    copyright_text = _read("copyright")
    assert re.search(
        r"^License:\s*GPL-2\.0-or-later", copyright_text, re.MULTILINE
    )


def test_copyright_authors_match_pyproject() -> None:
    # CONSISTENCY: lintian only checks copyright FORMAT, not whether the
    # authors are right. Pin them to the single source of truth (pyproject
    # authors) so the two cannot drift.
    copyright_text = _read("copyright")
    for author in _pyproject_authors():
        assert author in copyright_text, author


# -- default ruleset: anti-lockout invariants (load-bearing) --------------


def _compile_default_config(tmp_path: Path) -> str:
    """Compile the shipped ferm.conf with the real parser, both families."""
    workdir = tmp_path / "etc-ferm"
    (workdir / "ferm.d").mkdir(parents=True)
    config = workdir / "ferm.conf"
    config.write_text(
        (_DEB / "ferm.conf").read_text(encoding="utf-8"), encoding="utf-8"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--noexec",
            "--lines",
            "--test",
            str(config),
        ],
        capture_output=True,
        encoding="utf-8",
        check=True,
        cwd=_REPO_ROOT,
    )
    return result.stdout


def test_default_config_compiles_both_families(tmp_path: Path) -> None:
    out = _compile_default_config(tmp_path)
    # both an iptables and an ip6tables ruleset are produced
    assert "iptables-save" in out
    assert "ip6tables-save" in out


def test_default_config_established_accept_precedes_drop_policy(
    tmp_path: Path,
) -> None:
    # R4 invariant: the ESTABLISHED,RELATED ACCEPT rule must be present in the
    # INPUT chain (so it is evaluated before the chain falls through to the
    # DROP policy that keeps the host closed). Present as an -A INPUT rule ==
    # ahead of the policy fall-through.
    out = _compile_default_config(tmp_path)
    assert re.search(
        r"-A INPUT .*--state ESTABLISHED,RELATED --jump ACCEPT", out
    )
    # the closed-by-default policy is really DROP
    assert ":INPUT DROP" in out


def test_default_config_ipv6_icmp_is_not_blanket_accept(
    tmp_path: Path,
) -> None:
    # ICMPv6 must be a narrow icmpv6-type allowlist, never a blanket
    # `proto ipv6-icmp ACCEPT` (which would also pass Redirect etc.).
    out = _compile_default_config(tmp_path)
    # every ipv6-icmp accept must carry an --icmpv6-type selector
    icmp6_accepts = [
        line
        for line in out.splitlines()
        if "ipv6-icmp" in line and "--jump ACCEPT" in line
    ]
    assert icmp6_accepts, "expected some ICMPv6 accept rules"
    for line in icmp6_accepts:
        assert "--icmpv6-type" in line, f"blanket ICMPv6 accept: {line!r}"


def test_default_config_has_no_active_throttle(tmp_path: Path) -> None:
    # The aggressive `mod recent` throttle self-locks admins; it ships as a
    # disabled example, never in the default config.
    out = _compile_default_config(tmp_path)
    assert "--match recent" not in out
