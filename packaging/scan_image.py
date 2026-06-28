"""
Native-library CVE scanner for the standalone-binary build image.

``pip-audit`` (the ``audit`` nox session) covers only the Python dependency
graph.  It does NOT see the native shared objects Nuitka freezes into the
standalone dist -- the OpenSSL / libffi / xz / bzip2 / mpdecimal copies pulled
from the pinned manylinux build image.  The OpenSSL bundled by manylinux_2_28
is the EOL 1.1.x series, so a CVE landing there arrives with NO push that a
code-time gate would ever see -- a SCHEDULED scan is the only trigger that
matches how this class of problem shows up (the same rationale ``audit.yml``
records for pip-audit).

This driver scans the SAME digest-pinned image ``build.py`` compiles in: the
digest is read from ``packaging/Dockerfile`` (single source of truth, never
duplicated), so a base-image bump retargets the scan automatically.  Trivy's
findings are then filtered down to the rpm packages that actually provide a
bundled ``.so`` -- the soname->package map is derived FROM the image at scan
time via ``rpm -qf``, so it tracks the image rather than a hand-maintained
list.  A fixable CVE in the image's GCC / devtoolset (which is NOT shipped)
therefore does not red the gate; only a CVE in a library that really rides
inside the dist does.

``--ignore-unfixed`` makes the trigger ACTIONABLE: it fires only when a fix
exists -- exactly when a rebuild on a patched base image would resolve it.  A
reviewed ``.trivyignore`` at the repo root records any acknowledged finding.

Run via ``uv run nox -s image_scan`` (needs docker + network); wired into the
weekly ``audit.yml`` so a red scan escalates to a tracking issue.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import TypedDict, cast


class Finding(TypedDict):
    """One filtered vulnerability in a bundled native library."""

    id: str
    pkg: str
    installed: str
    fixed: str
    severity: str
    title: str


_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _REPO_ROOT / "packaging" / "Dockerfile"
_IGNOREFILE = _REPO_ROOT / ".trivyignore"

#: Wall-clock ceiling for each ``docker``/Trivy subprocess.  A hung image pull
#: or vuln-DB fetch would otherwise stall up to the CI job limit; a timeout is
#: turned into a fail-closed ``SystemExit`` (a red gate), never a silent pass.
_SUBPROCESS_TIMEOUT_SECONDS = 900

#: Trivy scanner, pinned by version tag AND digest (mirrors how the build
#: image and the GitHub Actions are pinned).  Bump deliberately after checking
#: the current release (``gh api repos/aquasecurity/trivy/releases/latest``)
#: and re-resolving the digest (``docker buildx imagetools inspect``), never
#: from memory -- CLI flags drift across versions (``--vuln-type`` became
#: ``--pkg-types``).  Verified against 0.71.2.
_TRIVY_IMAGE = (
    "aquasec/trivy:0.71.2@sha256:"
    "f5d0e600ecda7449e2a9b272805aef698631d3bb3f3a739a750de2c6819acdc9"
)

#: SONAME stems of the third-party native libraries Nuitka bundles into the
#: dist.  This is the CVE-relevant subset of ``build.py``'s
#: ``_ALLOWED_SO_NAMES`` -- the ``lib*.so*`` entries, with the stdlib
#: extension modules (``_ssl.so`` etc., which carry no rpm identity) excluded.
#: ``test_packaging_scan`` asserts this set stays in lockstep with the build
#: allow-list, so the two cannot drift silently.
_BUNDLED_LIB_STEMS: frozenset[str] = frozenset(
    {
        "libbz2",
        "libcrypto",
        "libffi",
        "liblzma",
        "libmpdec",
        "libssl",
    },
)

#: Stems whose bundled ``.so`` is source-built in the image and therefore has
#: no rpm owner, so the probe legitimately resolves no package for them.  The
#: per-stem coverage check exempts exactly these; an empty default means
#: *every* stem must map to a package or the scan reds.  Listing a stem here is
#: a documented, reviewed exception -- not a silent coverage gap.
#:
#: Currently EMPTY: on ``manylinux_2_28`` all six stems resolve via
#: ``ldconfig`` to a system rpm (verified at scan time).  ``libmpdec`` is the
#: subtle case -- it resolves to the system ``mpdecimal`` rpm
#: (``/lib64/libmpdec.so.3``), but Nuitka actually freezes a *source-built*
#: ``/opt/_internal/.../libmpdec.so.4`` that no rpm owns.  The scan therefore
#: tracks the system mpdecimal rather than the exact shipped copy (a known
#: image-vs-dist divergence recorded in the roadmap); it is NOT a no-rpm stem.
_KNOWN_NO_RPM_STEMS: frozenset[str] = frozenset()

#: ``FROM [--flag...] <ref>@sha256:<64-hex>`` -- the digest-pinned base-image
#: line.  Optional leading flags (e.g. ``--platform=linux/amd64``) are skipped
#: so a flagged but still digest-pinned ``FROM`` is recognized rather than
#: mistaken for unpinned.
_FROM_RE = re.compile(
    r"^FROM\s+(?:--\S+\s+)*(?P<ref>\S+@sha256:[0-9a-f]{64})\b",
    re.MULTILINE,
)


def lib_stems_from_allow_list(allowed: frozenset[str]) -> frozenset[str]:
    """
    Derive bundled-library SONAME stems from a ``.so`` allow-list.

    A pure helper shared with the consistency test: keep only the
    ``lib*.so*`` third-party libraries (drop stdlib extension modules like
    ``_ssl.so`` / ``array.so`` that have no rpm package), and reduce each to
    its stem (``libssl.so.1`` -> ``libssl``).  The result is what the scanner
    maps to rpm packages, so the test can prove it equals the bundled set.
    """
    stems: set[str] = set()
    for name in allowed:
        if name.startswith("lib") and ".so" in name:
            stems.add(name.split(".so", 1)[0])
    return frozenset(stems)


def read_pinned_image(dockerfile: Path) -> str:
    """
    Return the digest-pinned base-image ref from ``packaging/Dockerfile``.

    The build image is the single source of truth for the bundled native
    libraries, so the scan reads its digest here rather than duplicating it.
    Returns the FIRST digest-pinned ``FROM`` -- the single-stage build image
    where the bundled ``.so`` originate; revisit this choice if the Dockerfile
    ever becomes multi-stage with a non-bundling first stage.  Fails CLOSED
    (``SystemExit``) if no ``FROM ...@sha256:`` line is present -- an unpinned
    image must never be scanned silently against a moving tag.
    """
    text = dockerfile.read_text(encoding="utf-8")
    match = _FROM_RE.search(text)
    if match is None:
        raise SystemExit(
            f"no digest-pinned FROM line in {dockerfile} -- refusing to scan "
            "an unpinned image",
        )
    return match.group("ref")


def package_probe_script(stems: frozenset[str]) -> str:
    """
    Render the in-image shell that maps each bundled SONAME stem to its rpm.

    For every stem, resolve the real library path from ``ldconfig -p`` and ask
    ``rpm -qf`` which package owns it.  Output is ``stem<TAB>package`` pairs,
    one per line, deduplicated -- the stem column lets the driver assert that
    *every* expected stem resolved to an owner (a stem that silently stops
    resolving is a coverage hole, not a clean scan).

    A stem whose library is source-built (no rpm owner) emits no line for that
    stem; the driver reds unless the stem is a reviewed ``_KNOWN_NO_RPM_STEMS``
    exception.  Note the converse subtlety: if a source-built ``.so`` shares a
    soname with a *system* rpm library (``libmpdec`` resolves to system
    ``mpdecimal`` while Nuitka ships its own ``libmpdec.so.4``), the probe maps
    the stem to the system package -- so the scan tracks the system copy, not
    the exact shipped one.  This image-vs-dist divergence is recorded in the
    roadmap.
    """
    # Stems are fixed literals (``lib*``) with no shell/regex metacharacters,
    # so a plain space-joined ``for`` list is injection-safe.
    stem_list = " ".join(sorted(stems))
    return (
        f"for stem in {stem_list}; do\n"
        '  ldconfig -p | sed -n "s|.*=> \\(.*/${stem}\\.so.*\\)|\\1|p" |'
        " while read -r p; do\n"
        "    name=$(rpm -qf --qf '%{NAME}' \"$p\" 2>/dev/null) &&"
        ' [ -n "$name" ] && printf \'%s\\t%s\\n\' "$stem" "$name"\n'
        "  done\n"
        "done | sort -u\n"
    )


def resolve_shipped_packages(
    image: str,
    stems: frozenset[str],
) -> frozenset[str]:
    """
    Map the bundled SONAMEs to their rpm package names inside ``image``.

    Runs the probe script in a throwaway container of the pinned image.  Fails
    CLOSED on incomplete coverage: it reds unless EVERY stem resolved to a
    package (or is a reviewed ``_KNOWN_NO_RPM_STEMS`` exception).  A partial
    resolution would silently shrink the downstream filter and drop the missing
    library's findings -- a broken probe (rpm/ldconfig layout changed) or a
    base-image bump that renames a package must red, not pass.
    """
    try:
        run = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                image,
                "sh",
                "-c",
                package_probe_script(stems),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(f"package probe timed out in {image}: {exc}") from exc
    if run.returncode != 0:
        raise SystemExit(
            f"package probe failed in {image}:\n{run.stdout}{run.stderr}",
        )
    resolved_stems: set[str] = set()
    packages: set[str] = set()
    for line in run.stdout.splitlines():
        stem, tab, package = line.partition("\t")
        if not tab or not stem.strip() or not package.strip():
            continue
        resolved_stems.add(stem.strip())
        packages.add(package.strip())
    missing = stems - resolved_stems - _KNOWN_NO_RPM_STEMS
    if missing:
        raise SystemExit(
            f"package probe resolved no rpm owner for {sorted(missing)} in "
            f"{image} -- the rpm/ldconfig layout changed (a stem stopped "
            "resolving); refusing to scan with partial coverage that would "
            "silently drop that library's findings",
        )
    if not packages:
        raise SystemExit(
            f"package probe found no rpm owners for {sorted(stems)} in "
            f"{image} -- refusing to scan with an empty filter (would green "
            "the gate unconditionally)",
        )
    return frozenset(packages)


def run_trivy(target_image: str, ignorefile: Path | None) -> object:
    """
    Scan ``target_image`` with the pinned Trivy and return parsed JSON.

    Reports only FIXED (``--ignore-unfixed``) HIGH/CRITICAL OS-package
    vulnerabilities -- the actionable rebuild trigger.  Trivy itself always
    exits 0 (``--exit-code 0``); the gate decision is made here after filtering
    to shipped packages, not by Trivy's blanket exit code.  Trivy fetches the
    remote image and its vuln DB directly (no docker socket needed).
    """
    cmd = ["docker", "run", "--rm"]
    trivy_args = [
        "image",
        "--quiet",
        "--format",
        "json",
        "--ignore-unfixed",
        "--pkg-types",
        "os",
        "--scanners",
        "vuln",
        "--severity",
        "HIGH,CRITICAL",
        "--exit-code",
        "0",
    ]
    if ignorefile is not None and ignorefile.is_file():
        mount = f"{ignorefile.resolve()}:/work/.trivyignore:ro"
        cmd += ["-v", mount]
        trivy_args += ["--ignorefile", "/work/.trivyignore"]
    cmd += [_TRIVY_IMAGE, *trivy_args, target_image]
    try:
        run = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(
            f"trivy scan of {target_image} timed out: {exc}",
        ) from exc
    if run.returncode != 0 or not run.stdout.strip():
        raise SystemExit(
            f"trivy scan of {target_image} failed "
            f"(rc={run.returncode}):\n{run.stdout}{run.stderr}",
        )
    try:
        parsed: object = json.loads(run.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"trivy produced unparsable JSON: {exc}\n{run.stdout[:2000]}",
        ) from exc
    # Schema canary: a clean scan still emits a ``Results`` array.  An absent
    # or non-list ``Results`` means the JSON shape changed (a Trivy bump) --
    # fail CLOSED rather than let ``filter_findings`` read it as zero findings
    # and green the gate on an unrecognized shape.
    if not isinstance(_get(parsed, "Results"), list):
        keys = (
            sorted(cast("dict[str, object]", parsed))
            if isinstance(parsed, dict)
            else type(parsed).__name__
        )
        raise SystemExit(
            "trivy JSON has no 'Results' list -- output schema changed "
            f"(re-validate the parser on the Trivy bump); got: {keys}",
        )
    _assert_vuln_schema(parsed)
    return parsed


def _assert_vuln_schema(report: object) -> None:
    """
    Fail CLOSED if Trivy reports vulnerabilities in an unrecognized shape.

    The outer ``Results`` canary above does not guarantee the INNER fields
    ``filter_findings`` keys on (``Vulnerabilities``, ``PkgName``).  If a Trivy
    bump renamed those, ``filter_findings`` would walk the report, match
    nothing, and silently return zero findings -- greening the gate on real
    CVEs.  So: if the report carries any vulnerability entry at all, at least
    one must expose a ``PkgName`` string; otherwise the inner schema drifted
    and the scan reds rather than passing on a filter that can no longer see.
    A genuinely clean scan carries no vulnerability entries and passes.
    """
    results = _get(report, "Results")
    if not isinstance(results, list):
        return
    saw_vulnerability = False
    for result in cast("list[object]", results):
        vulns = _get(result, "Vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in cast("list[object]", vulns):
            if not isinstance(vuln, dict):
                continue
            saw_vulnerability = True
            pkg = cast("dict[str, object]", vuln).get("PkgName")
            if isinstance(pkg, str):
                return  # recognized shape -- canary satisfied
    if saw_vulnerability:
        raise SystemExit(
            "trivy reported vulnerabilities but none carried a 'PkgName' "
            "string -- the inner JSON schema changed (re-validate "
            "filter_findings on the Trivy bump); refusing to scan with a "
            "filter that would silently drop every finding",
        )


def _as_str(value: object, default: str = "?") -> str:
    """Return ``value`` if it is a string, else ``default`` (defensive)."""
    return value if isinstance(value, str) else default


def _get(obj: object, key: str) -> object:
    """
    Read ``key`` from ``obj`` if it is a mapping, else ``None``.

    Trivy's JSON is external, untyped data; this localizes the one cast needed
    to read a key off a value the type-checker only knows as ``object``.
    """
    if isinstance(obj, dict):
        return cast("dict[str, object]", obj).get(key)
    return None


def filter_findings(report: object, shipped: frozenset[str]) -> list[Finding]:
    """
    Keep only vulnerabilities in a package that actually ships a bundled .so.

    Walks Trivy's ``Results[].Vulnerabilities[]`` defensively (the JSON is
    external, untyped data, so every level is ``isinstance``-narrowed) and
    retains a finding only when its ``PkgName`` is in the shipped-package set.
    This is the noise filter that turns a whole-image scan into a precise
    "does a library we ship have a fixable CVE" signal.
    """
    findings: list[Finding] = []
    results = _get(report, "Results")
    if not isinstance(results, list):
        return findings
    for result in cast("list[object]", results):
        vulns = _get(result, "Vulnerabilities")
        if not isinstance(vulns, list):
            continue
        for vuln in cast("list[object]", vulns):
            pkg = _get(vuln, "PkgName")
            if not isinstance(pkg, str) or pkg not in shipped:
                continue
            findings.append(
                Finding(
                    id=_as_str(_get(vuln, "VulnerabilityID")),
                    pkg=pkg,
                    installed=_as_str(_get(vuln, "InstalledVersion")),
                    fixed=_as_str(_get(vuln, "FixedVersion")),
                    severity=_as_str(_get(vuln, "Severity")),
                    title=_as_str(_get(vuln, "Title"), ""),
                ),
            )
    findings.sort(key=lambda f: (f["pkg"], f["id"]))
    return findings


def format_findings(findings: list[Finding]) -> str:
    """Render the filtered findings as a compact, one-per-line report."""
    if not findings:
        return "no fixable HIGH/CRITICAL CVEs in bundled native libraries"
    header = (
        f"{len(findings)} fixable HIGH/CRITICAL CVE(s) in bundled libraries "
        "-- rebuild on a patched base image:"
    )
    rows = [
        f"  [{f['severity']}] {f['id']}  {f['pkg']} "
        f"{f['installed']} -> fixed {f['fixed']}"
        + (f"  {f['title']}" if f["title"] else "")
        for f in findings
    ]
    return "\n".join([header, *rows])


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the scanner command line."""
    parser = argparse.ArgumentParser(prog="scan_image.py")
    parser.add_argument("--dockerfile", type=Path, default=_DOCKERFILE)
    parser.add_argument("--ignorefile", type=Path, default=_IGNOREFILE)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Resolve the pinned image, scan it, and red the gate on a finding."""
    args = _parse_args(argv)
    image = read_pinned_image(args.dockerfile)
    sys.stdout.write(f"scanning pinned build image: {image}\n")
    shipped = resolve_shipped_packages(image, _BUNDLED_LIB_STEMS)
    sys.stdout.write(f"shipped native-lib packages: {sorted(shipped)}\n")
    report = run_trivy(image, args.ignorefile)
    findings = filter_findings(report, shipped)
    sys.stdout.write(format_findings(findings) + "\n")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
