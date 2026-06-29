# RPM spec for the ferm Python port (pyferm).
#
# This is the RPM counterpart of the native .deb under packaging/deb/: a
# noarch python package that drops in for the upstream Perl "ferm" (same
# /usr/bin/ferm and /usr/bin/import-ferm), ships a starter
# /etc/ferm/ferm.conf and a systemd unit that is deliberately NOT enabled on
# install (anti-lockout), and recommends the optional integrations.
#
# Build model (mirrors the .deb seed-and-rewrite): the spec carries a 0.0.0
# version seed and the build driver injects the real version from the release
# tag with `rpmbuild --define "_ferm_version <v>"`. The same value is fed to
# hatch-vcs through SETUPTOOLS_SCM_PRETEND_VERSION, since rpmbuild unpacks a
# source tarball with no .git for hatch-vcs to read. Source0 is a FULL source
# archive (e.g. `git archive`), not a pyproject sdist: the spec installs files
# from packaging/deb/ (the shipped ferm.conf and unit), which a wheel/sdist
# does not carry. The driver lives in a nox session (build_rpm), parallel to
# build_deb; it is not part of this spec.

# Version seed; the build driver overrides _ferm_version from the release tag.
# This is the rpm-sanitized version (pre-release markers as '~', no '-').
%global ferm_version %{?_ferm_version}%{!?_ferm_version:0.0.0}
# Full PEP 440 version handed to hatch-vcs (rpmbuild unpacks a tarball with no
# .git for it to read).  It must stay PEP 440 -- the rpm '~' pre-release form
# is not valid there -- so it is a separate input; it defaults to the rpm
# version, which is identical on a clean release tag that needs no '~'.
%global scm_version %{?_ferm_scm_version}%{!?_ferm_scm_version:%{ferm_version}}
# pyproject distribution name (pyproject [project].name) and import package.
%global dist_name ferm
%global import_name pyferm

Name:           pyferm
Version:        %{ferm_version}
Release:        1%{?dist}
Summary:        For Easy Rule Making -- iptables/nftables frontend (Python port)

License:        GPL-2.0-or-later
URL:            https://github.com/6RUN0/ferm
Source0:        %{dist_name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  systemd-rpm-macros

# ferm shells out to iptables/iptables-restore (and ip6tables); nft is the
# opt-in backend, dnspython powers @resolve(), etckeeper versions the config.
Requires:       iptables
Recommends:     nftables
Recommends:     python3-dnspython
Recommends:     etckeeper

# Drop-in for the upstream Perl "ferm": satisfy ferm dependencies and refuse
# to coexist (both own /usr/bin/ferm). This mirrors the .deb's
# Provides/Conflicts/Replaces. Obsoletes is deliberately NOT set: the Perl
# ferm shares this name, and an unversioned `Obsoletes: ferm` next to
# `Provides: ferm` risks self-obsoletion, while a versioned one cannot match
# (the Perl ferm's 2.x version sorts above this alpha). Migration from an
# installed Perl ferm is therefore an explicit `dnf swap ferm pyferm` until a
# distro-coordinated Obsoletes is arranged.
Provides:       ferm = %{version}-%{release}
Conflicts:      ferm

%description
ferm reads firewall rules from a structured, high-level configuration
language and translates them into iptables/ip6tables (or native nftables)
rules, applying them atomically via iptables-restore. It also handles the
arptables and ebtables families.

This package is the Python port of ferm; it drops in for the upstream Perl
"ferm" package (same /usr/bin/ferm and /usr/bin/import-ferm commands).

A starter /etc/ferm/ferm.conf is shipped but the systemd unit is NOT enabled
on install (anti-lockout): review the rules, add your services under
/etc/ferm/ferm.d/, then "systemctl enable --now ferm".

%prep
%autosetup -n %{dist_name}-%{version}

%generate_buildrequires
# hatch-vcs reads the version from SETUPTOOLS_SCM_PRETEND_VERSION here too:
# %%pyproject_buildrequires builds the project metadata, which resolves the
# dynamic version.
export SETUPTOOLS_SCM_PRETEND_VERSION=%{scm_version}
%pyproject_buildrequires

%build
export SETUPTOOLS_SCM_PRETEND_VERSION=%{scm_version}
%pyproject_wheel

%install
%pyproject_install
# Record the importable package, its dist-info and the console-entry scripts
# (ferm, import-ferm) into %%{pyproject_files}; non-python artifacts below are
# listed explicitly in %%files.
%pyproject_save_files %{import_name}

# Starter config as a conffile, plus the drop-in fragment directory. The
# source basename (ferm.conf) becomes /etc/ferm/ferm.conf; single source of
# truth is packaging/deb/ferm.conf, shared with the .deb.
install -Dpm0644 packaging/deb/ferm.conf %{buildroot}%{_sysconfdir}/ferm/ferm.conf
install -dm0755 %{buildroot}%{_sysconfdir}/ferm/ferm.d

# systemd unit, installed under the name `ferm` (shared with the .deb).
install -Dpm0644 packaging/deb/debian/pyferm.ferm.service %{buildroot}%{_unitdir}/ferm.service

# The throttle example under an examples/ subdir (not bare %%doc, which would
# flatten it into the docdir root); ferm.conf points users at
# /usr/share/doc/pyferm/examples/, matching the .deb layout.
install -Dpm0644 packaging/deb/examples/ssh-throttle.conf.example \
    %{buildroot}%{_pkgdocdir}/examples/ssh-throttle.conf.example

# No %pre legacy-config migration (unlike the .deb preinst): rpm's
# %config(noreplace) does not honor a file pre-placed in %pre on a fresh
# install -- it overwrites it with the packaged default -- so the deb trick of
# seeding the conffile early cannot work here. It is also a Debian-ism: the
# Fedora/RHEL Perl ferm already owns /etc/ferm/ferm.conf (the same path this
# package uses), so there is no cross-path /etc/ferm.conf to adopt. On the
# supported path, %config(noreplace) protects an admin-edited config across
# upgrades, and a `dnf swap ferm pyferm` carries the existing file over per
# rpm's standard config-on-erase handling (kept as .rpmsave if modified).

%pre
# Posture-downgrade SNAPSHOT (paired with the %post breadcrumb). Note this is a
# DIFFERENT use of %pre than the config migration declined above: the
# %config(noreplace) objection there is that rpm overwrites a file pre-placed in
# %pre on a fresh install -- but a /run marker is NOT a packaged file, so that
# objection does not apply, and %pre is exactly the right hook here. It runs
# before the new package's files and, on a swap/obsolete, before the old
# package's %postun strips its enablement artifacts, so it is the only point
# that reliably observes a prior ferm's posture.
#
# Gated to a fresh install ($1 = 1; rpm passes $1 >= 2 on upgrade), matching the
# %post fresh-install gate; a `dnf swap ferm pyferm` installs pyferm fresh
# ($1 = 1). Record the marker if ANY enablement regime shows the old ferm was
# on: the systemd wants symlink, the SysV rc?.d start links (a sysvinit host the
# wants-symlink probe alone would miss), or systemctl is-enabled (best-effort,
# failure ignored; unreliable in a chroot, hence only supplementary).
if [ "$1" = 1 ]; then
    WANTS=/etc/systemd/system/multi-user.target.wants/ferm.service
    MARKER=/run/pyferm-legacy-was-enabled
    if [ -L "$WANTS" ] || ls /etc/rc[2-5].d/S??ferm >/dev/null 2>&1 \
       || systemctl is-enabled ferm >/dev/null 2>&1; then
        : > "$MARKER" 2>/dev/null || :
    fi
fi

%post
# Anti-lockout: a firewall must NOT apply rules or auto-enable on install, so
# %%systemd_post is intentionally NOT used (it would run preset-based enable).
# Only tell systemd the new unit exists. daemon-reload runs unconditionally
# (install AND upgrade): the unit file may have changed on an upgrade too.
systemctl daemon-reload >/dev/null 2>&1 || :
# Posture-downgrade breadcrumb (mirror of the .deb postinst): if the previous
# ferm unit was ENABLED (observed file-wise by the wants symlink, the SysV
# rc?.d start links, or the %pre snapshot marker -- all reliable in a
# container/chroot), warn durably that this package does not auto-enable, so
# the firewall will not come up on the next reboot.
#
# Gated to FRESH INSTALL only ($1 = 1; rpm passes $1>=2 on upgrade). On a fresh
# install a pre-existing wants symlink genuinely means a prior (Perl) ferm was
# enabled -- a real posture downgrade. On an UPGRADE the wants symlink is just
# pyferm's own unit that the admin enabled after the first install, which is
# indistinguishable from the legacy signal and would re-fire a FALSE warning
# every time. A `dnf swap ferm pyferm` installs pyferm fresh ($1 = 1), so the
# legitimate "prior ferm enabled" signal is preserved.
if [ "$1" = 1 ]; then
    WANTS=/etc/systemd/system/multi-user.target.wants/ferm.service
    MARKER=/run/pyferm-legacy-was-enabled
    BREADCRUMB=%{_sysconfdir}/ferm/POSTURE-DOWNGRADE.README
    if [ ! -e "$BREADCRUMB" ] && { [ -L "$WANTS" ] || [ -e "$MARKER" ] \
       || ls /etc/rc[2-5].d/S??ferm >/dev/null 2>&1; }; then
        mkdir -p %{_sysconfdir}/ferm
        # The scriptlet runs without `set -e` (rpm idiom), so guard the
        # breadcrumb write: a failed mktemp must not leave $tmp empty and let
        # the cat/mv operate on a bogus path. Bail out (exit 0) rather than
        # continue silently -- the breadcrumb is best-effort, not a hard error.
        tmp="$(mktemp "${BREADCRUMB}.XXXXXX")" || exit 0
        [ -n "$tmp" ] || exit 0
        cat > "$tmp" <<'EOF'
PYFERM POSTURE DOWNGRADE -- ACTION REQUIRED

The previous ferm service was enabled on this host, but the pyferm package
installs its systemd unit WITHOUT enabling or starting it (anti-lockout).

As a result your firewall will NOT be applied automatically on the next
reboot. Review /etc/ferm/ferm.conf (and /etc/ferm/ferm.d/), then opt in:

    systemctl enable --now ferm

Delete this file once you have re-enabled the service (or decided not to).
EOF
        mv -f "$tmp" "$BREADCRUMB"
        echo "pyferm: previous ferm was enabled; this package does NOT auto-enable" \
             "the unit. See $BREADCRUMB." >&2
    fi
    # Consume the %pre snapshot marker once read (best-effort). It is in /run
    # and self-clears on reboot, but drop it now to avoid a stale re-read.
    rm -f "$MARKER" 2>/dev/null || :
fi

%preun
# Stop and disable on final removal only (no-op on upgrade). No restart on
# upgrade: a firewall reload is the admin's explicit action, not a side effect.
%systemd_preun ferm.service

%postun
%systemd_postun ferm.service
if [ "$1" -eq 0 ]; then
    # Final removal: drop the posture-downgrade breadcrumb so it does not
    # orphan in /etc/ferm (mirror of the .deb postrm purge).
    rm -f %{_sysconfdir}/ferm/POSTURE-DOWNGRADE.README
fi

%files -f %{pyproject_files}
%license COPYING
%doc README.md
%dir %{_pkgdocdir}/examples
%{_pkgdocdir}/examples/ssh-throttle.conf.example
# The console entry-point scripts are listed explicitly -- the recommended
# Fedora idiom. %%pyproject_save_files captures bindir scripts ONLY when invoked
# with the +auto (or +bindir) argument; without it (as here, where it is passed
# just the import package name) it never captures them, so these lines must STAY.
# A future maintainer who wants auto-capture must add +auto/+bindir to
# %%pyproject_save_files AND remove these two lines together -- doing one without
# the other either double-lists (build fails) or drops the executables.
%{_bindir}/ferm
%{_bindir}/import-ferm
%dir %{_sysconfdir}/ferm
%dir %{_sysconfdir}/ferm/ferm.d
%config(noreplace) %{_sysconfdir}/ferm/ferm.conf
%{_unitdir}/ferm.service

%changelog
* Sun Jun 28 2026 Boris Talovikov <boris@talovikov.ru> - 0.0.0-1
- Initial native RPM packaging of the ferm Python port (seed entry; the build
  driver rewrites the version from the release tag).
- Drop-in for the upstream Perl "ferm" (Provides/Conflicts: ferm).
- Ships a starter /etc/ferm/ferm.conf and a systemd unit that is NOT enabled
  on install (anti-lockout); recommends nftables, dnspython and etckeeper.
