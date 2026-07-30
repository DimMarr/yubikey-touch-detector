# Fedora/COPR spec for yubikey-touch-detector, a from-scratch Rust rewrite of
# maximbaz/yubikey-touch-detector.
#
# Packaged following the Fedora Rust Packaging Guidelines' macro-based
# approach for a Rust *application* (own package name, not `rust-%%{crate}`
# library naming) - modeled on how CLI tools like ripgrep/eza/bat are
# structured there: %%cargo_prep / %%cargo_generate_buildrequires /
# %%cargo_build / %%cargo_install, ExclusiveArch %%{rust_arches}, BuildRequires
# on `rust-packaging`, and plain %%license/%%doc/%%{_bindir}/%%{_mandir}
# entries (no -devel subpackage, since there's nothing here for other crates
# to depend on).
#
# Macro verification notes (session that wrote this spec had network access):
#   - %%cargo_prep, %%cargo_build, %%cargo_install, %%cargo_test,
#     `ExclusiveArch: %%{rust_arches}`, `BuildRequires: rust-packaging`,
#     %%license/%%doc, %%{_bindir}, %%{_mandir}/man1/ and the
#     `%%autosetup -n %%{crate}-%%{version} -p1` prep pattern were all
#     cross-checked against a live mirror of the Fedora Rust packaging
#     guidelines (a real ripgrep-based example spec) - confirmed, not guessed.
#   - The `%%generate_buildrequires` / `%%cargo_generate_buildrequires` pair
#     below (Fedora's DynamicBuildRequires mechanism) is the standard,
#     widely-documented modern pattern for Rust specs, corroborated by
#     multiple independent sources, but was NOT seen verbatim in the single
#     guidelines mirror reachable in this session - flagging it as
#     high-confidence rather than directly-quoted-and-confirmed.
#   - `%%{_userunitdir}` (-> /usr/lib/systemd/user) is confirmed via the
#     Fedora Packaging:Systemd guidelines (used for user-session services
#     like gpg-agent, which is exactly this package's category).
#   - There is no `%%cargo_license_summary` (or similar) macro used here:
#     could not confirm its exact name/behavior from a reachable source, so
#     this spec sticks to the directly-confirmed `%%license` file list
#     instead of guessing at a macro that may not exist as imagined.

%bcond_without check

Name:           yubikey-touch-detector
Version:        0.1.0
Release:        1%{?dist}
Summary:        Detects when a YubiKey is waiting for a touch

# SPDX license expression (current Fedora licensing convention) - matches
# Cargo.toml's `license = "MIT OR Apache-2.0"` exactly.
License:        MIT OR Apache-2.0
URL:            https://github.com/DimMarr/yubikey-touch-detector
Source0:        https://github.com/DimMarr/yubikey-touch-detector/archive/v%{version}/%{name}-%{version}.tar.gz

ExclusiveArch:  %{rust_arches}

BuildRequires:  rust-packaging
# Renders yubikey-touch-detector.1.scd (scdoc source, checked into the repo)
# into a real roff man page during %%build - see below.
BuildRequires:  scdoc
# Provides %%{_userunitdir} (/usr/lib/systemd/user).
BuildRequires:  systemd-rpm-macros

# --- The whole point of this Rust rewrite, packaging-wise ---
# No BuildRequires/Requires on gpgme or gpgme-devel anywhere in this spec.
# The original Go yubikey-touch-detector links libgpgme via cgo to talk to
# gpg-agent, which is precisely why it was never packaged for Fedora: gpgme's
# build/link story is unfriendly to straightforward COPR/Fedora packaging.
# This rewrite reimplements the small slice of the Assuan protocol it needs
# in pure Rust (see src/assuan/ upstream), so gpgme never enters the
# dependency graph here at all.

%description
%{summary}.

yubikey-touch-detector watches for GPG, U2F/FIDO2, and HMAC-SECRET
operations that are waiting on a physical YubiKey touch, and reports that
state over a unix socket, D-Bus, libnotify desktop notifications, or stdout,
so other tools (status bars, notification widgets, etc.) can show a visible
indicator.

This package ships the systemd --user unit files that socket-activate the
detector, and a scdoc-rendered man page.

%prep
%autosetup -n %{name}-%{version} -p1
%cargo_prep

%generate_buildrequires
%cargo_generate_buildrequires

%build
%cargo_build
scdoc < %{name}.1.scd > %{name}.1

%install
%cargo_install

install -Dpm0644 %{name}.1 %{buildroot}%{_mandir}/man1/%{name}.1
install -Dpm0644 %{name}.service %{buildroot}%{_userunitdir}/%{name}.service
install -Dpm0644 %{name}.socket %{buildroot}%{_userunitdir}/%{name}.socket

%if %{with check}
%check
%cargo_test
%endif

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md service.conf.example
%{_bindir}/%{name}
%{_mandir}/man1/%{name}.1*
%{_userunitdir}/%{name}.service
%{_userunitdir}/%{name}.socket

%changelog
* Wed Jul 29 2026 Dimitri Martel <martel.dimitri34@gmail.com> - 0.1.0-1
- Initial packaging of the Rust rewrite (no gpgme/gpgme-devel dependency).
