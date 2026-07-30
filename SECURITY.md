# Security Policy

## Scope

`yubikey-touch-detector` is a local touch-detection helper: it observes
existing GPG/SSH/U2F/HMAC traffic and device state to figure out when a
YubiKey is waiting for a touch, and broadcasts that as a simple on/off
signal over a Unix socket and D-Bus. It is not itself a security boundary or
an authentication mechanism, and it doesn't hold or manage any secrets.

That said, two parts of it sit directly on trust-sensitive paths and bugs
there are taken seriously:

- The **SSH detector** ([`src/detector/ssh.rs`](src/detector/ssh.rs))
  transparently proxies the `$SSH_AUTH_SOCK` Unix socket — all forwarded
  ssh-agent traffic passes through this code.
- The **GPG detector** ([`src/detector/gpg.rs`](src/detector/gpg.rs)) and
  the underlying [Assuan client](src/assuan/mod.rs) talk directly to the
  `gpg-agent` control socket.

A bug that corrupted, misdirected, or leaked traffic passing through either
of these would be a real problem even though the daemon's own job is just
touch detection, so please report issues here with that in mind, even if
they seem minor.

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/DimMarr/yubikey-touch-detector/security/advisories/new)
rather than in a public issue.

This is a solo-maintained project, so response times are best-effort, not
covered by a formal SLA — but you should expect an acknowledgement within a
few days. Please include:

- A description of the issue and its potential impact.
- Steps to reproduce, if applicable.
- The affected version and how it was installed (COPR / AUR / `.deb` /
  `cargo install`).

## Non-security bugs

For anything that isn't a security concern, please use the regular
[issue tracker](https://github.com/DimMarr/yubikey-touch-detector/issues)
instead.
