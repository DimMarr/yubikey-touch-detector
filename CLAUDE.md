# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Detects when a YubiKey is waiting for a physical touch (GPG, SSH-forwarded
agent, U2F/FIDO2, HMAC challenge-response) and broadcasts that state over a
Unix socket, D-Bus, libnotify, and stdout, so status bars, desktop
notifications, or any other tool can show a visible indicator. It's a
single dependency-light Rust binary with no `libgpgme`/`gpgme-devel` C
dependency: the small slice of the Assuan protocol needed to talk to
`gpg-agent` is implemented natively in pure Rust — see `src/assuan/`.

## Commands

```sh
cargo build
cargo run -- -v                                    # run locally with debug logging
cargo test                                          # unit tests
dbus-run-session -- cargo test --all-features       # run with a real D-Bus session (see below)
cargo test <test_name>                              # run a single test
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
```

All three of `cargo fmt`, `cargo clippy --all-targets --all-features -- -D
warnings`, and `cargo test` must be clean before a PR — this is enforced in
CI (`.github/workflows/`), not aspirational.

**D-Bus tests**: `notifier::dbus` and `notifier::libnotify` tests connect to
a real D-Bus session bus. If none is reachable (minimal container/sandbox)
they `eprintln!` and skip rather than fail (see `session_bus_or_skip` in
those files) — a clean `cargo test` run doesn't prove those paths were
exercised. Use `dbus-run-session -- cargo test --all-features` (as CI does)
to actually exercise them.

PR titles are the squash-merge commit message — use Conventional Commits
style (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`).

## Architecture

**Detectors → Bus → Notifiers.** Each detector (`src/detector/*.rs`) runs
independently as a spawned tokio task and pushes `Message` (`src/message.rs`)
onto a shared `Bus` (`src/bus.rs`, a thin wrapper over
`tokio::sync::broadcast` chosen specifically so one slow notifier can't
head-of-line-block the others or the detectors). Every enabled notifier
(`src/notifier/*.rs`) subscribes independently and fans the same messages
out to its own sink. Wiring/spawning of both sides lives in `src/main.rs`.

**Wire format is a compatibility contract, not an implementation detail.**
`Message::wire_bytes()` produces fixed 5-byte ASCII frames (`GPG_1`,
`GPG_0`, `U2F_1`, `U2F_0`, `MAC_1`, `MAC_0`) that existing
py3status/waybar/i3status-rust integrations depend on. Don't change these
without recognizing it's a breaking change for downstream consumers. The
D-Bus service name is `io.github.dimmarr.YubikeyTouchDetector`
(reverse-DNS convention).

**Pure decision logic is kept separate from I/O** so it's unit-testable
without hardware or system services. Follow this shape when extending a
detector:
- `descriptor_declares_fido_ctaphid` (`src/detector/hid_descriptor.rs`) —
  pure HID report descriptor parsing, tested against fixture byte arrays.
- `resolve_agent_socket` (`src/assuan/discovery.rs`) — pure priority-chain
  socket resolution (`gpgconf` output > `$GNUPGHOME` > `$XDG_RUNTIME_DIR`)
  taking `Option` parameters instead of touching `std::env`/spawning
  `gpgconf` itself.

If new logic can be expressed as a pure function plus a thin async I/O
wrapper, prefer that split over mixing decisions into the I/O loop.

### The four detectors (`src/detector/`)

- **GPG** (`gpg.rs`): `gpg-agent` doesn't expose "waiting for touch"
  directly. Watches `private-keys-v1.d/*` for `OPEN` events via inotify (a
  hardware-shadowed key file gets opened right before gpg-agent talks to the
  card), then sends a `LEARN` command over Assuan with a short timeout — no
  reply in time means the card is assumed busy waiting for touch. Talks to
  gpg-agent via the hand-rolled client in `src/assuan/`.
- **SSH** (`ssh.rs`): proxies `$SSH_AUTH_SOCK` transparently (forwards
  traffic unmodified both ways) so agent-forwarded requests from a remote
  host also trigger the GPG detector's busy-check — reuses `gpg.rs`'s logic
  rather than duplicating it. Only started when GPG detection initializes
  successfully (`main.rs` gates SSH on `detector::gpg::try_init` returning
  `Some`).
- **U2F/FIDO2** (`u2f.rs` + `hid_descriptor.rs`): reads raw HID reports from
  FIDO hidraw device nodes, watching for `CTAPHID_MSG` with
  `SW_CONDITIONS_NOT_SATISFIED` (`0x6985`) or a `CTAPHID_KEEPALIVE` with
  `UP_NEEDED`. Candidate devices are identified by parsing the HID report
  descriptor for the FIDO usage page (`hid_descriptor.rs`).
- **HMAC** (`hmac.rs`): some HMAC challenge-response configs produce no
  readable HID traffic; instead the OTP/HMAC hidraw node vanishes from
  `/dev` while waiting for touch. Treats "one node vanished, others remain"
  as a touch wait and "whole set became empty" as unplugged.

### `src/assuan/` — minimal Assuan protocol client

Exists solely to avoid linking `libgpgme`. `mod.rs` implements just enough
of the newline-delimited Assuan protocol (greeting, command, `OK`/`ERR`
status line, no-op `INQUIRE` reply) to drive the GPG busy-check.
`discovery.rs` resolves the gpg-agent socket and home directory (`gpgconf`
first, falling back to `$GNUPGHOME`/`$XDG_RUNTIME_DIR` conventions).

### Shutdown (`src/shutdown.rs`)

A single root `tokio_util::sync::CancellationToken` (replacing the Go
original's per-task exit-channel registry) signals shutdown on
SIGINT/SIGTERM. Most tasks (debug/stdout/dbus/libnotify notifiers,
U2F/HMAC detectors) are simply abandoned at shutdown — matching the
original. Only tasks with cleanup that must complete first (unix socket
notifier removing its socket file, SSH proxy restoring the original socket)
are tracked as "critical tasks" and joined with a bounded 2s timeout in
`Shutdown::join_critical_tasks`, so a stuck cleanup can't hang shutdown
forever.

### Config (`src/config.rs`)

CLI flags (clap, `env` feature) > env vars (`YUBIKEY_TOUCH_DETECTOR_*`) >
defaults. `libnotify` defaults to **on**, so touch-wait desktop
notifications work without any flags. Boolean env vars accept
`true`/`false`, `yes`/`no`, `1`/`0`, `on`/`off` case-insensitively.

### Versioning (`build.rs`)

Embeds `git describe --tags --always --dirty` as
`YUBIKEY_TOUCH_DETECTOR_VERSION` at build time, falling back to
`.git-archival.txt`'s `export-subst`-expanded `describe-name:` line (for
GitHub source-tarball builds with no `.git` dir), then `"unknown"`.

## Packaging

Three native packaging paths are maintained in parallel and must stay in
sync when service files, assets, or the man page change: `[package.metadata.deb]`
in `Cargo.toml` (cargo-deb), `packaging/fedora/*.spec`, and
`packaging/arch/PKGBUILD`. Notably, cargo-deb does **not** package the man
page (ships as scdoc source, no build hook to render it to roff) while
Fedora/Arch both render it with `scdoc` at build time — see the comments in
`Cargo.toml`'s `[package.metadata.deb]` section before changing packaging
assets.
