# Contributing

Thanks for considering a contribution to `yubikey-touch-detector`.

## Dev setup

```sh
cargo build
cargo run -- -v            # run locally with debug logging
cargo test
```

`cargo test` covers the pure decision-logic and protocol code without any
hardware or system services. A handful of tests do talk to a real D-Bus
session bus (the `notifier::dbus` and `notifier::libnotify` modules) — those
connect to the session bus at test time and, if none is reachable (e.g. in a
minimal CI container or sandbox with no `dbus-daemon`/`dbus-broker`
running), they print a message with `eprintln!` explaining why and return
early instead of failing. See `session_bus_or_skip` in
[`src/notifier/dbus.rs`](src/notifier/dbus.rs) and
[`src/notifier/libnotify.rs`](src/notifier/libnotify.rs) for the exact
mechanism. This means a clean `cargo test` run doesn't by itself guarantee
those code paths were exercised — if you change D-Bus-facing behavior, run
the tests in an environment with a working session bus (any normal desktop
Linux session has one) and check the output isn't full of skip messages.

## Before opening a PR

All of the following must be clean — this is the actual current state of the
repository, not an aspiration:

```sh
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## PR titles

This repository squash-merges pull requests using the PR title as the final
commit message, so title quality matters. Use
[Conventional Commits](https://www.conventionalcommits.org/) style:
`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`, etc.

## Filing a good bug report

Please include:

- The output of running with `-v` attached (verbose/debug logging).
- Your YubiKey model.
- Your Linux distribution.
- How you installed the binary (COPR / AUR / `.deb` / `cargo install` /
  other).

## Engineering approach

Pure decision logic — parsing, state machines, path resolution — is kept
separate from I/O, so it's unit-testable without any YubiKey hardware or
system services attached. When extending a detector or adding a new one,
follow this pattern rather than mixing decisions into the async I/O loop
that drives them. Two concrete examples worth reading before adding
similar logic:

- `descriptor_declares_fido_ctaphid` in
  [`src/detector/hid_descriptor.rs`](src/detector/hid_descriptor.rs): a pure
  function that walks a HID report descriptor byte slice and decides
  whether it declares a FIDO CTAPHID usage, tested against fixture byte
  arrays with no device I/O involved.
- `resolve_agent_socket` in
  [`src/assuan/discovery.rs`](src/assuan/discovery.rs): pure priority-chain
  logic (`gpgconf` output > `$GNUPGHOME` > `$XDG_RUNTIME_DIR` convention)
  that takes its inputs as plain `Option` parameters instead of reading
  `std::env`/spawning `gpgconf` itself, so the resolution logic is testable
  without touching the real environment or having `gpgconf` installed.

If a change can be expressed as one of these pure functions plus a thin I/O
wrapper around it, prefer that shape.
