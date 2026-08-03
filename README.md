# yubikey-touch-detector

Detects when a YubiKey is waiting for a physical touch, and broadcasts that
state to other programs (status bars, desktop notifications) over a Unix
socket and D-Bus.

## Why this exists

Touch-protected YubiKey operations — GPG signing/decryption, SSH
authentication, U2F/FIDO2, HMAC challenge-response — block silently while
waiting for a physical touch, with no indication to the user beyond a
blinking LED they may not be looking at. `yubikey-touch-detector` watches
for that wait across all four mechanisms and broadcasts a simple on/off
signal that status bars, desktop notifications, or any other tool can react
to.

It ships as a single, dependency-light Rust binary with no
`libgpgme`/`gpgme-devel` C dependency: the small slice of the Assuan
protocol needed to talk to `gpg-agent` is implemented natively in pure Rust
(see [How it works](#how-it-works)), so it installs cleanly on Fedora,
Debian/Ubuntu, Arch, or via `cargo install` anywhere else, with no C build
toolchain or native library required.

Desktop notifications via libnotify are on by default, so a touch-wait
indicator works out of the box.

The detection techniques themselves aren't arbitrary choices — they're
dictated by how Linux and the YubiKey actually expose this state: the Assuan
protocol, hidraw ioctls, sysfs uevents, and ssh-agent socket forwarding.

## Installation

### Fedora (COPR)

Once published, a COPR repository will provide native packages:

```sh
sudo dnf copr enable dimmarr/yubikey-touch-detector
sudo dnf install yubikey-touch-detector
```

### Debian / Ubuntu (.deb)

Once release builds are published, download the `.deb` for your architecture
from the [GitHub Releases](https://github.com/DimMarr/yubikey-touch-detector/releases)
page and install it with `apt`, so dependencies are resolved automatically:

```sh
sudo apt install ./yubikey-touch-detector_*.deb
```

### Arch Linux (AUR)

Once published to the AUR, install with your AUR helper of choice:

```sh
yay -S yubikey-touch-detector
```

### From source (works today, any distro)

This always works, regardless of packaging status, and requires only a Rust
toolchain (no `gpgme-devel` or other C dependencies):

```sh
cargo install --locked --git https://github.com/DimMarr/yubikey-touch-detector
```

## Usage

The recommended way to run `yubikey-touch-detector` is as a systemd user
service, activated on demand by its socket unit:

```sh
systemctl --user daemon-reload
systemctl --user enable --now yubikey-touch-detector.socket
```

Configuration is via environment variables read from
`$XDG_CONFIG_HOME/yubikey-touch-detector/service.conf` (see
[`service.conf.example`](service.conf.example) for a template with every
variable documented and its default value).

To run it directly instead (e.g. for testing):

```sh
yubikey-touch-detector -v
```

See [`yubikey-touch-detector.1`](yubikey-touch-detector.1.scd) for the full
man page.

### CLI flags / environment variables

CLI flags take precedence over environment variables, which take precedence
over the defaults below.

| Flag | Env var | Default | Description |
| --- | --- | --- | --- |
| `-v`, `--verbose` | `YUBIKEY_TOUCH_DETECTOR_VERBOSE` | off | Enable debug logging. |
| `--libnotify` / `--no-libnotify` | `YUBIKEY_TOUCH_DETECTOR_LIBNOTIFY` | **on** | Show desktop notifications using libnotify. `--no-libnotify` (or `--libnotify=false`) disables it regardless of the env var. |
| `--stdout` | `YUBIKEY_TOUCH_DETECTOR_STDOUT` | off | Print notifications to stdout. |
| `--no-socket` | `YUBIKEY_TOUCH_DETECTOR_NOSOCKET` | off (socket is on by default) | Disable the unix socket notifier. |
| `--dbus` | `YUBIKEY_TOUCH_DETECTOR_DBUS` | off | Enable the D-Bus server notifier (`io.github.dimmarr.YubikeyTouchDetector`). |

Boolean env vars accept `true`/`false`, `yes`/`no`, `1`/`0`, `on`/`off`
(case-insensitive).

## How it works

Each detector runs independently and reports its state onto a shared
in-process event bus, which the enabled notifiers (unix socket, D-Bus,
libnotify, stdout) fan out to.

### GPG (Assuan busy-check)

`gpg-agent` doesn't expose "waiting for touch" directly, so the GPG detector
uses a busy-check heuristic: it watches the
`private-keys-v1.d/*` files that back a hardware-shadowed key for `OPEN`
events (gpg-agent opens one of these right before talking to the card), then
sends a `LEARN` command to gpg-agent over the Assuan protocol with a short
timeout. If the command doesn't complete in time, the card is assumed busy —
almost always because it's waiting for a touch.

This talks to gpg-agent using a small, pure-Rust Assuan client
([`src/assuan/mod.rs`](src/assuan/mod.rs)) rather than linking `libgpgme`.
Assuan is a simple newline-delimited text protocol — a greeting on connect, a
command line, and a terminating `OK`/`ERR` status line — so a minimal client
implementing just enough of it (plus a no-op reply to `INQUIRE`) removes the
`gpgme-devel` C build dependency entirely, which is what keeps this binary
free of a C build toolchain requirement (see
[Why this exists](#why-this-exists)). Socket and home-directory discovery
(`gpgconf` first, falling back to `$GNUPGHOME`/`$XDG_RUNTIME_DIR`
conventions) lives in [`src/assuan/discovery.rs`](src/assuan/discovery.rs).

See [`src/detector/gpg.rs`](src/detector/gpg.rs).

### SSH (forwarded-agent proxy)

When `ssh` forwards agent requests from a remote host back to a local
`ssh-agent` (typically gpg-agent acting as one), that traffic goes over
`$SSH_AUTH_SOCK` and never touches the files the GPG detector watches. So
this detector transparently proxies the `$SSH_AUTH_SOCK` Unix socket,
forwarding all traffic unmodified in both directions, and triggers the same
Assuan busy-check on any traffic seen — reusing the GPG detector's logic
rather than duplicating it.

See [`src/detector/ssh.rs`](src/detector/ssh.rs).

### U2F / FIDO2 (HID report reading)

FIDO U2F/CTAP2 authenticators signal "user presence needed" directly in
their HID traffic. This detector reads raw HID reports from FIDO hidraw
device nodes and watches for the two frame types that mean "waiting for a
touch":

- A classic U2F response (`CTAPHID_MSG`) with status word
  `SW_CONDITIONS_NOT_SATISFIED` (`0x6985`).
- A FIDO2 keepalive (`CTAPHID_KEEPALIVE`) with status `UP_NEEDED`.

Candidate devices are identified by parsing their HID report descriptor for
the FIDO usage page and CTAPHID usage
([`src/detector/hid_descriptor.rs`](src/detector/hid_descriptor.rs)).

See [`src/detector/u2f.rs`](src/detector/u2f.rs).

### HMAC challenge-response (device-presence watching)

Some YubiKey configurations don't produce readable HID traffic for HMAC
challenge-response touch waits; instead, the hidraw device node for the
OTP/HMAC interface disappears from `/dev` while the key is waiting for a
touch, and reappears once it's done. Since a YubiKey normally exposes
multiple hidraw nodes at once (one per interface), this detector treats "one
node vanished but others remain" as a touch wait, and "the whole set became
empty" as the key simply being unplugged.

See [`src/detector/hmac.rs`](src/detector/hmac.rs).

## Integrating with other UI components

Both integration surfaces below are stable, so status-bar integrations
(py3status, waybar, i3status-rust, etc.) can build on them without worrying
about the wire format or socket path changing between releases.

### Unix socket

A socket is created at `$XDG_RUNTIME_DIR/yubikey-touch-detector.socket` (or
taken over directly via systemd socket activation, when launched through the
bundled [`yubikey-touch-detector.socket`](yubikey-touch-detector.socket)
unit). Every connected client receives every event, broadcast as a fixed
5-byte ASCII frame:

| Message | Meaning |
| --- | --- |
| `GPG_1` | A GPG operation started waiting for a touch. |
| `GPG_0` | A GPG operation stopped waiting for a touch. |
| `U2F_1` | A U2F/FIDO2 operation started waiting for a touch. |
| `U2F_0` | A U2F/FIDO2 operation stopped waiting for a touch. |
| `MAC_1` | An HMAC operation started waiting for a touch. |
| `MAC_0` | An HMAC operation stopped waiting for a touch. |

See [`src/message.rs`](src/message.rs) and
[`src/notifier/unix_socket.rs`](src/notifier/unix_socket.rs).

### D-Bus

When `--dbus` is enabled, the current state is also exposed as three
properties on a session-bus service, readable or observable (via the
standard `org.freedesktop.DBus.Properties` `PropertiesChanged` signal) like
any other D-Bus property:

- **Name**: `io.github.dimmarr.YubikeyTouchDetector`
- **Path**: `/io/github/dimmarr/YubikeyTouchDetector`
- **Properties**: `GPGState`, `U2FState`, `HMACState` (each `0` or `1`)

See [`src/notifier/dbus.rs`](src/notifier/dbus.rs).

## FAQ

### How do I configure my YubiKey to require a physical touch?

Use [`ykman`](https://docs.yubico.com/software/yubikey/tools/ykman/) (the
answer here doesn't depend on which touch-detector implementation you run):

```sh
ykman openpgp keys set-touch sig on
ykman openpgp keys set-touch enc on
ykman openpgp keys set-touch aut on
```

`on` requires a touch every time; `cached` requires one but caches the
result for 15 seconds so a batch of operations only needs one touch;
`cached-fixed` is the same but the setting can no longer be changed back to
`off` without a factory reset. After changing touch policy, unplug and
replug the YubiKey for the change to take effect.

## License

Licensed under either of

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
