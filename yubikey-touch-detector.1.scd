yubikey-touch-detector(1)

# NAME

yubikey-touch-detector - detect when a YubiKey is waiting for a touch

# SYNOPSIS

*yubikey-touch-detector* [options...]

# OPTIONS

*-v*, *--verbose*
	Enable debug logging.

*--libnotify*=<true|false>, *--no-libnotify*
	Show desktop notifications using libnotify. Enabled by default;
	*--no-libnotify* (or *--libnotify=false*) disables it.

*--stdout*
	Print notifications to stdout.

*--no-socket*
	Disable the unix socket notifier.

*--dbus*
	Enable the custom D-Bus server notifier.

*--version*
	Print version information and exit.

*-h*, *--help*
	Print help and exit.

# DESCRIPTION

*yubikey-touch-detector* detects when a YubiKey is waiting for a touch
confirmation. It is designed to be integrated with other UI components to
display a visible indicator.

# ENVIRONMENT

_YUBIKEY_TOUCH_DETECTOR_VERBOSE_
	Equivalent to specifying *-v*.

_YUBIKEY_TOUCH_DETECTOR_LIBNOTIFY_
	Sets the default for *--libnotify* (accepts true/false/yes/no/1/0,
	case-insensitive). An explicit *--libnotify* or *--no-libnotify* flag
	on the command line always takes precedence.

_YUBIKEY_TOUCH_DETECTOR_STDOUT_
	Equivalent to specifying *--stdout*.

_YUBIKEY_TOUCH_DETECTOR_NOSOCKET_
	Equivalent to specifying *--no-socket*.

_YUBIKEY_TOUCH_DETECTOR_DBUS_
	Equivalent to specifying *--dbus*.

# FILES

_$XDG_RUNTIME_DIR/yubikey-touch-detector.socket_
	The socket exposing events is created at this location, or taken
	over directly via systemd socket activation when launched through
	the bundled _yubikey-touch-detector.socket_ unit.

# EVENTS

The following events are emitted over the unix socket, as fixed 5-byte
ASCII frames:

_GPG_1_
	When a GPG operation starts waiting for a touch.

_GPG_0_
	When a GPG operation stops waiting for a touch.

_U2F_1_
	When a U2F/FIDO2 operation starts waiting for a touch.

_U2F_0_
	When a U2F/FIDO2 operation stops waiting for a touch.

_MAC_1_
	When a HMAC operation starts waiting for a touch.

_MAC_0_
	When a HMAC operation stops waiting for a touch.

The same state is also exposed as three D-Bus properties (*GPGState*,
*U2FState*, *HMACState*) on _io.github.dimmarr.YubikeyTouchDetector_ at
_/io/github/dimmarr/YubikeyTouchDetector_ when *--dbus* is enabled.

# SEE ALSO

ykman(1), pam_u2f(8)

# AUTHORS

Rust rewrite maintained by Dimitri Martel <https://github.com/DimMarr/yubikey-touch-detector>,
based on the design of the original Go implementation by Maxim Baz
<https://github.com/maximbaz/yubikey-touch-detector>.

# LICENSE

yubikey-touch-detector is distributed under the MIT OR Apache-2.0 license.
