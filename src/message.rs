//! Wire protocol for the unix socket notifier: every event is a fixed
//! 5-byte ASCII message broadcast to all connected consumers.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Message {
    GpgOn,
    GpgOff,
    U2fOn,
    U2fOff,
    HmacOn,
    HmacOff,
}

impl Message {
    /// The fixed 5-byte wire representation. Kept stable so existing
    /// consumers (py3status, waybar, ...) keep working.
    pub const fn wire_bytes(self) -> &'static [u8; 5] {
        match self {
            Message::GpgOn => b"GPG_1",
            Message::GpgOff => b"GPG_0",
            Message::U2fOn => b"U2F_1",
            Message::U2fOff => b"U2F_0",
            Message::HmacOn => b"MAC_1",
            Message::HmacOff => b"MAC_0",
        }
    }

    /// Whether this message signals the start (true) or end (false) of a
    /// touch wait, regardless of which detector emitted it.
    pub const fn is_on(self) -> bool {
        matches!(self, Message::GpgOn | Message::U2fOn | Message::HmacOn)
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(std::str::from_utf8(self.wire_bytes()).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_bytes_match_the_documented_protocol() {
        assert_eq!(Message::GpgOn.wire_bytes(), b"GPG_1");
        assert_eq!(Message::GpgOff.wire_bytes(), b"GPG_0");
        assert_eq!(Message::U2fOn.wire_bytes(), b"U2F_1");
        assert_eq!(Message::U2fOff.wire_bytes(), b"U2F_0");
        assert_eq!(Message::HmacOn.wire_bytes(), b"MAC_1");
        assert_eq!(Message::HmacOff.wire_bytes(), b"MAC_0");
    }

    #[test]
    fn is_on_reflects_touch_wait_start() {
        assert!(Message::GpgOn.is_on());
        assert!(Message::U2fOn.is_on());
        assert!(Message::HmacOn.is_on());
        assert!(!Message::GpgOff.is_on());
        assert!(!Message::U2fOff.is_on());
        assert!(!Message::HmacOff.is_on());
    }

    #[test]
    fn display_matches_wire_bytes() {
        assert_eq!(Message::GpgOn.to_string(), "GPG_1");
    }
}
