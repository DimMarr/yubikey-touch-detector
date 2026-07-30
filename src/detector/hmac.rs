//! Detects touch-waits on HMAC challenge-response operations.
//!
//! Unlike the other detectors, this isn't based on reading device traffic:
//! some YubiKey configurations cause the hidraw device node handling the
//! OTP/HMAC interface to disappear entirely from `/dev` while the key is
//! waiting for a touch on an HMAC challenge, and reappear once it's done.
//! A real YubiKey normally exposes *multiple* hidraw nodes at once (one per
//! interface), so "one of them vanished but others remain" is what signals
//! a touch wait - if the whole set becomes empty, the key itself was
//! unplugged, which is reported as "not waiting" (there's nothing to wait
//! on), not as a touch wait.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use inotify::{EventMask, Inotify, StreamExt, WatchMask};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::bus::Bus;
use crate::message::Message;

/// Newly created devices are given this long to finish initializing before
/// being checked, matching the original implementation.
const DEVICE_SETTLE_DELAY: Duration = Duration::from_secs(1);
/// After a device disappears, wait this long before deciding the new
/// on/off state, absorbing rapid back-to-back device churn.
const REMOVE_DEBOUNCE_DELAY: Duration = Duration::from_secs(1);

/// Watches `/dev` for YubiKey hidraw devices appearing and disappearing.
pub async fn watch(bus: Bus, shutdown: CancellationToken) {
    let inotify = match Inotify::init() {
        Ok(inotify) => inotify,
        Err(err) => {
            error!(%err, "cannot initialize inotify for the HMAC watcher");
            return;
        }
    };
    if let Err(err) = inotify
        .watches()
        .add("/dev", WatchMask::CREATE | WatchMask::DELETE)
    {
        error!(%err, "failed to establish a HMAC watch on /dev");
        return;
    }
    debug!("HMAC watcher is watching /dev for YubiKey devices");

    let mut stream = match inotify.into_event_stream([0u8; 4096]) {
        Ok(stream) => stream,
        Err(err) => {
            error!(%err, "failed to create inotify event stream for the HMAC watcher");
            return;
        }
    };

    let mut tracked_devices: HashSet<PathBuf> = HashSet::new();
    match std::fs::read_dir("/dev") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if is_yubikey_hidraw_device(&path) {
                    tracked_devices.insert(path);
                }
            }
        }
        Err(err) => error!(%err, "cannot list devices in /dev to find connected YubiKeys"),
    }

    let mut last_message = Message::HmacOff;
    let mut remove_deadline: Option<Instant> = None;

    loop {
        let debounce = async {
            match remove_deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            _ = shutdown.cancelled() => return,
            () = debounce, if remove_deadline.is_some() => {
                let new_message = if tracked_devices.is_empty() {
                    Message::HmacOff
                } else {
                    Message::HmacOn
                };
                if last_message != new_message {
                    bus.send(new_message);
                    last_message = new_message;
                }
                remove_deadline = None;
            }
            event = stream.next() => {
                match event {
                    Some(Ok(ev)) if ev.mask.contains(EventMask::CREATE) => {
                        // Any /dev creation cancels a pending debounce, not
                        // just a YubiKey one - matches the original.
                        remove_deadline = None;
                        if let Some(name) = ev.name {
                            let path = PathBuf::from("/dev").join(name);
                            tokio::time::sleep(DEVICE_SETTLE_DELAY).await;
                            if is_yubikey_hidraw_device(&path) {
                                tracked_devices.insert(path);
                                if last_message != Message::HmacOff {
                                    bus.send(Message::HmacOff);
                                    last_message = Message::HmacOff;
                                }
                            }
                        }
                    }
                    Some(Ok(ev)) if ev.mask.contains(EventMask::DELETE) => {
                        if let Some(name) = ev.name {
                            let path = PathBuf::from("/dev").join(name);
                            if tracked_devices.remove(&path) {
                                remove_deadline = Some(Instant::now() + REMOVE_DEBOUNCE_DELAY);
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        error!(%err, "inotify read error in the HMAC watcher");
                        return;
                    }
                    None => return,
                }
            }
        }
    }
}

fn is_yubikey_hidraw_device(device_path: &Path) -> bool {
    if !device_path.to_string_lossy().starts_with("/dev/hidraw") {
        return false;
    }
    let Some(name) = device_path.file_name() else {
        return false;
    };
    let uevent_path = Path::new("/sys/class/hidraw")
        .join(name)
        .join("device/uevent");
    match std::fs::read(&uevent_path) {
        Ok(contents) => uevent_declares_yubikey(&contents),
        Err(_) => false,
    }
}

/// Pure substring check, kept separate from any file I/O so it's
/// unit-testable against fixture `uevent` content.
fn uevent_declares_yubikey(uevent_contents: &[u8]) -> bool {
    String::from_utf8_lossy(uevent_contents)
        .to_lowercase()
        .contains("yubikey")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_yubikey_uevent_content() {
        let uevent = b"DRIVER=hid-generic\nHID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey OTP+FIDO+CCID\n";
        assert!(uevent_declares_yubikey(uevent));
    }

    #[test]
    fn is_case_insensitive() {
        assert!(uevent_declares_yubikey(b"HID_NAME=YUBIKEY 5"));
        assert!(uevent_declares_yubikey(b"hid_name=yubikey 5"));
    }

    #[test]
    fn rejects_unrelated_uevent_content() {
        let uevent = b"DRIVER=hid-generic\nHID_NAME=Some Other Keyboard\n";
        assert!(!uevent_declares_yubikey(uevent));
    }

    #[test]
    fn rejects_empty_content() {
        assert!(!uevent_declares_yubikey(b""));
    }

    #[test]
    fn non_hidraw_path_is_rejected_before_any_io() {
        assert!(!is_yubikey_hidraw_device(Path::new("/dev/not-hidraw")));
    }

    #[test]
    fn nonexistent_hidraw_device_is_not_a_yubikey() {
        assert!(!is_yubikey_hidraw_device(Path::new(
            "/dev/hidraw-does-not-exist-in-tests"
        )));
    }
}
