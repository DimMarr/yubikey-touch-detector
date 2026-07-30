//! Detects touch-waits on U2F/FIDO2 operations by reading raw HID reports
//! from FIDO hidraw devices and watching for the CTAPHID frames that
//! signal "user presence needed":
//!
//! - A classic U2F response (`CTAPHID_MSG`) whose status word is
//!   `SW_CONDITIONS_NOT_SATISFIED` (0x6985).
//! - A FIDO2 keepalive (`CTAPHID_KEEPALIVE`) with status `UP_NEEDED`.
//!
//! See <https://fidoalliance.org/specs/u2f-specs-master/inc/u2f_hid.h> and
//! <https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html>.

use std::io::Read;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use inotify::{EventMask, Inotify, StreamExt, WatchMask};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use crate::bus::Bus;
use crate::detector::hid_descriptor::is_fido_u2f_device;
use crate::message::Message;

/// Devices are given this long to finish initializing before being
/// re-checked, matching the original implementation.
const DEVICE_INIT_DELAY: Duration = Duration::from_secs(1);
/// After a touch-needed message, wait this long without further such
/// messages before declaring the touch wait over.
const OFF_DELAY_AFTER_TOUCH: u16 = 2000;
/// After any *other* message, a much shorter grace period - just enough to
/// absorb intermediate pings without flapping ON/OFF.
const OFF_DELAY_AFTER_OTHER: u16 = 200;

// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f_hid.h and its
// backwards-compatible successor, the FIDO2 CTAP HID transport spec.
const TYPE_INIT: u8 = 0x80;
const CTAPHID_MSG: u8 = TYPE_INIT | 0x03;
const CTAPHID_KEEPALIVE: u8 = TYPE_INIT | 0x3b;
const STATUS_UPNEEDED: u8 = 0x02;

// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f.h
const U2F_SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;

/// Watches `/dev` for newly connected FIDO U2F/CTAP hidraw devices (as well
/// as ones already present at startup) and spawns a reader for each.
///
/// Deviates from the original implementation in one deliberate way: newly
/// created devices are checked concurrently (each on its own spawned task,
/// after the same 1s settle delay) rather than sequentially in the single
/// event-processing loop. The original blocks that whole loop for 1s per
/// `/dev` creation event, serializing unrelated devices for no correctness
/// reason; nothing here depends on that ordering.
pub async fn watch(bus: Bus, shutdown: CancellationToken) {
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_fido_u2f_device(&path) {
                spawn_device_reader(path, bus.clone());
            }
        }
    } else {
        error!("cannot list devices in /dev to find connected YubiKeys");
    }

    let inotify = match Inotify::init() {
        Ok(inotify) => inotify,
        Err(err) => {
            error!(%err, "cannot initialize inotify for the U2F watcher");
            return;
        }
    };
    if let Err(err) = inotify.watches().add("/dev", WatchMask::CREATE) {
        error!(%err, "failed to establish a U2F watch on /dev");
        return;
    }
    debug!("U2F watcher is watching /dev for new devices");

    let mut stream = match inotify.into_event_stream([0u8; 4096]) {
        Ok(stream) => stream,
        Err(err) => {
            error!(%err, "failed to create inotify event stream for the U2F watcher");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            event = stream.next() => {
                match event {
                    Some(Ok(ev)) if ev.mask.contains(EventMask::CREATE) => {
                        if let Some(name) = ev.name {
                            let path = PathBuf::from("/dev").join(name);
                            let bus = bus.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(DEVICE_INIT_DELAY).await;
                                if is_fido_u2f_device(&path) {
                                    spawn_device_reader(path, bus);
                                }
                            });
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        error!(%err, "inotify read error in the U2F watcher");
                        return;
                    }
                    None => return,
                }
            }
        }
    }
}

fn spawn_device_reader(path: PathBuf, bus: Bus) {
    tokio::task::spawn_blocking(move || run_device_reader(&path, &bus));
}

/// Blocking per-device reader loop. Not part of the graceful-shutdown
/// join set (same as the original implementation): it's a blocking read on
/// a hidraw device with no reliable way to interrupt it early other than
/// process exit, so it's simply abandoned at shutdown like the original's
/// per-device goroutines are.
fn run_device_reader(path: &Path, bus: &Bus) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => {
            error!(path = %path.display(), %err, "cannot open device to run U2F watcher");
            return;
        }
    };

    let mut last_message = Message::U2fOff;
    let mut next_timeout = PollTimeout::NONE;
    let mut buf = [0u8; 64];

    loop {
        let fd = file.as_fd();
        let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
        match poll(&mut fds, next_timeout) {
            Ok(0) => {
                // Timed out waiting for another report: the touch wait (or
                // grace period) is over.
                if last_message != Message::U2fOff {
                    bus.send(Message::U2fOff);
                    last_message = Message::U2fOff;
                }
                next_timeout = PollTimeout::NONE;
                continue;
            }
            Ok(_) => {}
            Err(err) => {
                debug!(path = %path.display(), %err, "poll error while watching U2F device");
                if last_message != Message::U2fOff {
                    bus.send(Message::U2fOff);
                }
                return;
            }
        }

        let bytes_read = match (&file).read(&mut buf) {
            Ok(0) | Err(_) => {
                // Device unplugged.
                if last_message != Message::U2fOff {
                    bus.send(Message::U2fOff);
                }
                return;
            }
            Ok(n) => n,
        };

        let (is_u2f, is_fido2) = classify_ctaphid_report(&buf[..bytes_read]);

        if is_u2f || is_fido2 {
            if last_message != Message::U2fOn {
                bus.send(Message::U2fOn);
                last_message = Message::U2fOn;
            }
            next_timeout = PollTimeout::from(OFF_DELAY_AFTER_TOUCH);
        } else {
            next_timeout = PollTimeout::from(OFF_DELAY_AFTER_OTHER);
        }
    }
}

/// Pure CTAPHID frame classification, kept separate from any device I/O so
/// it's unit-testable against fixture byte arrays.
fn classify_ctaphid_report(payload: &[u8]) -> (bool, bool) {
    let cmd = payload.get(4).copied().unwrap_or(0);
    let val1b = payload.get(7).copied().unwrap_or(0);
    let val2b = (u16::from(val1b) << 8) | u16::from(payload.get(8).copied().unwrap_or(0));

    let is_u2f = cmd == CTAPHID_MSG && val2b == U2F_SW_CONDITIONS_NOT_SATISFIED;
    let is_fido2 = cmd == CTAPHID_KEEPALIVE && val1b == STATUS_UPNEEDED;
    (is_u2f, is_fido2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(cmd: u8, byte7: u8, byte8: u8) -> [u8; 64] {
        let mut payload = [0u8; 64];
        payload[4] = cmd;
        payload[7] = byte7;
        payload[8] = byte8;
        payload
    }

    #[test]
    fn classic_u2f_conditions_not_satisfied_is_touch_needed() {
        let payload = report(CTAPHID_MSG, 0x69, 0x85);
        assert_eq!(classify_ctaphid_report(&payload), (true, false));
    }

    #[test]
    fn fido2_keepalive_up_needed_is_touch_needed() {
        let payload = report(CTAPHID_KEEPALIVE, STATUS_UPNEEDED, 0x00);
        assert_eq!(classify_ctaphid_report(&payload), (false, true));
    }

    #[test]
    fn u2f_msg_with_a_different_status_word_is_not_touch_needed() {
        let payload = report(CTAPHID_MSG, 0x90, 0x00); // SW_NO_ERROR
        assert_eq!(classify_ctaphid_report(&payload), (false, false));
    }

    #[test]
    fn keepalive_with_a_different_status_is_not_touch_needed() {
        let payload = report(CTAPHID_KEEPALIVE, 0x01, 0x00); // STATUS_PROCESSING
        assert_eq!(classify_ctaphid_report(&payload), (false, false));
    }

    #[test]
    fn unrelated_command_is_not_touch_needed() {
        let payload = report(0x00, 0x69, 0x85);
        assert_eq!(classify_ctaphid_report(&payload), (false, false));
    }

    #[test]
    fn short_payload_does_not_panic() {
        assert_eq!(classify_ctaphid_report(&[]), (false, false));
        assert_eq!(
            classify_ctaphid_report(&[0, 0, 0, 0, CTAPHID_MSG]),
            (false, false)
        );
    }
}
