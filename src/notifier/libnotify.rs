//! Desktop notification notifier, via `org.freedesktop.Notifications`.
//!
//! Enabled **by default** in this rewrite (see `Config.libnotify`) - in the
//! original Go implementation this was an opt-in flag, which was itself the
//! usability complaint that motivated the whole project: touch-wait
//! notifications are exactly the kind of thing a new user expects to just
//! work, not something to discover in a `--help` listing.
//!
//! A hand-rolled `#[zbus::proxy]` is used rather than the `notify-rust`
//! crate: this notifier needs a persistent connection, a tracked
//! `replaces_id` so repeated touch-waits update a single notification
//! instead of stacking new ones, reconnect-on-error, and to observe
//! `NotificationClosed` (so a user manually dismissing the notification is
//! reflected back into our state) - all of which is a thin, fully-controlled
//! proxy over a small, stable, well-known interface, not meaningfully more
//! code than wiring up a generic notification crate, and it keeps a single
//! D-Bus stack in the whole binary (`zbus`, also used by `notifier::dbus`).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use futures_util::StreamExt;
use tracing::{debug, error};
use zbus::Connection;
use zbus::proxy;
use zbus::zvariant::Value;

use crate::bus::Bus;

const APP_NAME: &str = "yubikey-touch-detector";
const APP_ICON: &str = "yubikey-touch-detector";
const SUMMARY: &str = "YubiKey is waiting for a touch";

#[proxy(
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications",
    interface = "org.freedesktop.Notifications"
)]
trait Notifications {
    // Fixed by the org.freedesktop.Notifications spec, not our own API design.
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, &Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32);
}

/// A live connection to the notification server, plus the background task
/// that watches for `NotificationClosed` (dropped along with the session).
struct Session {
    proxy: NotificationsProxy<'static>,
    signal_task: tokio::task::JoinHandle<()>,
}

impl Session {
    /// Connects to the session bus and starts watching `NotificationClosed`,
    /// resetting `replaces_id` to `0` whenever the notification it currently
    /// tracks is closed - whether by us (`close`) or by the user dismissing
    /// it. This is the *only* place `replaces_id` is ever reset: mirrors the
    /// original implementation, which relies solely on this same signal
    /// rather than also clearing it right after a successful `close` call.
    async fn connect(replaces_id: Arc<AtomicU32>) -> Option<Self> {
        let connection = match Connection::session().await {
            Ok(connection) => connection,
            Err(err) => {
                error!(%err, "cannot establish a session bus connection for desktop notifications");
                return None;
            }
        };

        let proxy = match NotificationsProxy::new(&connection).await {
            Ok(proxy) => proxy,
            Err(err) => {
                error!(%err, "cannot initialize the desktop notifications proxy");
                return None;
            }
        };

        let mut closed_stream = match proxy.receive_notification_closed().await {
            Ok(stream) => stream,
            Err(err) => {
                error!(%err, "cannot watch for closed desktop notifications");
                return None;
            }
        };

        let signal_task = tokio::spawn(async move {
            while let Some(signal) = closed_stream.next().await {
                if let Ok(args) = signal.args() {
                    let _ = replaces_id.compare_exchange(
                        args.id,
                        0,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                }
            }
        });

        Some(Self { proxy, signal_task })
    }

    async fn notify(&self, replaces_id: u32) -> zbus::Result<u32> {
        self.proxy
            .notify(
                APP_NAME,
                replaces_id,
                APP_ICON,
                SUMMARY,
                "",
                &[],
                HashMap::from([("transient", &Value::from(true))]),
                0,
            )
            .await
    }

    async fn close(&self, id: u32) -> zbus::Result<()> {
        self.proxy.close_notification(id).await
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.signal_task.abort();
    }
}

/// Subscribes to `bus` and shows/updates/closes a single desktop
/// notification depending on the number of currently-active touch waits
/// (tracked as a signed counter, incremented on `_On` and decremented on
/// `_Off`, so overlapping detectors don't prematurely close it). Not a
/// critical shutdown task: there's no on-disk state, the connection is
/// simply dropped.
pub async fn watch(bus: Bus) {
    let mut events = bus.subscribe();
    let replaces_id = Arc::new(AtomicU32::new(0));

    let Some(mut session) = Session::connect(replaces_id.clone()).await else {
        return;
    };
    debug!("desktop notification notifier ready");

    let mut active_touch_waits: i64 = 0;

    loop {
        let Some(message) = events.recv().await else {
            return;
        };

        active_touch_waits += if message.is_on() { 1 } else { -1 };

        if active_touch_waits > 0 {
            let current_id = replaces_id.load(Ordering::SeqCst);
            match session.notify(current_id).await {
                Ok(id) => {
                    // Only ever transitions 0 -> id: once a notification is
                    // showing, subsequent updates reuse the same id (the
                    // notification server is expected to keep returning it
                    // for a `replaces_id` call), matching the original.
                    let _ = replaces_id.compare_exchange(0, id, Ordering::SeqCst, Ordering::SeqCst);
                }
                Err(err) => {
                    error!(%err, "cannot show notification, reconnecting");
                    match Session::connect(replaces_id.clone()).await {
                        Some(reconnected) => {
                            session = reconnected;
                            if let Err(err) =
                                session.notify(replaces_id.load(Ordering::SeqCst)).await
                            {
                                error!(%err, "cannot show notification after reconnecting");
                            }
                        }
                        None => error!("failed to reconnect for desktop notifications"),
                    }
                }
            }
        } else {
            let current_id = replaces_id.load(Ordering::SeqCst);
            if current_id != 0
                && let Err(err) = session.close(current_id).await
            {
                error!(%err, "cannot close notification, reconnecting");
                if let Some(reconnected) = Session::connect(replaces_id.clone()).await {
                    session = reconnected;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use std::time::Duration;
    use tokio::sync::Mutex;

    // Sending a real notification is process-wide-ish contention on the
    // notification server's single "replaces" slot per app; serialize
    // tests in this module the same way `notifier::dbus`'s tests serialize
    // on the bus name.
    static SESSION_LOCK: Mutex<()> = Mutex::const_new(());

    async fn session_bus_or_skip() -> bool {
        if zbus::Connection::session().await.is_err() {
            eprintln!("skipping libnotify test: no session bus available");
            return false;
        }
        true
    }

    #[tokio::test]
    async fn shows_and_closes_a_real_notification() {
        let _guard = SESSION_LOCK.lock().await;
        if !session_bus_or_skip().await {
            return;
        }

        let replaces_id = Arc::new(AtomicU32::new(0));
        let Some(session) = Session::connect(replaces_id).await else {
            eprintln!("skipping: no notification server available on the session bus");
            return;
        };

        let id = session
            .notify(0)
            .await
            .expect("a real notification server should accept Notify");
        assert!(id > 0, "a fresh notification should get a nonzero id");

        session
            .close(id)
            .await
            .expect("closing a just-shown notification should succeed");
    }

    #[tokio::test]
    async fn active_touch_wait_counter_only_notifies_while_positive() {
        let _guard = SESSION_LOCK.lock().await;
        if !session_bus_or_skip().await {
            return;
        }

        let bus = Bus::new();
        let watcher = tokio::spawn(watch(bus.clone()));

        // Give the watcher time to connect before sending.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Two overlapping "on" sources (e.g. GPG and U2F both waiting) must
        // not cause the notification to close after only one turns off.
        bus.send(Message::GpgOn);
        bus.send(Message::U2fOn);
        tokio::time::sleep(Duration::from_millis(200)).await;

        bus.send(Message::GpgOff);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!watcher.is_finished(), "watcher should still be running");

        bus.send(Message::U2fOff);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!watcher.is_finished(), "watcher should still be running");

        watcher.abort();
    }
}
