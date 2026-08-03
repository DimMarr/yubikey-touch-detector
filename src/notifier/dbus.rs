//! Custom D-Bus server notifier: exposes the current touch-wait state as
//! three properties (`GPGState`/`U2FState`/`HMACState`, each `0` or `1`) on
//! a session-bus service, for other programs to read or observe via the
//! standard `org.freedesktop.DBus.Properties` mechanism (`PropertiesChanged`
//! signal, introspection).
//!
//! The service name `io.github.dimmarr.YubikeyTouchDetector` follows the
//! reverse-DNS convention for a GitHub-hosted project.

use tokio_util::sync::CancellationToken;
use tracing::{debug, error};
use zbus::connection::Builder;
use zbus::interface;

use crate::bus::Bus;
use crate::message::Message;

const DBUS_NAME: &str = "io.github.dimmarr.YubikeyTouchDetector";
const DBUS_PATH: &str = "/io/github/dimmarr/YubikeyTouchDetector";

struct TouchState {
    gpg_state: u32,
    u2f_state: u32,
    hmac_state: u32,
}

#[interface(name = "io.github.dimmarr.YubikeyTouchDetector")]
impl TouchState {
    #[zbus(property, name = "GPGState")]
    fn gpg_state(&self) -> u32 {
        self.gpg_state
    }

    #[zbus(property, name = "U2FState")]
    fn u2f_state(&self) -> u32 {
        self.u2f_state
    }

    #[zbus(property, name = "HMACState")]
    fn hmac_state(&self) -> u32 {
        self.hmac_state
    }
}

/// Starts the D-Bus service and updates its properties as `Message`s arrive
/// on `bus`, forever (or until `shutdown` is cancelled). Not a critical
/// shutdown task: there's no on-disk state to clean up, the session bus
/// connection is simply dropped.
pub async fn watch(bus: Bus, shutdown: CancellationToken) {
    let mut events = bus.subscribe();

    let connection = match connect().await {
        Ok(connection) => connection,
        Err(err) => {
            error!(%err, "cannot start the dbus notifier");
            return;
        }
    };

    let iface_ref = match connection
        .object_server()
        .interface::<_, TouchState>(DBUS_PATH)
        .await
    {
        Ok(iface_ref) => iface_ref,
        Err(err) => {
            error!(%err, "cannot access the dbus notifier's own interface");
            return;
        }
    };

    debug!(name = DBUS_NAME, path = DBUS_PATH, "dbus notifier ready");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            message = events.recv() => {
                let Some(message) = message else { return };
                apply(&iface_ref, message).await;
            }
        }
    }
}

async fn connect() -> zbus::Result<zbus::Connection> {
    Builder::session()?
        .name(DBUS_NAME)?
        .serve_at(
            DBUS_PATH,
            TouchState {
                gpg_state: 0,
                u2f_state: 0,
                hmac_state: 0,
            },
        )?
        .build()
        .await
}

async fn apply(iface_ref: &zbus::object_server::InterfaceRef<TouchState>, message: Message) {
    let value = u32::from(message.is_on());
    let mut state = iface_ref.get_mut().await;

    // The `#[interface]` macro derives each property's `*_changed` emitter
    // method name from the D-Bus property name (`GPGState` etc, via
    // `#[zbus(property, name = "...")]` above), splitting at every
    // uppercase letter - hence the odd `g_p_g_state_changed` shape rather
    // than the Rust method name `gpg_state`.
    let changed = match message {
        Message::GpgOn | Message::GpgOff => {
            state.gpg_state = value;
            state.g_p_g_state_changed(iface_ref.signal_emitter()).await
        }
        Message::U2fOn | Message::U2fOff => {
            state.u2f_state = value;
            state.u2_f_state_changed(iface_ref.signal_emitter()).await
        }
        Message::HmacOn | Message::HmacOff => {
            state.hmac_state = value;
            state
                .h_m_a_c_state_changed(iface_ref.signal_emitter())
                .await
        }
    };

    if let Err(err) = changed {
        error!(%err, "failed to emit PropertiesChanged for the dbus notifier");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use zbus::fdo::PropertiesProxy;

    // Registering `DBUS_NAME` on the session bus is process-wide contention:
    // only one test in this module may hold the name at a time.
    static NAME_LOCK: Mutex<()> = Mutex::const_new(());

    /// Every test needs a real session bus (e.g. via `dbus-run-session` in
    /// CI). Rather than failing where one genuinely isn't available (a
    /// minimal local sandbox), skip gracefully.
    async fn session_bus_or_skip() -> Option<zbus::Connection> {
        match zbus::Connection::session().await {
            Ok(connection) => Some(connection),
            Err(err) => {
                eprintln!("skipping dbus notifier test: no session bus available ({err})");
                None
            }
        }
    }

    async fn properties_proxy(connection: &zbus::Connection) -> PropertiesProxy<'static> {
        PropertiesProxy::builder(connection)
            .destination(DBUS_NAME)
            .unwrap()
            .path(DBUS_PATH)
            .unwrap()
            .build()
            .await
            .unwrap()
    }

    async fn read_property(props: &PropertiesProxy<'static>, name: &str) -> u32 {
        let value = props
            .get(
                zbus::names::InterfaceName::try_from(DBUS_NAME).unwrap(),
                name,
            )
            .await
            .unwrap();
        u32::try_from(value).unwrap()
    }

    #[tokio::test]
    async fn properties_reflect_bus_messages() {
        let _guard = NAME_LOCK.lock().await;
        let Some(client) = session_bus_or_skip().await else {
            return;
        };

        let bus = Bus::new();
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(bus.clone(), shutdown.clone()));

        // Give `watch` time to connect and register the name before the
        // test client queries it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let props = properties_proxy(&client).await;

        assert_eq!(read_property(&props, "GPGState").await, 0);
        assert_eq!(read_property(&props, "U2FState").await, 0);
        assert_eq!(read_property(&props, "HMACState").await, 0);

        bus.send(Message::GpgOn);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(read_property(&props, "GPGState").await, 1);

        bus.send(Message::GpgOff);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(read_property(&props, "GPGState").await, 0);

        bus.send(Message::U2fOn);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(read_property(&props, "U2FState").await, 1);

        bus.send(Message::HmacOn);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(read_property(&props, "HMACState").await, 1);

        shutdown.cancel();
        let _ = watcher.await;
    }

    #[tokio::test]
    async fn properties_changed_signal_is_emitted() {
        let _guard = NAME_LOCK.lock().await;
        let Some(client) = session_bus_or_skip().await else {
            return;
        };

        let bus = Bus::new();
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(bus.clone(), shutdown.clone()));

        tokio::time::sleep(Duration::from_millis(300)).await;
        let props = properties_proxy(&client).await;
        let mut changed_stream = props.receive_properties_changed().await.unwrap();

        bus.send(Message::GpgOn);

        let signal = tokio::time::timeout(Duration::from_secs(2), changed_stream.next())
            .await
            .expect("should receive a PropertiesChanged signal")
            .expect("stream should not have ended");
        let args = signal.args().unwrap();
        assert_eq!(args.interface_name.as_str(), DBUS_NAME);
        assert!(args.changed_properties.contains_key("GPGState"));

        shutdown.cancel();
        let _ = watcher.await;
    }
}
