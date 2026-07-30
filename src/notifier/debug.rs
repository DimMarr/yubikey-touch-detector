//! Debug-log notifier: logs every [`Message`](crate::message::Message) at
//! debug level. In the original Go implementation this notifier only ran
//! when verbose logging was on; here that's a `main.rs`-level decision
//! (whether to spawn this at all, based on `Config.verbose`) rather than
//! something this module checks itself.
//!
//! Like the per-device U2F reader threads, this task is simply abandoned at
//! process exit - it's not part of the critical shutdown set (only the SSH
//! proxy and the unix socket notifier get graceful cleanup, matching the
//! original).

use tracing::debug;

use crate::bus::Bus;

/// Subscribes to `bus` and logs every message received, forever.
pub async fn watch(bus: Bus) {
    let mut events = bus.subscribe();
    while let Some(message) = events.recv().await {
        debug!(%message, "notifier/debug received a message");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use std::time::Duration;

    #[tokio::test]
    async fn consumes_messages_sent_on_the_bus_without_panicking() {
        let bus = Bus::new();
        let watcher = tokio::spawn(watch(bus.clone()));

        // Give the watcher a moment to subscribe before sending, since
        // `Bus::send` drops messages when there are no subscribers yet.
        tokio::time::sleep(Duration::from_millis(50)).await;

        bus.send(Message::GpgOn);
        bus.send(Message::GpgOff);

        // The loop never returns on its own (the bus is never dropped while
        // `bus` is held here); just prove the task is still alive and
        // hasn't panicked after processing both messages.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!watcher.is_finished());

        watcher.abort();
    }
}
