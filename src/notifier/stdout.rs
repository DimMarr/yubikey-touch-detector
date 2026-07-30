//! Stdout notifier: prints every [`Message`](crate::message::Message) as its
//! own line, using the wire-format string (`GPG_1`, `U2F_0`, ...) via
//! `Message`'s `Display` impl - matching the original Go implementation's
//! `fmt.Println(value)`.
//!
//! Same "no shutdown handling" reasoning as `notifier::debug`: this task is
//! abandoned at process exit rather than joined during graceful shutdown.

use crate::bus::Bus;

/// Subscribes to `bus` and prints each message received, forever.
pub async fn watch(bus: Bus) {
    let mut events = bus.subscribe();
    while let Some(message) = events.recv().await {
        println!("{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use std::time::Duration;

    #[tokio::test]
    async fn consumes_messages_sent_on_the_bus_without_panicking() {
        // Capturing real stdout output would require redirecting a
        // process-global fd, which is more machinery than this notifier's
        // one-line `println!` warrants (see `Message`'s own tests for
        // coverage that the printed string matches the wire format). What's
        // worth verifying here is the bus wiring: this loop actually
        // subscribes and keeps consuming without panicking.
        let bus = Bus::new();
        let watcher = tokio::spawn(watch(bus.clone()));

        // Give the watcher a moment to subscribe before sending, since
        // `Bus::send` drops messages when there are no subscribers yet.
        tokio::time::sleep(Duration::from_millis(50)).await;

        bus.send(Message::U2fOn);
        bus.send(Message::U2fOff);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!watcher.is_finished());

        watcher.abort();
    }
}
