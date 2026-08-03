//! Fan-out of [`Message`] from detectors to notifiers.
//!
//! Built on `tokio::sync::broadcast` rather than a bounded channel per
//! notifier: a per-notifier bounded channel would head-of-line block once
//! any one notifier's buffer fills, stalling every detector before the
//! others can be notified. `broadcast` decouples this: a lagging receiver
//! only misses its own messages (and logs it), it never blocks the sender
//! or the other receivers.

use tokio::sync::broadcast;
use tracing::warn;

use crate::message::Message;

/// Generous relative to how infrequently touch events fire; this is not a
/// tuning-critical value.
const CHANNEL_CAPACITY: usize = 32;

#[derive(Clone)]
pub struct Bus {
    tx: broadcast::Sender<Message>,
}

impl Bus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }

    /// Broadcast a message to every current subscriber. Never blocks: if
    /// there are no subscribers yet, the message is simply dropped.
    pub fn send(&self, message: Message) {
        let _ = self.tx.send(message);
    }

    pub fn subscribe(&self) -> BusReceiver {
        BusReceiver {
            rx: self.tx.subscribe(),
        }
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

/// Thin wrapper over `broadcast::Receiver` that turns a `Lagged` error into
/// a logged skip instead of terminating the notifier's receive loop.
pub struct BusReceiver {
    rx: broadcast::Receiver<Message>,
}

impl BusReceiver {
    /// Waits for the next message, transparently skipping past any messages
    /// that were dropped because this receiver fell behind.
    pub async fn recv(&mut self) -> Option<Message> {
        loop {
            match self.rx.recv().await {
                Ok(message) => return Some(message),
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "notifier fell behind, skipping missed messages");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn broadcast_reaches_all_subscribers() {
        let bus = Bus::new();
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();

        bus.send(Message::GpgOn);

        assert_eq!(a.recv().await, Some(Message::GpgOn));
        assert_eq!(b.recv().await, Some(Message::GpgOn));
    }

    #[tokio::test]
    async fn send_without_subscribers_does_not_panic_or_block() {
        let bus = Bus::new();
        bus.send(Message::U2fOff);
    }

    #[tokio::test]
    async fn a_slow_subscriber_does_not_lose_messages_for_others() {
        let bus = Bus::new();
        let mut fast = bus.subscribe();
        let _slow = bus.subscribe(); // never polled

        for _ in 0..(CHANNEL_CAPACITY * 2) {
            bus.send(Message::HmacOn);
        }

        // The fast subscriber must still be able to observe messages even
        // though the slow one never drained its queue.
        assert_eq!(fast.recv().await, Some(Message::HmacOn));
    }
}
