//! Graceful shutdown coordination.
//!
//! Replaces the Go original's `exits *sync.Map` (a name -> exit-channel
//! registry, iterated on SIGINT/SIGTERM, each entry required to confirm
//! before the process exits). A single root [`tokio_util::sync::CancellationToken`]
//! plays the same "observe shutdown" role for every task; the handful of
//! tasks with cleanup that must run before exit (the SSH proxy restoring
//! the original socket, the unix socket notifier removing its socket file)
//! are joined explicitly with a bounded timeout, so a stuck cleanup can no
//! longer hang shutdown forever the way the Go original's unconditional
//! wait could.

use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// How long we wait for critical cleanup tasks (SSH socket restore, unix
/// socket removal) to finish before exiting anyway.
const CRITICAL_TASK_TIMEOUT: Duration = Duration::from_secs(2);

pub struct Shutdown {
    token: CancellationToken,
}

impl Shutdown {
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Spawns a task that waits for SIGINT/SIGTERM and cancels the root
    /// token when either arrives.
    pub fn spawn_signal_listener(&self) -> JoinHandle<()> {
        let token = self.token.clone();
        tokio::spawn(async move {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(err) => {
                        warn!(%err, "failed to install SIGTERM handler");
                        return;
                    }
                };

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }

            debug!("Stopping YubiKey touch detector");
            token.cancel();
        })
    }

    /// Waits for every critical cleanup task to finish, up to a fixed
    /// timeout, logging (but not failing on) any that don't make it in
    /// time.
    pub async fn join_critical_tasks(handles: Vec<JoinHandle<()>>) {
        let joined = tokio::time::timeout(CRITICAL_TASK_TIMEOUT, async {
            for handle in handles {
                let _ = handle.await;
            }
        });

        if joined.await.is_err() {
            warn!(
                timeout_secs = CRITICAL_TASK_TIMEOUT.as_secs(),
                "not all cleanup tasks finished before the shutdown timeout"
            );
        }
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}
