//! Unix socket notifier: the default-on notifier other programs actually
//! integrate with (status bars via py3status, waybar, ...). Broadcasts every
//! `Message`'s wire bytes, unmodified, to every connected client - this is a
//! compatibility surface with existing consumers, so the wire format and
//! socket path convention are kept stable across releases.
//!
//! Supports systemd socket activation: if the process was launched by a
//! `.socket` unit, the already-bound-and-listening file descriptor it passed
//! is used directly instead of binding our own socket file. This is detected
//! manually via `$LISTEN_PID`/`$LISTEN_FDS` (see `sd_listen_fds(3)`) rather
//! than pulling in a socket-activation crate, matching this project's
//! general preference for a little bit of its own code over an extra
//! dependency (see `assuan::discovery` shelling out to `gpgconf` rather than
//! linking `libgpgme`).

use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::bus::{Bus, BusReceiver};

const SOCKET_FILE_NAME: &str = "yubikey-touch-detector.socket";

/// Fixed by the `sd_listen_fds(3)` convention: passed file descriptors start
/// at 3 and are contiguous.
const SD_LISTEN_FDS_START: RawFd = 3;

/// Pure decision logic for whether this process was launched via systemd
/// socket activation, given the two env vars systemd sets
/// (`$LISTEN_PID`/`$LISTEN_FDS`) and the pid to compare against (injected
/// rather than read from `std::process::id()` directly, so this is
/// unit-testable without actually forking a process or faking systemd).
/// Returns the number of file descriptors passed when activation applies
/// (always >= 1), or `None` when it doesn't - either env var missing or
/// unparseable, or `$LISTEN_PID` naming some other process.
fn systemd_activation_fd_count(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    current_pid: u32,
) -> Option<u32> {
    let pid: u32 = listen_pid?.parse().ok()?;
    if pid != current_pid {
        return None;
    }
    let fds: u32 = listen_fds?.parse().ok()?;
    if fds == 0 { None } else { Some(fds) }
}

/// Takes over the file descriptor systemd passed via socket activation, if
/// this process was launched that way. The outer `Option` is `None` when
/// `$LISTEN_PID`/`$LISTEN_FDS` don't indicate activation for this process
/// (caller should fall back to a manual bind); the inner `Result` reports a
/// failure to adopt the fd once activation *is* indicated.
fn try_systemd_activation() -> Option<io::Result<tokio::net::UnixListener>> {
    let listen_pid = std::env::var("LISTEN_PID").ok();
    let listen_fds = std::env::var("LISTEN_FDS").ok();
    let fd_count = systemd_activation_fd_count(
        listen_pid.as_deref(),
        listen_fds.as_deref(),
        std::process::id(),
    )?;

    if fd_count > 1 {
        warn!(
            fd_count,
            "systemd passed more than one socket-activated file descriptor to the unix socket notifier; only the first is used"
        );
    }

    // SAFETY: `systemd_activation_fd_count` returning `Some` just above
    // means `$LISTEN_PID` named this exact process and `$LISTEN_FDS` was a
    // positive count - per the `sd_listen_fds(3)` contract that systemd and
    // its `.socket` units honor, that guarantees file descriptor 3 is a
    // valid, already-bound-and-listening Unix socket handed to this process
    // (and this process alone) for the remainder of its lifetime.
    let std_listener =
        unsafe { std::os::unix::net::UnixListener::from_raw_fd(SD_LISTEN_FDS_START) };

    // Not guaranteed to already be nonblocking, but required before handing
    // it to tokio.
    if let Err(err) = std_listener.set_nonblocking(true) {
        return Some(Err(err));
    }
    Some(tokio::net::UnixListener::from_std(std_listener))
}

/// Binds `socket_path` ourselves, first clearing away any stale socket file
/// left behind by a previous crash - simpler here than the SSH proxy's
/// rename dance since there's nothing to preserve, just a dead file to
/// remove before binding fresh.
fn bind_manual(socket_path: &Path) -> io::Result<tokio::net::UnixListener> {
    if socket_path.exists() {
        warn!(
            path = %socket_path.display(),
            "found a leftover unix socket file from a previous crash, removing it"
        );
        std::fs::remove_file(socket_path)?;
    }
    tokio::net::UnixListener::bind(socket_path)
}

/// Acquires the listener to serve, preferring a systemd-activated fd over
/// binding `socket_path` ourselves. The returned `bool` is whether we bound
/// the socket file ourselves (and therefore own removing it on shutdown).
fn acquire_listener(socket_path: &Path) -> io::Result<(tokio::net::UnixListener, bool)> {
    if let Some(result) = try_systemd_activation() {
        return result.map(|listener| (listener, false));
    }
    bind_manual(socket_path).map(|listener| (listener, true))
}

/// Writes every message received on `events` to `stream` as raw wire bytes
/// (no delimiter - these are fixed 5-byte frames, not line-delimited text
/// like the stdout notifier). Returns as soon as a write fails, dropping
/// this client's connection; other clients are unaffected.
async fn broadcast_to_client(mut stream: tokio::net::UnixStream, mut events: BusReceiver) {
    while let Some(message) = events.recv().await {
        if let Err(err) = stream.write_all(message.wire_bytes()).await {
            debug!(%err, "unix socket notifier client disconnected");
            return;
        }
    }
}

/// Listens on `$XDG_RUNTIME_DIR/yubikey-touch-detector.socket` (or takes
/// over a systemd-activated fd, see the module docs) and broadcasts every
/// `Message` from `bus` to every connected client, as raw wire bytes. Many
/// clients can be connected at once; every one of them gets every message.
///
/// This is a **critical** shutdown task, in the same category as the SSH
/// proxy (`detector::ssh::watch`): its `JoinHandle` must be passed to
/// `Shutdown::join_critical_tasks`. On cancellation, the listener is closed
/// and - only if this notifier bound its own socket file, not if it was
/// handed one via systemd activation (that socket file's lifecycle belongs
/// to the `.socket` unit) - the socket file is removed.
pub async fn watch(bus: Bus, shutdown: CancellationToken) {
    let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") else {
        error!("XDG_RUNTIME_DIR is not set, disabling the unix socket notifier");
        return;
    };
    let socket_path = PathBuf::from(runtime_dir).join(SOCKET_FILE_NAME);

    let (listener, self_bound) = match acquire_listener(&socket_path) {
        Ok(acquired) => acquired,
        Err(err) => {
            error!(
                path = %socket_path.display(),
                %err,
                "failed to set up the unix socket notifier"
            );
            return;
        }
    };

    debug!(
        path = %socket_path.display(),
        self_bound,
        "unix socket notifier listening"
    );

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                drop(listener);
                if self_bound {
                    if let Err(err) = std::fs::remove_file(&socket_path) {
                        error!(
                            path = %socket_path.display(),
                            %err,
                            "failed to remove the unix socket file during shutdown"
                        );
                    }
                }
                return;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        tokio::spawn(broadcast_to_client(stream, bus.subscribe()));
                    }
                    Err(err) => {
                        error!(%err, "failed to accept a unix socket notifier connection");
                    }
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
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixStream;
    use tokio::sync::{Mutex, MutexGuard};

    #[test]
    fn matching_pid_and_positive_fds_is_activated() {
        assert_eq!(
            systemd_activation_fd_count(Some("1234"), Some("1"), 1234),
            Some(1)
        );
        assert_eq!(
            systemd_activation_fd_count(Some("1234"), Some("3"), 1234),
            Some(3)
        );
    }

    #[test]
    fn mismatched_pid_is_not_activated() {
        assert_eq!(
            systemd_activation_fd_count(Some("1234"), Some("1"), 5678),
            None
        );
    }

    #[test]
    fn zero_fds_is_not_activated() {
        assert_eq!(
            systemd_activation_fd_count(Some("1234"), Some("0"), 1234),
            None
        );
    }

    #[test]
    fn unset_or_unparseable_fds_is_not_activated() {
        assert_eq!(systemd_activation_fd_count(Some("1234"), None, 1234), None);
        assert_eq!(
            systemd_activation_fd_count(Some("1234"), Some("not-a-number"), 1234),
            None
        );
    }

    #[test]
    fn unset_or_unparseable_pid_is_not_activated() {
        assert_eq!(systemd_activation_fd_count(None, Some("1"), 1234), None);
        assert_eq!(
            systemd_activation_fd_count(Some("not-a-number"), Some("1"), 1234),
            None
        );
    }

    // `std::env` is process-global but `cargo test` runs tests in parallel
    // threads by default. Every test in this module that touches
    // `XDG_RUNTIME_DIR`/`LISTEN_PID`/`LISTEN_FDS` must hold this lock for
    // its entire body, matching the pattern in `src/config.rs` and
    // `src/detector/ssh.rs` - a `tokio::sync::Mutex` rather than a
    // `std::sync::Mutex` because, unlike those two (which never await while
    // holding the guard), these tests must keep the lock held across
    // `.await` points: `watch` itself reads the env vars asynchronously, so
    // the guard can't be dropped before awaiting it.
    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    async fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().await
    }

    /// Points `$XDG_RUNTIME_DIR` at `dir` and clears any systemd activation
    /// env vars that might otherwise be inherited from the test runner's
    /// real environment, so every test in this module gets a manual bind
    /// unless it sets those vars up itself. Caller must be holding
    /// `lock_env()` for its entire body.
    fn set_runtime_dir(dir: &Path) {
        // SAFETY: serialized against every other test in this module via
        // `ENV_LOCK`.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
            std::env::remove_var("LISTEN_PID");
            std::env::remove_var("LISTEN_FDS");
        }
    }

    fn clear_runtime_dir() {
        // SAFETY: serialized against every other test in this module via
        // `ENV_LOCK`.
        unsafe {
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
    }

    #[tokio::test]
    async fn broadcasts_to_every_connected_client_in_order() {
        let _guard = lock_env().await;
        let dir = tempfile::tempdir().unwrap();
        set_runtime_dir(dir.path());
        let socket_path = dir.path().join(SOCKET_FILE_NAME);

        let bus = Bus::new();
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(bus.clone(), shutdown.clone()));

        // Give `watch` time to bind before clients try to connect.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client_a = UnixStream::connect(&socket_path).await.unwrap();
        let mut client_b = UnixStream::connect(&socket_path).await.unwrap();

        // Give the accept loop time to register both clients' bus
        // subscriptions before sending, since `Bus::send` drops messages
        // when there are no subscribers yet.
        tokio::time::sleep(Duration::from_millis(100)).await;

        bus.send(Message::GpgOn);
        bus.send(Message::GpgOff);

        for client in [&mut client_a, &mut client_b] {
            let mut buf = [0u8; 10];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"GPG_1GPG_0");
        }

        shutdown.cancel();
        let _ = watcher.await;
        clear_runtime_dir();
    }

    #[tokio::test]
    async fn stale_socket_file_is_removed_and_replaced_with_a_working_listener() {
        let _guard = lock_env().await;
        let dir = tempfile::tempdir().unwrap();
        set_runtime_dir(dir.path());
        let socket_path = dir.path().join(SOCKET_FILE_NAME);
        std::fs::write(&socket_path, b"stale").unwrap();

        let bus = Bus::new();
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(bus, shutdown.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        // A successful connect proves the stale file was removed and a real
        // listener bound in its place.
        UnixStream::connect(&socket_path)
            .await
            .expect("should connect to the freshly bound socket");

        shutdown.cancel();
        let _ = watcher.await;
        clear_runtime_dir();
    }

    #[tokio::test]
    async fn shutdown_removes_the_self_bound_socket_file() {
        let _guard = lock_env().await;
        let dir = tempfile::tempdir().unwrap();
        set_runtime_dir(dir.path());
        let socket_path = dir.path().join(SOCKET_FILE_NAME);

        let bus = Bus::new();
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(bus, shutdown.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            socket_path.exists(),
            "watch should have bound the socket file by now"
        );

        shutdown.cancel();
        watcher.await.unwrap();

        assert!(
            !socket_path.exists(),
            "shutdown must remove the self-bound socket file"
        );
        clear_runtime_dir();
    }

    #[tokio::test]
    async fn missing_xdg_runtime_dir_disables_without_panicking() {
        let _guard = lock_env().await;
        clear_runtime_dir();

        let bus = Bus::new();
        let shutdown = CancellationToken::new();

        let result = tokio::time::timeout(Duration::from_secs(1), watch(bus, shutdown)).await;
        assert!(
            result.is_ok(),
            "watch should return promptly when XDG_RUNTIME_DIR is unset"
        );
    }

    /// Stand-in for the systemd-activation code path (see the module docs
    /// for why the real path isn't exercised end to end here): confirms the
    /// same `set_nonblocking` + `tokio::net::UnixListener::from_std` steps
    /// `try_systemd_activation` performs on an adopted fd work correctly on
    /// a real, already-bound `std::os::unix::net::UnixListener`.
    #[tokio::test]
    async fn std_listener_converted_like_the_systemd_path_still_accepts_connections() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("activated.socket");
        let std_listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(std_listener).unwrap();

        let accept_task = tokio::spawn(async move { listener.accept().await });

        let _client = UnixStream::connect(&socket_path).await.unwrap();
        accept_task.await.unwrap().unwrap();
    }
}
