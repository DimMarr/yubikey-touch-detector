//! Detects touch-waits that arrive via SSH agent forwarding: `ssh` can
//! forward a remote host's `ssh-agent` requests back to a *local* agent
//! (typically gpg-agent acting as an ssh-agent) over `$SSH_AUTH_SOCK`. That
//! traffic never touches the paths the GPG detector watches (see
//! `detector::gpg`), so instead this module transparently proxies the
//! `$SSH_AUTH_SOCK` Unix socket and re-uses the GPG detector's shared
//! [`Notify`] to trigger the same busy check on any traffic seen in either
//! direction.
//!
//! Socket discovery (env var / `gpgconf` / conventional fallback) is kept
//! separate from the proxy mechanics so the proxy can be exercised with
//! real temp-dir-backed sockets in tests, without touching process env vars.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::assuan;

const READ_BUFFER_SIZE: usize = 16 * 1024;

/// Pure decision logic for locating `$SSH_AUTH_SOCK`, mirroring the
/// `gpgconf` > env-var > conventional-default priority used in
/// `assuan::discovery`, but keyed off `agent-ssh-socket` rather than
/// `agent-socket` and checking `$SSH_AUTH_SOCK` first (ssh itself sets it
/// when forwarding is active).
fn resolve_ssh_auth_sock(
    ssh_auth_sock_env: Option<&str>,
    gpgconf_ssh_socket: Option<PathBuf>,
    xdg_runtime_dir_env: Option<&str>,
) -> Option<PathBuf> {
    ssh_auth_sock_env
        .map(PathBuf::from)
        .or(gpgconf_ssh_socket)
        .or_else(|| xdg_runtime_dir_env.map(|dir| PathBuf::from(dir).join("gnupg/S.gpg-agent.ssh")))
}

/// Locates the socket to proxy for SSH agent forwarding: `$SSH_AUTH_SOCK`,
/// then `gpgconf --list-dirs agent-ssh-socket`, then the conventional
/// `$XDG_RUNTIME_DIR/gnupg/S.gpg-agent.ssh`. Returns `None` (disabling this
/// detector) if none of those are available.
pub fn discover_ssh_auth_sock() -> Option<PathBuf> {
    resolve_ssh_auth_sock(
        std::env::var("SSH_AUTH_SOCK").ok().as_deref(),
        assuan::discovery::run_gpgconf_list_dirs("agent-ssh-socket"),
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
    )
}

/// `socket_path` with `.original` appended to its filename, e.g.
/// `/run/user/1000/gnupg/S.gpg-agent.ssh` ->
/// `/run/user/1000/gnupg/S.gpg-agent.ssh.original`.
fn original_path_for(socket_path: &Path) -> PathBuf {
    let mut name = socket_path.as_os_str().to_os_string();
    name.push(".original");
    PathBuf::from(name)
}

/// Undoes the `socket_path` -> `original_path` rename, restoring direct
/// access to the real agent. Used both on graceful shutdown and when the
/// proxy fails to set up after having already vacated `socket_path`. Logs
/// (rather than panics) on failure, since by this point we're already
/// either shutting down or bailing out.
fn restore_original(original_path: &Path, socket_path: &Path) {
    if let Err(err) = std::fs::rename(original_path, socket_path) {
        error!(
            from = %original_path.display(),
            to = %socket_path.display(),
            %err,
            "failed to restore the original SSH auth socket path"
        );
    }
}

/// Forwards bytes from `reader` to `writer`, notifying `notify` after every
/// chunk successfully forwarded (mirroring the original Go implementation,
/// which busy-checks on any traffic seen in either direction, not just once
/// per connection). Returns once the connection is closed or errors in
/// either direction.
async fn pump(mut reader: OwnedReadHalf, mut writer: OwnedWriteHalf, notify: Arc<Notify>) {
    let mut buf = [0u8; READ_BUFFER_SIZE];
    loop {
        let bytes_read = match reader.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(err) => {
                debug!(%err, "SSH forwarded-agent connection read error");
                return;
            }
        };
        if let Err(err) = writer.write_all(&buf[..bytes_read]).await {
            debug!(%err, "SSH forwarded-agent connection write error");
            return;
        }
        notify.notify_one();
    }
}

/// Dials the real agent at `original_path` on behalf of one accepted
/// `inbound` connection and pumps bytes in both directions concurrently.
/// If the dial fails, the connection is dropped and logged; other
/// connections keep being accepted by the caller.
async fn proxy_connection(inbound: UnixStream, original_path: PathBuf, notify: Arc<Notify>) {
    let outbound = match UnixStream::connect(&original_path).await {
        Ok(stream) => stream,
        Err(err) => {
            error!(
                path = %original_path.display(),
                %err,
                "failed to dial the real SSH agent, dropping forwarded connection"
            );
            return;
        }
    };

    let (inbound_read, inbound_write) = inbound.into_split();
    let (outbound_read, outbound_write) = outbound.into_split();

    let client_to_agent = tokio::spawn(pump(inbound_read, outbound_write, notify.clone()));
    let agent_to_client = tokio::spawn(pump(outbound_read, inbound_write, notify));

    let _ = tokio::join!(client_to_agent, agent_to_client);
}

/// Transparently proxies the already-resolved `socket_path` (as returned by
/// [`discover_ssh_auth_sock`]): the real agent listening there is moved
/// aside to `original_path`, a new listener takes over the vacated name,
/// and every accepted connection is dialed through to `original_path` and
/// pumped in both directions, notifying `notify` on any traffic. On
/// cancellation, `original_path` is renamed back before returning, so
/// direct access to the real agent is restored - the caller must treat
/// this task's `JoinHandle` as critical to shutdown (see
/// `shutdown::Shutdown::join_critical_tasks`).
pub async fn watch(socket_path: PathBuf, notify: Arc<Notify>, shutdown: CancellationToken) {
    if !socket_path.exists() {
        debug!(
            path = %socket_path.display(),
            "SSH auth socket does not exist, disabling the SSH forwarded-agent detector"
        );
        return;
    }

    let original_path = original_path_for(&socket_path);

    if original_path.exists() {
        // A previous run crashed after renaming `socket_path` away but
        // before restoring it: `original_path` is the real agent socket,
        // and `socket_path` is our own stale listener file. Leave
        // `original_path` untouched and just clear the way for a fresh
        // listener.
        warn!(
            path = %original_path.display(),
            "found a leftover SSH proxy socket from a previous crash, recovering"
        );
        if let Err(err) = std::fs::remove_file(&socket_path) {
            error!(
                path = %socket_path.display(),
                %err,
                "failed to remove the stale SSH auth socket during crash recovery"
            );
            return;
        }
    } else if let Err(err) = std::fs::rename(&socket_path, &original_path) {
        error!(%err, "failed to move the SSH auth socket aside for proxying");
        return;
    }

    // Renaming a Unix socket's filesystem path doesn't disturb an
    // already-bound listener: connections are resolved by pathname at
    // `connect()` time, so the real agent stays reachable under
    // `original_path` while we bind a fresh listener under the vacated
    // `socket_path` name.
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            error!(
                path = %socket_path.display(),
                %err,
                "failed to bind the SSH forwarded-agent proxy socket"
            );
            restore_original(&original_path, &socket_path);
            return;
        }
    };

    debug!(path = %socket_path.display(), "SSH forwarded-agent proxy listening");

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                drop(listener);
                restore_original(&original_path, &socket_path);
                return;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((inbound, _addr)) => {
                        tokio::spawn(proxy_connection(inbound, original_path.clone(), notify.clone()));
                    }
                    Err(err) => {
                        error!(%err, "failed to accept an SSH forwarded-agent connection");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    // `std::env` is process-global but `cargo test` runs tests in parallel
    // threads by default. Every test in this module that touches
    // `SSH_AUTH_SOCK`/`XDG_RUNTIME_DIR` must hold this lock for its entire
    // body, matching the pattern in `src/config.rs`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn prefers_ssh_auth_sock_env_over_any_fallback() {
        let resolved = resolve_ssh_auth_sock(
            Some("/tmp/ssh-agent.sock"),
            Some(PathBuf::from("/run/user/1000/gnupg/S.gpg-agent.ssh")),
            Some("/run/user/1000"),
        );
        assert_eq!(resolved, Some(PathBuf::from("/tmp/ssh-agent.sock")));
    }

    #[test]
    fn falls_back_to_gpgconf_when_env_var_unset() {
        let resolved = resolve_ssh_auth_sock(
            None,
            Some(PathBuf::from("/run/user/1000/gnupg/S.gpg-agent.ssh")),
            Some("/run/user/1000"),
        );
        assert_eq!(
            resolved,
            Some(PathBuf::from("/run/user/1000/gnupg/S.gpg-agent.ssh"))
        );
    }

    #[test]
    fn falls_back_to_xdg_runtime_dir_when_neither_env_nor_gpgconf_available() {
        let resolved = resolve_ssh_auth_sock(None, None, Some("/run/user/1000"));
        assert_eq!(
            resolved,
            Some(PathBuf::from("/run/user/1000/gnupg/S.gpg-agent.ssh"))
        );
    }

    #[test]
    fn none_when_nothing_is_available() {
        assert_eq!(resolve_ssh_auth_sock(None, None, None), None);
    }

    #[test]
    fn real_discovery_reads_ssh_auth_sock_env_var() {
        let _guard = lock_env();
        // SAFETY: serialized against every other test in this module via
        // `ENV_LOCK`.
        unsafe {
            std::env::set_var("SSH_AUTH_SOCK", "/tmp/some-real-looking.sock");
        }

        let discovered = discover_ssh_auth_sock();

        unsafe {
            std::env::remove_var("SSH_AUTH_SOCK");
        }

        assert_eq!(
            discovered,
            Some(PathBuf::from("/tmp/some-real-looking.sock"))
        );
    }

    fn original_path_of(socket_path: &Path) -> PathBuf {
        original_path_for(socket_path)
    }

    /// Runs a scripted fake ssh-agent that accepts a single connection on
    /// an already-bound `listener` and echoes back a fixed reply for every
    /// chunk it reads, so tests can assert both directions of the proxy.
    fn spawn_fake_agent(listener: UnixListener, reply: &'static [u8]) {
        tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.unwrap();
            let (mut read_half, mut write_half) = stream.into_split();
            let mut buf = [0u8; 1024];
            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if write_half.write_all(reply).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }

    #[tokio::test]
    async fn proxies_bytes_both_ways_and_notifies() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("S.gpg-agent.ssh");

        let real_listener = UnixListener::bind(&socket_path).unwrap();
        spawn_fake_agent(real_listener, b"pong");

        let notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(socket_path.clone(), notify.clone(), shutdown.clone()));

        // Give `watch` time to rename the socket aside and bind its own
        // listener before the test client tries to connect.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        client.write_all(b"ping").await.unwrap();

        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        assert!(
            tokio::time::timeout(Duration::from_secs(1), notify.notified())
                .await
                .is_ok(),
            "notify should have been signaled by the proxied traffic"
        );

        shutdown.cancel();
        let _ = watcher.await;
    }

    #[tokio::test]
    async fn crash_recovery_removes_stale_socket_and_proxies_to_the_survivor() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("S.gpg-agent.ssh");
        let original_path = original_path_of(&socket_path);

        // Stale leftover from a crash: any file is enough to exercise the
        // removal step.
        std::fs::write(&socket_path, b"stale").unwrap();
        // The real agent, which survived the crash under `.original`.
        let real_listener = UnixListener::bind(&original_path).unwrap();
        spawn_fake_agent(real_listener, b"pong");

        let notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(socket_path.clone(), notify.clone(), shutdown.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        assert!(
            original_path.exists(),
            "the survivor socket must be left in place"
        );

        shutdown.cancel();
        let _ = watcher.await;
    }

    #[tokio::test]
    async fn shutdown_restores_direct_access_to_the_real_agent() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("S.gpg-agent.ssh");
        let original_path = original_path_of(&socket_path);

        let real_listener = UnixListener::bind(&socket_path).unwrap();
        // Distinctive greeting sent on every accepted connection, so a
        // post-shutdown connection can be told apart from one relayed
        // through the (now-gone) proxy.
        tokio::spawn(async move {
            loop {
                let (stream, _addr) = match real_listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let (_read_half, mut write_half) = stream.into_split();
                    let _ = write_half.write_all(b"hello").await;
                });
            }
        });

        let notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(socket_path.clone(), notify.clone(), shutdown.clone()));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            original_path.exists(),
            "proxy setup should have renamed the socket aside"
        );

        shutdown.cancel();
        watcher.await.unwrap();

        assert!(
            !original_path.exists(),
            "shutdown must rename the original socket back into place"
        );

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    /// Forces the bind step in `watch` to fail deterministically (without
    /// racing the preceding rename, which happens in the same directory
    /// and would be disturbed by any permission-based trick) by making
    /// `socket_path` itself longer than `sockaddr_un::sun_path` (108 bytes
    /// on Linux). `std::fs::rename` has no such limit (only `PATH_MAX`,
    /// ~4096), so the initial rename still succeeds; only the subsequent
    /// `UnixListener::bind` at that same overlong path fails. The initial
    /// `socket_path` only needs to *exist* to pass `watch`'s first check
    /// and be renameable - it doesn't need to be a working socket for this
    /// recovery-path test.
    #[tokio::test]
    async fn bind_failure_restores_the_original_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut long_dir = dir.path().to_path_buf();
        long_dir.push("a".repeat(60));
        long_dir.push("b".repeat(60));
        std::fs::create_dir_all(&long_dir).unwrap();
        let socket_path = long_dir.join("S.gpg-agent.ssh");
        assert!(
            socket_path.as_os_str().len() > 108,
            "test setup must produce a path longer than sockaddr_un::sun_path"
        );
        let original_path = original_path_of(&socket_path);

        std::fs::write(&socket_path, b"placeholder").unwrap();

        let notify = Arc::new(Notify::new());
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(watch(socket_path.clone(), notify, shutdown));

        tokio::time::timeout(Duration::from_secs(2), watcher)
            .await
            .expect("watch should return promptly after a bind failure")
            .unwrap();

        assert!(
            !original_path.exists(),
            "bind failure must restore the original socket path rather than leaving it stranded"
        );
        assert!(
            socket_path.exists(),
            "the real socket should be back at its original name"
        );
    }
}
