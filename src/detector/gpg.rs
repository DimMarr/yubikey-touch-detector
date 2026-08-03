//! Detects touch-waits on GPG operations via a "busy check": when the
//! smartcard is busy (a `LEARN` Assuan command to gpg-agent hangs), it is
//! assumed to be waiting for a touch. This produces false positives when
//! the card is busy for unrelated reasons, but is a good heuristic in
//! practice.
//!
//! To avoid running the busy check continuously (which would keep the
//! YubiKey blinking), it only runs after one of the `private-keys-v1.d/*`
//! files that back a hardware-shadowed key is opened - `gpg`/`gpg-agent`
//! opens these files whenever it's about to talk to the card.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use inotify::{EventMask, Inotify, StreamExt, WatchMask};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use crate::assuan::{self, AssuanClient};
use crate::bus::Bus;
use crate::message::Message;

const SHADOWED_KEY_MARKER: &str = "shadowed-private-key";
const POST_OPEN_SETTLE_DELAY: Duration = Duration::from_millis(200);
const BUSY_CHECK_TIMEOUT: Duration = Duration::from_millis(400);
const REWATCH_DELAY: Duration = Duration::from_secs(5);

/// Locates every file under `private_keys_dir` whose contents reference a
/// hardware-shadowed key. These are the files worth watching for `OPEN`
/// events, since opening one of them is what precedes gpg-agent talking to
/// the card.
pub fn find_shadowed_private_keys(private_keys_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(private_keys_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut result = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let contents = std::fs::read(&path)?;
        if String::from_utf8_lossy(&contents).contains(SHADOWED_KEY_MARKER) {
            result.push(path);
        }
    }
    Ok(result)
}

/// Watches `files` for `OPEN` events (each one wakes up [`check_on_request`]
/// via `notify`) and for `DELETE_SELF`/`MOVE_SELF` events, which mean
/// gpg-agent rewrote the file out from under the watch; in that case every
/// watch is torn down and re-established (after a short delay) on the same
/// file list.
pub async fn watch_for_touch_requests(
    files: Vec<PathBuf>,
    notify: Arc<Notify>,
    shutdown: CancellationToken,
) {
    if files.is_empty() {
        return;
    }

    loop {
        let inotify = match Inotify::init() {
            Ok(inotify) => inotify,
            Err(err) => {
                error!(%err, "cannot initialize inotify for the GPG watcher");
                return;
            }
        };

        let mask = WatchMask::OPEN | WatchMask::DELETE_SELF | WatchMask::MOVE_SELF;
        let mut watch_failed = false;
        for file in &files {
            if let Err(err) = inotify.watches().add(file, mask) {
                error!(path = %file.display(), %err, "failed to establish a GPG file watch");
                watch_failed = true;
                break;
            }
        }
        if watch_failed {
            return;
        }
        debug!(
            count = files.len(),
            "GPG watcher is watching shadowed private key files"
        );

        let mut stream = match inotify.into_event_stream([0u8; 1024]) {
            Ok(stream) => stream,
            Err(err) => {
                error!(%err, "failed to create inotify event stream for the GPG watcher");
                return;
            }
        };

        // The inner loop only exits via `return` (shutdown, terminal) or
        // `break` (something requires tearing down and re-establishing the
        // watch), so reaching past it always means: wait, then loop again.
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) if ev.mask.contains(EventMask::OPEN) => {
                            notify.notify_one();
                        }
                        Some(Ok(ev))
                            if ev.mask.contains(EventMask::DELETE_SELF)
                                || ev.mask.contains(EventMask::MOVE_SELF) =>
                        {
                            debug!(?ev.mask, "GPG watched file changed, recreating the watcher");
                            break;
                        }
                        Some(Ok(_)) => {}
                        Some(Err(err)) => {
                            error!(%err, "inotify read error in the GPG watcher");
                            break;
                        }
                        None => break,
                    }
                }
            }
        }

        tokio::time::sleep(REWATCH_DELAY).await;
    }
}

async fn reconnect(agent_socket: &Path) -> Option<AssuanClient> {
    match AssuanClient::connect(agent_socket).await {
        Ok(client) => Some(client),
        Err(err) => {
            error!(%err, "cannot reconnect to gpg-agent, stopping GPG touch detection");
            None
        }
    }
}

/// Consumes `notify` wake-ups and busy-checks gpg-agent via the Assuan
/// `LEARN` command. Deliberately does **not** wrap the check in
/// `tokio::time::timeout` (which would cancel it): the check is spawned as
/// its own task and raced against a timeout on the `JoinHandle` instead, so
/// that when the timeout fires first, the real exchange keeps running in
/// the background to completion and only the timer decides whether to
/// notify. Errors from the exchange are only logged when it actually ran
/// past the busy-check timeout — a fast, successful round trip that
/// happens to return an error is silently ignored.
pub async fn check_on_request(agent_socket: PathBuf, notify: Arc<Notify>, bus: Bus) {
    let mut client = match reconnect(&agent_socket).await {
        Some(client) => client,
        None => return,
    };

    loop {
        notify.notified().await;
        tokio::time::sleep(POST_OPEN_SETTLE_DELAY).await;

        let mut task = tokio::spawn(async move {
            let result = client.send_command("LEARN").await;
            (client, result)
        });

        match tokio::time::timeout(BUSY_CHECK_TIMEOUT, &mut task).await {
            Ok(Ok((returned_client, _result))) => {
                // Completed within the busy-check window: the card wasn't
                // actually waiting for a touch. Any error here is silently
                // dropped.
                client = returned_client;
            }
            Ok(Err(join_err)) => {
                error!(%join_err, "GPG check task panicked, reconnecting to gpg-agent");
                client = match reconnect(&agent_socket).await {
                    Some(client) => client,
                    None => return,
                };
            }
            Err(_elapsed) => {
                bus.send(Message::GpgOn);
                match task.await {
                    Ok((returned_client, Ok(()))) => client = returned_client,
                    Ok((returned_client, Err(err))) => {
                        warn!(%err, "gpg-agent returned an error");
                        client = returned_client;
                    }
                    Err(join_err) => {
                        error!(%join_err, "GPG check task panicked, reconnecting to gpg-agent");
                        match reconnect(&agent_socket).await {
                            Some(reconnected) => client = reconnected,
                            None => {
                                bus.send(Message::GpgOff);
                                return;
                            }
                        }
                    }
                }
                bus.send(Message::GpgOff);
            }
        }
    }
}

/// Discovers the GnuPG homedir, the shadowed private keys under it, and the
/// gpg-agent socket; if all of that succeeds, spawns the watcher and
/// checker tasks and returns the shared [`Notify`] handle so other
/// detectors (the SSH forwarded-agent proxy) can trigger the same busy
/// check. Returns `None` (leaving GPG touch detection disabled) if
/// anything required isn't available, degrading gracefully rather than
/// failing.
pub fn try_init(bus: Bus, shutdown: CancellationToken) -> Option<Arc<Notify>> {
    let homedir = assuan::discovery::homedir().or_else(|| {
        debug!("cannot determine GnuPG homedir, disabling GPG and SSH watchers");
        None
    })?;

    let private_keys_dir = homedir.join("private-keys-v1.d");
    let files = match find_shadowed_private_keys(&private_keys_dir) {
        Ok(files) => files,
        Err(err) => {
            debug!(dir = %private_keys_dir.display(), %err, "error finding shadowed private keys");
            return None;
        }
    };
    if files.is_empty() {
        debug!(dir = %private_keys_dir.display(), "no shadowed private keys found");
        return None;
    }

    let agent_socket = assuan::discovery::agent_socket_path().or_else(|| {
        debug!("cannot locate gpg-agent socket, disabling GPG and SSH watchers");
        None
    })?;

    let notify = Arc::new(Notify::new());
    tokio::spawn(watch_for_touch_requests(files, notify.clone(), shutdown));
    tokio::spawn(check_on_request(agent_socket, notify.clone(), bus));
    Some(notify)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    #[test]
    fn finds_only_files_containing_the_shadowed_marker() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("shadowed"),
            "(21:private-key-shadowed-info8:shadowed-private-key...)",
        )
        .unwrap();
        std::fs::write(dir.path().join("regular"), "(11:private-key...)").unwrap();
        std::fs::write(dir.path().join("binary"), [0xff, 0x00, 0xfe, 0x10]).unwrap();

        let mut found = find_shadowed_private_keys(dir.path()).unwrap();
        found.sort();

        assert_eq!(found, vec![dir.path().join("shadowed")]);
    }

    #[test]
    fn missing_directory_yields_an_empty_list_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");

        assert_eq!(
            find_shadowed_private_keys(&missing).unwrap(),
            Vec::<PathBuf>::new()
        );
    }

    #[test]
    fn subdirectories_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        std::fs::write(
            dir.path().join("subdir").join("shadowed"),
            "shadowed-private-key",
        )
        .unwrap();

        assert_eq!(
            find_shadowed_private_keys(dir.path()).unwrap(),
            Vec::<PathBuf>::new()
        );
    }

    /// Runs a scripted fake gpg-agent on a real (tempdir-backed) Unix
    /// socket, so `AssuanClient::connect` can be exercised end to end
    /// without a real gpg-agent.
    fn spawn_fake_agent<F, Fut>(socket_path: PathBuf, script: F)
    where
        F: FnOnce(
                BufReader<tokio::net::unix::OwnedReadHalf>,
                tokio::net::unix::OwnedWriteHalf,
            ) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(async move {
            let listener = UnixListener::bind(&socket_path).unwrap();
            let (stream, _addr) = listener.accept().await.unwrap();
            let (read_half, write_half) = stream.into_split();
            script(BufReader::new(read_half), write_half).await;
        });
    }

    async fn write_line(writer: &mut tokio::net::unix::OwnedWriteHalf, line: &str) {
        writer.write_all(line.as_bytes()).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
    }

    async fn read_line(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> String {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        line.trim_end().to_string()
    }

    #[tokio::test(start_paused = true)]
    async fn a_quick_response_never_notifies() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("S.gpg-agent");

        spawn_fake_agent(socket_path.clone(), |mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let command = read_line(&mut reader).await;
            assert_eq!(command, "LEARN");
            // Responds well within the busy-check window: no artificial delay.
            write_line(&mut writer, "OK").await;
        });

        let bus = Bus::new();
        let mut events = bus.subscribe();
        let notify = Arc::new(Notify::new());

        let checker = tokio::spawn(check_on_request(socket_path, notify.clone(), bus));

        notify.notify_one();

        // Give the checker a chance to run; since nothing else is
        // outstanding, paused time auto-advances through the 200ms settle
        // delay and the round trip completes near-instantly.
        tokio::time::sleep(Duration::from_secs(1)).await;

        // No message should ever arrive because the round trip completed
        // inside the 400ms busy-check window.
        assert!(
            tokio::time::timeout(Duration::from_millis(1), events.recv())
                .await
                .is_err(),
            "a quick round trip must not emit any touch notification"
        );

        checker.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_response_notifies_on_then_off() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("S.gpg-agent");

        spawn_fake_agent(socket_path.clone(), |mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let command = read_line(&mut reader).await;
            assert_eq!(command, "LEARN");
            // Delay well past the 400ms busy-check window.
            tokio::time::sleep(Duration::from_millis(900)).await;
            write_line(&mut writer, "OK").await;
        });

        let bus = Bus::new();
        let mut events = bus.subscribe();
        let notify = Arc::new(Notify::new());

        let checker = tokio::spawn(check_on_request(socket_path, notify.clone(), bus));
        notify.notify_one();

        assert_eq!(events.recv().await, Some(Message::GpgOn));
        assert_eq!(events.recv().await, Some(Message::GpgOff));

        checker.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_error_after_the_busy_window_is_still_followed_by_off() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("S.gpg-agent");

        spawn_fake_agent(socket_path.clone(), |mut reader, mut writer| async move {
            write_line(&mut writer, "OK Pleased to meet you").await;
            let _command = read_line(&mut reader).await;
            tokio::time::sleep(Duration::from_millis(900)).await;
            write_line(&mut writer, "ERR 100663404 Card error <GPG Agent>").await;
        });

        let bus = Bus::new();
        let mut events = bus.subscribe();
        let notify = Arc::new(Notify::new());

        let checker = tokio::spawn(check_on_request(socket_path, notify.clone(), bus));
        notify.notify_one();

        assert_eq!(events.recv().await, Some(Message::GpgOn));
        assert_eq!(events.recv().await, Some(Message::GpgOff));

        checker.abort();
    }
}
