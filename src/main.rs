mod assuan;
mod bus;
mod config;
mod detector;
mod message;
mod notifier;
mod shutdown;

use tracing_subscriber::EnvFilter;

use crate::bus::Bus;
use crate::config::Config;
use crate::shutdown::Shutdown;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let config = Config::parse();

    let filter = if config.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::debug!(?config, "Starting YubiKey touch detector");

    let shutdown = Shutdown::new();
    let signal_listener = shutdown.spawn_signal_listener();

    let bus = Bus::new();

    // Notifiers. debug/stdout/dbus/libnotify are simply abandoned at
    // shutdown, same as the original implementation (only the unix socket
    // notifier and the SSH proxy get graceful cleanup, tracked below).
    if config.verbose {
        tokio::spawn(notifier::debug::watch(bus.clone()));
    }
    if config.stdout {
        tokio::spawn(notifier::stdout::watch(bus.clone()));
    }
    if config.dbus {
        tokio::spawn(notifier::dbus::watch(bus.clone(), shutdown.token()));
    }
    if config.libnotify {
        tokio::spawn(notifier::libnotify::watch(bus.clone()));
    }

    let mut critical_tasks = Vec::new();
    if config.socket {
        critical_tasks.push(tokio::spawn(notifier::unix_socket::watch(
            bus.clone(),
            shutdown.token(),
        )));
    }

    // Detectors. U2F/HMAC are also abandoned at shutdown (their per-device
    // reads have no reliable early-interrupt short of process exit, same
    // as the original's per-device goroutines).
    tokio::spawn(detector::u2f::watch(bus.clone(), shutdown.token()));
    tokio::spawn(detector::hmac::watch(bus.clone(), shutdown.token()));

    // GPG and the SSH forwarded-agent proxy share the same busy-check
    // trigger, so SSH is only started when GPG detection could be set up -
    // matching the original, which gates both on the same gpgme context.
    if let Some(notify) = detector::gpg::try_init(bus.clone(), shutdown.token())
        && let Some(ssh_socket) = detector::ssh::discover_ssh_auth_sock()
    {
        critical_tasks.push(tokio::spawn(detector::ssh::watch(
            ssh_socket,
            notify,
            shutdown.token(),
        )));
    }

    shutdown.token().cancelled().await;
    Shutdown::join_critical_tasks(critical_tasks).await;
    let _ = signal_listener.await;
}
