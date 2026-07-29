mod assuan;
mod bus;
mod config;
mod message;
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

    let _bus = Bus::new();
    // Detectors and notifiers are wired in as they land (see project plan);
    // for now the process just waits for a shutdown signal.

    shutdown.token().cancelled().await;
    let _ = signal_listener.await;
}
