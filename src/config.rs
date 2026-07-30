//! CLI/env configuration, mirroring the original Go flag+env-var precedence
//! (CLI arg > env var > default) with one deliberate behavior change: the
//! `libnotify` desktop-notification notifier now defaults to **on** instead
//! of requiring an opt-in flag, since that opt-in was the actual usability
//! complaint that motivated this rewrite.

use clap::Parser;
use clap::builder::BoolishValueParser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "yubikey-touch-detector",
    version = env!("YUBIKEY_TOUCH_DETECTOR_VERSION"),
    about,
    long_about = None
)]
struct CliArgs {
    /// Enable debug logging
    #[arg(
        short = 'v',
        long = "verbose",
        env = "YUBIKEY_TOUCH_DETECTOR_VERBOSE",
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        default_missing_value = "true",
        default_value_t = false,
    )]
    verbose: bool,

    /// Show desktop notifications using libnotify (enabled by default)
    #[arg(
        long = "libnotify",
        env = "YUBIKEY_TOUCH_DETECTOR_LIBNOTIFY",
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        default_missing_value = "true",
        default_value_t = true,
    )]
    libnotify: bool,

    /// Shorthand for --libnotify=false, regardless of env var
    #[arg(long = "no-libnotify")]
    no_libnotify: bool,

    /// Print notifications to stdout
    #[arg(
        long = "stdout",
        env = "YUBIKEY_TOUCH_DETECTOR_STDOUT",
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        default_missing_value = "true",
        default_value_t = false,
    )]
    stdout: bool,

    /// Disable the unix socket notifier
    #[arg(
        long = "no-socket",
        env = "YUBIKEY_TOUCH_DETECTOR_NOSOCKET",
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        default_missing_value = "true",
        default_value_t = false,
    )]
    no_socket: bool,

    /// Enable the D-Bus server notifier (io.github.dimmarr.YubikeyTouchDetector)
    #[arg(
        long = "dbus",
        env = "YUBIKEY_TOUCH_DETECTOR_DBUS",
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        default_missing_value = "true",
        default_value_t = false,
    )]
    dbus: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub verbose: bool,
    pub libnotify: bool,
    pub stdout: bool,
    pub socket: bool,
    pub dbus: bool,
}

impl From<CliArgs> for Config {
    fn from(args: CliArgs) -> Self {
        Config {
            verbose: args.verbose,
            libnotify: args.libnotify && !args.no_libnotify,
            stdout: args.stdout,
            socket: !args.no_socket,
            dbus: args.dbus,
        }
    }
}

impl Config {
    pub fn parse() -> Self {
        CliArgs::parse().into()
    }

    #[cfg(test)]
    fn try_parse_from<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        CliArgs::try_parse_from(args).map(Config::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // `std::env` is process-global and clap's `env` attribute reads it
    // directly, but `cargo test` runs tests in parallel threads by default.
    // Every test in this module must hold this lock for its entire body
    // (not just around the `set_var`/`remove_var` calls) so that no test's
    // `parse()` call can observe an env var mutated by another test running
    // concurrently, even tests that never touch the env vars themselves.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn parse(args: &[&str]) -> Config {
        let mut full = vec!["yubikey-touch-detector"];
        full.extend_from_slice(args);
        Config::try_parse_from(full).expect("args should parse")
    }

    #[test]
    fn defaults_match_expected_out_of_the_box_behavior() {
        let _guard = lock_env();
        let cfg = parse(&[]);
        assert!(!cfg.verbose);
        assert!(cfg.libnotify, "libnotify must default to on");
        assert!(!cfg.stdout);
        assert!(cfg.socket, "unix socket notifier must default to on");
        assert!(!cfg.dbus);
    }

    #[test]
    fn bare_flags_act_as_switches() {
        let _guard = lock_env();
        let cfg = parse(&["-v", "--stdout", "--dbus"]);
        assert!(cfg.verbose);
        assert!(cfg.stdout);
        assert!(cfg.dbus);
    }

    #[test]
    fn no_libnotify_flag_disables_regardless_of_libnotify_flag() {
        let _guard = lock_env();
        let cfg = parse(&["--no-libnotify"]);
        assert!(!cfg.libnotify);
    }

    #[test]
    fn explicit_libnotify_false_disables() {
        let _guard = lock_env();
        let cfg = parse(&["--libnotify=false"]);
        assert!(!cfg.libnotify);
    }

    #[test]
    fn no_socket_flag_disables_socket() {
        let _guard = lock_env();
        let cfg = parse(&["--no-socket"]);
        assert!(!cfg.socket);
    }

    #[test]
    fn env_var_sets_default_but_cli_flag_overrides() {
        let _guard = lock_env();
        // SAFETY: serialized against all other tests in this module by
        // `ENV_LOCK`, so no other test observes this mutation.
        unsafe {
            std::env::set_var("YUBIKEY_TOUCH_DETECTOR_STDOUT", "true");
        }
        let cfg_from_env = parse(&[]);
        assert!(cfg_from_env.stdout, "truthy env var should enable stdout");

        let cfg_overridden = parse(&["--stdout=false"]);
        assert!(!cfg_overridden.stdout, "explicit CLI arg must win over env");

        unsafe {
            std::env::remove_var("YUBIKEY_TOUCH_DETECTOR_STDOUT");
        }
    }

    #[test]
    fn env_var_truthy_values_are_case_insensitive() {
        let _guard = lock_env();
        for value in ["true", "TRUE", "yes", "YES", "1", "on"] {
            // SAFETY: serialized against all other tests in this module by
            // `ENV_LOCK`.
            unsafe {
                std::env::set_var("YUBIKEY_TOUCH_DETECTOR_DBUS", value);
            }
            let cfg = parse(&[]);
            assert!(cfg.dbus, "env value {value:?} should be treated as truthy");
        }
        unsafe {
            std::env::remove_var("YUBIKEY_TOUCH_DETECTOR_DBUS");
        }
    }
}
