//! Locating the gpg-agent Assuan socket without linking gpgme.
//!
//! GnuPG >= 2.1 places its sockets under a randomized runtime directory
//! (not simply `$GNUPGHOME`), so `gpgconf --list-dirs agent-socket` is the
//! only generally reliable source — it's what `gpg`/`gpg-agent` themselves
//! use to agree on the socket location. The `$GNUPGHOME`/`$XDG_RUNTIME_DIR`
//! paths are kept only as a last-resort fallback for unusual setups where
//! `gpgconf` isn't on `$PATH`.

use std::path::PathBuf;
use std::process::Command;

/// Pure decision logic, independent of how each candidate was obtained, so
/// it's testable without a real `gpgconf` binary or environment.
fn resolve_agent_socket(
    gpgconf_socket: Option<PathBuf>,
    gnupghome_env: Option<&str>,
    xdg_runtime_dir_env: Option<&str>,
) -> Option<PathBuf> {
    gpgconf_socket
        .or_else(|| gnupghome_env.map(|home| PathBuf::from(home).join("S.gpg-agent")))
        .or_else(|| {
            xdg_runtime_dir_env.map(|dir| PathBuf::from(dir).join("gnupg").join("S.gpg-agent"))
        })
}

/// Parses the raw stdout of `gpgconf --list-dirs <key>`, which is expected
/// to be a single path on one line (possibly with trailing whitespace).
fn parse_gpgconf_path(raw_stdout: &[u8]) -> Option<PathBuf> {
    let text = std::str::from_utf8(raw_stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn run_gpgconf_list_dirs(key: &str) -> Option<PathBuf> {
    let output = Command::new("gpgconf")
        .arg("--list-dirs")
        .arg(key)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_gpgconf_path(&output.stdout)
}

/// Locates the gpg-agent Assuan socket (`S.gpg-agent`), trying `gpgconf`
/// first and falling back to well-known conventional locations.
pub fn agent_socket_path() -> Option<PathBuf> {
    resolve_agent_socket(
        run_gpgconf_list_dirs("agent-socket"),
        std::env::var("GNUPGHOME").ok().as_deref(),
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_gpgconf_result_over_any_fallback() {
        let resolved = resolve_agent_socket(
            Some(PathBuf::from("/run/user/1000/gnupg/d.abc123/S.gpg-agent")),
            Some("/home/user/.gnupg"),
            Some("/run/user/1000"),
        );
        assert_eq!(
            resolved,
            Some(PathBuf::from("/run/user/1000/gnupg/d.abc123/S.gpg-agent"))
        );
    }

    #[test]
    fn falls_back_to_gnupghome_when_gpgconf_unavailable() {
        let resolved =
            resolve_agent_socket(None, Some("/home/user/.gnupg"), Some("/run/user/1000"));
        assert_eq!(
            resolved,
            Some(PathBuf::from("/home/user/.gnupg/S.gpg-agent"))
        );
    }

    #[test]
    fn falls_back_to_xdg_runtime_dir_when_neither_gpgconf_nor_gnupghome_available() {
        let resolved = resolve_agent_socket(None, None, Some("/run/user/1000"));
        assert_eq!(
            resolved,
            Some(PathBuf::from("/run/user/1000/gnupg/S.gpg-agent"))
        );
    }

    #[test]
    fn none_when_nothing_is_available() {
        assert_eq!(resolve_agent_socket(None, None, None), None);
    }

    #[test]
    fn parses_trimmed_gpgconf_output() {
        assert_eq!(
            parse_gpgconf_path(b"/run/user/1000/gnupg/d.abc123/S.gpg-agent\n"),
            Some(PathBuf::from("/run/user/1000/gnupg/d.abc123/S.gpg-agent"))
        );
    }

    #[test]
    fn empty_gpgconf_output_is_treated_as_unavailable() {
        assert_eq!(parse_gpgconf_path(b""), None);
        assert_eq!(parse_gpgconf_path(b"   \n"), None);
    }

    #[test]
    fn non_utf8_gpgconf_output_is_treated_as_unavailable() {
        assert_eq!(parse_gpgconf_path(&[0xff, 0xfe, 0xfd]), None);
    }
}
