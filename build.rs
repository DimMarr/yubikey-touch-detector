//! Embeds a version string derived from `git describe`, falling back to
//! `.git-archival.txt` when building from a GitHub-generated source
//! tarball (no `.git` directory, but `export-subst` in `.gitattributes`
//! has expanded the placeholder into a real value), and finally to
//! `"unknown"` - mirrors the original Go implementation's exact mechanism
//! (`-ldflags "-X main.version=$(git describe)"` for normal builds, a
//! `$Format:%(describe)$` `export-subst` placeholder for archive builds).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git-archival.txt");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let version = git_describe()
        .or_else(archival_version)
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=YUBIKEY_TOUCH_DETECTOR_VERSION={version}");
}

/// Runs `git describe` directly; works for a normal clone (with `.git`),
/// fails harmlessly (returning `None`) when building from a tarball.
fn git_describe() -> Option<String> {
    let output = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    non_empty(String::from_utf8(output.stdout).ok()?)
}

/// Reads the `describe-name:` line from `.git-archival.txt`, which
/// `export-subst` (see `.gitattributes`) expands to a real value only when
/// `git archive` produces the tarball being built from - in a normal git
/// checkout it's still the literal, unexpanded `$Format:...$` placeholder,
/// which is deliberately rejected here so `git_describe` above is always
/// preferred when both are available.
fn archival_version() -> Option<String> {
    let contents = std::fs::read_to_string(".git-archival.txt").ok()?;
    let describe_line = contents
        .lines()
        .find_map(|line| line.strip_prefix("describe-name:"))?;
    let candidate = non_empty(describe_line.to_string())?;
    if candidate.starts_with('$') {
        None
    } else {
        Some(candidate)
    }
}

fn non_empty(raw: String) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
