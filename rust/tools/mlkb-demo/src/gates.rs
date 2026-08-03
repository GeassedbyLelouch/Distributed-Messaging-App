//! The "run the gates" panel: shells out to `cargo test` and reports what it
//! actually said.
//!
//! # Why shell out rather than report a number
//!
//! A hard-coded test count in a demo page is a claim nobody re-checks. This
//! runs the real command in the real workspace and parses the real summary
//! lines, so the number on the page is the number `cargo` printed a moment ago,
//! or the page says the run failed. It is slow — a cold workspace test run
//! takes minutes — and the UI says so before you press the button.
//!
//! The workspace root is resolved from `CARGO_MANIFEST_DIR` at compile time
//! (`tools/mlkb-demo` → up two), so `cargo run -p mlkb-demo` from anywhere
//! finds it.

use std::path::PathBuf;
use std::process::Command;

/// The parsed result of one `cargo test` invocation.
#[derive(Debug)]
pub(crate) struct Run {
    /// The command line, for display.
    pub(crate) command: String,
    /// Whether the process exited 0.
    pub(crate) ok: bool,
    /// Sum of `passed` across every `test result:` line.
    pub(crate) passed: u64,
    /// Sum of `failed`.
    pub(crate) failed: u64,
    /// Sum of `ignored`.
    pub(crate) ignored: u64,
    /// The tail of the combined output, for display.
    pub(crate) tail: String,
}

/// The workspace root, two levels above this crate's manifest.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(std::path::Path::parent)
        .map_or(manifest.clone(), std::path::Path::to_path_buf)
}

/// Runs one `cargo test` invocation and parses its summary lines.
#[must_use]
pub(crate) fn run(args: &[&str]) -> Run {
    let command = format!("cargo {}", args.join(" "));
    let output = Command::new("cargo")
        .args(args)
        .current_dir(workspace_root())
        .output();

    let Ok(output) = output else {
        return Run {
            command,
            ok: false,
            passed: 0,
            failed: 0,
            ignored: 0,
            tail: String::from("could not run `cargo` - is it on PATH?"),
        };
    };

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));

    let (passed, failed, ignored) = tally(&text);
    Run {
        command,
        ok: output.status.success(),
        passed,
        failed,
        ignored,
        tail: tail(&text, 40),
    }
}

/// Sums every `test result: ok. 12 passed; 0 failed; 0 ignored; ...` line.
///
/// The scan is over adjacent `<number> <label>` token pairs rather than over
/// `;`-separated segments. An earlier version split on `;` and read the first
/// two words of each segment, which silently dropped every `passed` count: the
/// first segment is `" ok. 3 passed"`, whose first word is the verdict, not the
/// number. The page then reported `0 passed` for a run that had passed. The
/// unit tests below are what caught it, which is why they are here at all —
/// a gates panel that under-reports is worse than no gates panel.
fn tally(text: &str) -> (u64, u64, u64) {
    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut ignored = 0u64;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("test result:") else {
            continue;
        };
        // `;` and `.` are separators, not part of a token.
        let flat = rest.replace([';', '.'], " ");
        let tokens: Vec<&str> = flat.split_whitespace().collect();
        for pair in tokens.windows(2) {
            let (Some(count), Some(label)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            let Ok(count) = count.parse::<u64>() else {
                continue;
            };
            match *label {
                "passed" => passed = passed.saturating_add(count),
                "failed" => failed = failed.saturating_add(count),
                "ignored" => ignored = ignored.saturating_add(count),
                _ => {}
            }
        }
    }
    (passed, failed, ignored)
}

/// The last `n` lines, so a failure is legible without shipping megabytes to
/// the browser.
fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines.get(start..).unwrap_or(&[]).join("\n")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::tally;

    #[test]
    fn tally_sums_every_summary_line() {
        let text = "\
running 3 tests
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 9 tests
test result: FAILED. 7 passed; 2 failed; 1 ignored; 0 measured; 0 filtered out
";
        assert_eq!(tally(text), (10, 2, 1));
    }

    /// The regression the first implementation had: the `passed` count sits
    /// behind the verdict word in its own segment, so a "first two words of
    /// each `;` segment" reader loses it and reports zero.
    #[test]
    fn tally_does_not_lose_passed_behind_the_verdict_word() {
        assert_eq!(
            tally("test result: ok. 375 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"),
            (375, 0, 0)
        );
    }

    /// `0 filtered out` must not be read as a count of anything tallied.
    #[test]
    fn tally_ignores_labels_it_does_not_know() {
        assert_eq!(
            tally("test result: ok. 1 passed; 0 failed; 0 ignored; 4 measured; 9 filtered out"),
            (1, 0, 0)
        );
    }

    #[test]
    fn tally_ignores_unrelated_output() {
        assert_eq!(
            tally("Compiling mlkb-demo v0.1.0\nwarning: unused\n"),
            (0, 0, 0)
        );
    }
}
