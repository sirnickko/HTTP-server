use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::request::Request;

/// Prints one log line per request to stdout.
///
/// Format: `[YYYY-MM-DD HH:MM:SS] METHOD /path STATUS  XXXms`
pub fn log(req: &Request, status: u16, elapsed: Duration) {
    let ts = timestamp();
    let ms = elapsed.as_secs_f64() * 1000.0;
    let status_label = status_color(status);
    println!(
        "[{ts}] {method:<6} {path:<40} {status_label}  {ms:.2}ms",
        method = req.method,
        path   = req.path,
    );
}

/// Formats the current wall-clock time as `YYYY-MM-DD HH:MM:SS` (UTC).
/// Uses only `std::time` — no external crate needed.
fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Gregorian calendar decomposition from a Unix timestamp.
    // Reference: https://howardhinnant.github.io/date_algorithms.html
    let z    = secs / 86_400 + 719_468;
    let era  = z / 146_097;
    let doe  = z - era * 146_097;
    let yoe  = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y    = yoe + era * 400;
    let doy  = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp   = (5 * doy + 2) / 153;
    let d    = doy - (153 * mp + 2) / 5 + 1;
    let m    = if mp < 10 { mp + 3 } else { mp - 9 };
    let y    = if m <= 2 { y + 1 } else { y };

    let hour = (secs % 86_400) / 3_600;
    let min  = (secs % 3_600) / 60;
    let sec  = secs % 60;

    format!("{y:04}-{m:02}-{d:02} {hour:02}:{min:02}:{sec:02}")
}

/// Returns the status code as a plain string (ANSI colour if the terminal supports it,
/// but we keep it simple with no-escape fallback for redirect to file).
fn status_color(status: u16) -> String {
    // Use ANSI codes only when stdout is likely a terminal.
    // On Windows this works in Windows Terminal / VS Code integrated terminal.
    match status {
        200..=299 => format!("\x1b[32m{status}\x1b[0m"), // green
        300..=399 => format!("\x1b[36m{status}\x1b[0m"), // cyan
        400..=499 => format!("\x1b[33m{status}\x1b[0m"), // yellow
        500..=599 => format!("\x1b[31m{status}\x1b[0m"), // red
        _         => status.to_string(),
    }
}
