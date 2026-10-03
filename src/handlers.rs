use std::{
    fs,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use crate::{mime, request::Request, response::Response};

/// The directory from which static files are served.
const WWW_ROOT: &str = "www";

/// Routes a parsed request to the appropriate handler and returns a [`Response`].
pub fn dispatch(req: &Request) -> (Response, bool) {
    let send_body = req.method != "HEAD";
    let resp = match req.method.as_str() {
        "GET" | "HEAD" => handle_get(req),
        "POST"         => handle_post(req),
        _              => method_not_allowed(),
    };
    (resp, send_body)
}

// ─── GET / HEAD ───────────────────────────────────────────────────────────────

fn handle_get(req: &Request) -> Response {
    let fs_path = resolve_path(&req.path);

    match fs_path {
        None => not_found(),
        Some(path) => {
            if path.is_dir() {
                // Redirect bare directory URLs to the trailing-slash form.
                if !req.path.ends_with('/') {
                    return redirect_301(&format!("{}/", req.path));
                }
                // Look for index.html inside the directory.
                let index = path.join("index.html");
                if index.is_file() {
                    serve_file(&index, req)
                } else {
                    directory_listing(&path, &req.path)
                }
            } else if path.is_file() {
                serve_file(&path, req)
            } else {
                not_found()
            }
        }
    }
}

/// Resolves a URL path to a filesystem path within `WWW_ROOT`.
/// Returns `None` if the path would escape the root (safety check,
/// though `request::parse` already sanitises `..` components).
fn resolve_path(url_path: &str) -> Option<PathBuf> {
    // Strip the leading `/`.
    let relative = url_path.trim_start_matches('/');
    let base = PathBuf::from(WWW_ROOT);
    let target = base.join(relative);

    // Canonicalise to detect symlink escapes on real deployments.
    // `canonicalize` fails if the path doesn't exist, so we do a prefix
    // check on the non-canonicalised path only (sufficient for our purposes).
    let base_abs = fs::canonicalize(&base).unwrap_or(base.clone());
    // For paths that don't exist yet (→ 404), just return the raw target.
    if !target.exists() {
        return Some(target);
    }
    let target_abs = fs::canonicalize(&target).ok()?;
    if target_abs.starts_with(&base_abs) {
        Some(target_abs)
    } else {
        None // escape attempt
    }
}

/// Serves a single file, handling ETag-based caching.
fn serve_file(path: &Path, req: &Request) -> Response {
    let meta = match fs::metadata(path) {
        Ok(m)  => m,
        Err(_) => return internal_error("could not read file metadata"),
    };

    let file_size = meta.len();
    let mtime_secs = meta
        .modified()
        .unwrap_or(UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // ETag: "{size_hex}-{mtime_hex}" — same format as nginx's weak ETag.
    let etag = format!("\"{file_size:x}-{mtime_secs:x}\"");

    // If-None-Match check → 304.
    if let Some(inm) = req.headers.get("if-none-match") {
        if inm.trim() == etag || inm.trim() == "*" {
            return Response::new(304)
                .header("ETag", &etag)
                .header("Cache-Control", "max-age=3600");
        }
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let content_type = mime::from_ext(ext);

    let body = match fs::read(path) {
        Ok(b)  => b,
        Err(_) => return internal_error("could not read file"),
    };

    let last_modified = http_date(mtime_secs);

    Response::new(200)
        .header("Content-Type",  content_type)
        .header("ETag",          &etag)
        .header("Last-Modified", &last_modified)
        .header("Cache-Control", "max-age=3600")
        .body(body)
}

/// Generates an HTML directory listing page.
fn directory_listing(dir: &Path, url_path: &str) -> Response {
    let entries = match fs::read_dir(dir) {
        Ok(e)  => e,
        Err(_) => return internal_error("could not read directory"),
    };

    let mut rows = String::new();
    if url_path != "/" {
        rows.push_str(r#"<tr><td><a href="../">../</a></td><td>-</td><td>-</td></tr>"#);
    }

    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let display = if is_dir { format!("{name}/") } else { name.to_string() };
        let href    = if is_dir { format!("{name}/") } else { name.to_string() };

        let size = if is_dir {
            "-".to_string()
        } else {
            entry.metadata().map(|m| format_size(m.len())).unwrap_or_else(|_| "-".to_string())
        };

        let mtime = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| http_date(d.as_secs()))
            .unwrap_or_else(|| "-".to_string());

        rows.push_str(&format!(
            "<tr><td><a href=\"{href}\">{display}</a></td><td>{size}</td><td>{mtime}</td></tr>\n"
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Index of {url_path}</title>
  <style>
    body {{ font-family: monospace; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }}
    h1 {{ border-bottom: 1px solid #ccc; padding-bottom: .5rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ text-align: left; padding: .4rem .8rem; border-bottom: 1px solid #eee; }}
    th {{ background: #f4f4f4; }}
    a {{ color: #0066cc; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <h1>Index of {url_path}</h1>
  <table>
    <thead><tr><th>Name</th><th>Size</th><th>Last Modified</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"#
    );

    Response::new(200)
        .header("Content-Type", "text/html; charset=utf-8")
        .body_str(&html)
}

// ─── POST ─────────────────────────────────────────────────────────────────────

fn handle_post(req: &Request) -> Response {
    let body_len = req.body.len();
    let preview  = String::from_utf8_lossy(req.body.get(..256.min(body_len)).unwrap_or(&[]));

    println!(
        "  POST {} — body {} byte(s): {}{}",
        req.path,
        body_len,
        preview,
        if body_len > 256 { "…" } else { "" }
    );

    let reply = format!(
        "Received POST to {}\nBody length: {} byte(s)\nBody preview: {}\n",
        req.path, body_len, preview
    );

    Response::new(200)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body_str(&reply)
}

// ─── Error / redirect helpers ────────────────────────────────────────────────

fn not_found() -> Response {
    // Try to serve a custom 404 page.
    let custom = PathBuf::from(WWW_ROOT).join("404.html");
    let body = if custom.is_file() {
        fs::read(&custom).unwrap_or_else(|_| b"404 Not Found".to_vec())
    } else {
        b"<h1>404 Not Found</h1>".to_vec()
    };
    Response::new(404)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(body)
}

fn internal_error(msg: &str) -> Response {
    eprintln!("  Internal error: {msg}");
    Response::new(500)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body_str(&format!("500 Internal Server Error\n{msg}\n"))
}

fn method_not_allowed() -> Response {
    Response::new(405)
        .header("Allow",        "GET, POST, HEAD")
        .header("Content-Type", "text/plain; charset=utf-8")
        .body_str("405 Method Not Allowed\nSupported methods: GET, POST, HEAD\n")
}

fn redirect_301(location: &str) -> Response {
    Response::new(301)
        .header("Location",     location)
        .header("Content-Type", "text/html; charset=utf-8")
        .body_str(&format!(
            "<html><body>Redirecting to <a href=\"{location}\">{location}</a></body></html>"
        ))
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

/// Formats a Unix timestamp as an HTTP-date string per RFC 7231.
/// e.g. `Sat, 01 Jan 2000 00:00:00 GMT`
pub fn http_date(secs: u64) -> String {
    // Decompose Unix timestamp → calendar (UTC).
    // Algorithm: https://howardhinnant.github.io/date_algorithms.html
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

    // Day of week: 0=Sun … 6=Sat  (Unix epoch Jan 1 1970 was a Thursday = 4)
    let dow = (secs / 86_400 + 4) % 7;

    let hour = (secs % 86_400) / 3_600;
    let min  = (secs % 3_600) / 60;
    let sec  = secs % 60;

    const DAYS:   [&str; 7] = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
    const MONTHS: [&str; 13] = ["","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[dow as usize], d, MONTHS[m as usize], y, hour, min, sec
    )
}

/// Human-readable file size (B, KB, MB, GB).
fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    match bytes {
        b if b >= GB => format!("{:.1} GB", b as f64 / GB as f64),
        b if b >= MB => format!("{:.1} MB", b as f64 / MB as f64),
        b if b >= KB => format!("{:.1} KB", b as f64 / KB as f64),
        b            => format!("{b} B"),
    }
}
