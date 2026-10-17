use std::{
    io::{BufReader, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

use crate::{handlers, logger, request};

// ── HSTS max-age (1 year in seconds, as recommended by HSTS spec) ─────────────
const HSTS_MAX_AGE: &str = "max-age=31536000; includeSubDomains";

// ── Plain-TCP connection: HTTP (used for HTTP→HTTPS redirect on port 80) ──────

/// Handles one **plain HTTP** TCP connection.
///
/// This is intentionally minimal: every request gets a `301 Moved Permanently`
/// redirect to the `https://` equivalent regardless of method.  No keep-alive
/// is maintained because redirecting clients will immediately reconnect on TLS.
pub fn handle_http_redirect(stream: TcpStream, https_port: u16) {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut reader = BufReader::new(&stream);

    // We only need to parse the Host and path to build the redirect URL.
    if let Ok(req) = request::parse(&mut reader) {
        let host = req
            .headers
            .get("host")
            .map(|h| {
                // Strip any existing port from the Host header before re-adding ours.
                match h.rfind(':') {
                    Some(i) if h[i + 1..].parse::<u16>().is_ok() => h[..i].to_string(),
                    _ => h.clone(),
                }
            })
            .unwrap_or_else(|| "localhost".to_string());

        // Build the Location URL.  If HTTPS is on the standard port 443 we
        // omit it, otherwise we include it explicitly so browsers connect to
        // the right port (useful during development when port 4433 is used).
        let location = if https_port == 443 {
            format!("https://{host}{}", req.path)
        } else {
            format!("https://{host}:{https_port}{}", req.path)
        };

        let body = format!(
            "<html><body>Redirecting to <a href=\"{location}\">{location}</a></body></html>"
        );
        let response = format!(
            "HTTP/1.1 301 Moved Permanently\r\n\
             Location: {location}\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len()
        );
        let _ = (&stream).write_all(response.as_bytes());
    }
}

// ── TLS connection handler (generic over the stream type) ─────────────────────

/// Handles one **TLS** connection for its full lifetime.
///
/// Works with any `stream` that implements `Read + Write` — concretely this
/// will be a `rustls::StreamOwned<ServerConnection, TcpStream>`, but the
/// function is generic so the unit-test harness can pass a plain `Vec<u8>`.
///
/// ## What this adds over the plain HTTP handler
/// - **HSTS** (`Strict-Transport-Security`) is injected into every response.
/// - Keep-alive loop is fully preserved (same semantics as the original handler).
pub fn handle_connection<S>(stream: S)
where
    S: std::io::Read + Write,
{
    handle_connection_inner(stream);
}

fn handle_connection_inner<S: std::io::Read + Write>(stream: S) {
    // We need separate read/write halves but `S` might not be `Clone` or
    // splittable (TLS streams are not).  The trick: wrap in a `ReadWrite`
    // newtype that holds the stream behind a `RefCell`, then borrow it for
    // reading via `BufReader` and for writing directly.
    //
    // Actually the cleanest approach for a single-threaded connection handler
    // is to use `unsafe` split — but rustls's `StreamOwned` is `!Sync`, so
    // instead we use a small wrapper that implements `Read` for the reader
    // side while keeping a raw pointer for writes.  To keep things safe and
    // readable we simply box the stream and use `std::io::split` via trait
    // object indirection.
    //
    // Simplest correct approach: store the stream in a `Box`, use a raw
    // reference for the BufReader, and write through the original box.
    // This is safe because BufReader and the write half are used strictly
    // sequentially (read request → write response → repeat).

    let mut stream = stream;

    // We cannot directly create a BufReader<&mut S> and also write to `stream`
    // in the same scope without fighting the borrow checker.  The standard
    // Rust idiom for a single owned stream that must be both read and written
    // is to use `std::io::Read::by_ref()` for the BufReader, then drop it
    // before writing.  We restructure the loop accordingly.

    let timeout_dur = Duration::from_secs(5);
    let start_time  = Instant::now();

    loop {
        // Build a temporary BufReader that borrows `stream` for the parse.
        let req = {
            let mut reader = BufReader::new(std::io::Read::by_ref(&mut stream));
            match request::parse(&mut reader) {
                Ok(r)  => r,
                Err(_) => break,
            }
            // `reader` is dropped here, releasing the borrow on `stream`.
        };

        // Check idle timeout manually (rustls streams don't expose set_read_timeout).
        if start_time.elapsed() > Duration::from_secs(300) {
            break; // 5-minute total connection lifetime cap
        }

        // Keep-alive decision.
        let conn_header = req
            .headers
            .get("connection")
            .map(|v| v.to_ascii_lowercase());
        let keep_alive = match req.version.as_str() {
            "1.1" => conn_header.as_deref() != Some("close"),
            _     => conn_header.as_deref() == Some("keep-alive"),
        };

        let t0 = Instant::now();
        let (mut resp, send_body) = handlers::dispatch(&req);

        // Connection header.
        let conn_value = if keep_alive { "keep-alive" } else { "close" };
        resp = resp.header("Connection", conn_value);
        if keep_alive {
            resp = resp.header("Keep-Alive", "timeout=5, max=100");
        }

        // ── HSTS — injected on every HTTPS response ───────────────────────────
        // This tells browsers to always use HTTPS for this origin for 1 year.
        // After receiving this header, a browser will refuse to connect over
        // plain HTTP (even if the user types http://) — that's the point.
        resp = resp.header("Strict-Transport-Security", HSTS_MAX_AGE);

        let status = resp.status;

        // Write response directly through the stream (BufReader borrow is gone).
        if let Err(e) = resp.write_to(&mut stream, send_body) {
            eprintln!("  Write error: {e}");
            break;
        }

        logger::log(&req, status, t0.elapsed());

        if !keep_alive {
            break;
        }

        // Per-request idle timeout emulation: if we've been quiet for 5s the
        // next `read_line` inside `parse` will block.  For TLS streams we
        // rely on the OS-level TCP timeout set on the underlying `TcpStream`
        // before wrapping (done in main.rs).
        let _ = timeout_dur; // suppress unused-variable warning
    }
}
