use std::{
    io::BufReader,
    net::TcpStream,
    time::{Duration, Instant},
};

use crate::{handlers, logger, request};

/// Handles one TCP connection for its full lifetime.
///
/// Implements the HTTP/1.1 keep-alive loop: keeps reading requests on the same
/// stream until the client closes the connection, we hit the read timeout, or
/// the client sends `Connection: close`.
pub fn handle_connection(stream: TcpStream) {
    // 5-second idle timeout per keep-alive window.
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    // ── Create ONE BufReader for the whole connection lifetime ────────────────
    // This is critical: BufReader reads ahead from the TCP stream into an
    // internal buffer. If we created a new BufReader on every request::parse
    // call, the old buffer would be dropped and those already-read bytes would
    // be silently lost, corrupting subsequent keep-alive requests.
    let mut reader = BufReader::new(&stream);

    loop {
        // ── Parse the next request off the wire ──────────────────────────────
        let req = match request::parse(&mut reader) {
            Ok(r)  => r,
            Err(_) => break, // connection closed, timed out, or malformed
        };

        // ── Decide keep-alive ─────────────────────────────────────────────────
        // HTTP/1.1: persistent by default unless the client says "close".
        // HTTP/1.0: close by default unless the client says "keep-alive".
        let conn_header = req
            .headers
            .get("connection")
            .map(|v| v.to_ascii_lowercase());

        let keep_alive = match req.version.as_str() {
            "1.1" => conn_header.as_deref() != Some("close"),
            _     => conn_header.as_deref() == Some("keep-alive"),
        };

        // ── Dispatch ──────────────────────────────────────────────────────────
        let start = Instant::now();
        let (mut resp, send_body) = handlers::dispatch(&req);

        // Inject Connection header so the client knows what we decided.
        let conn_value = if keep_alive { "keep-alive" } else { "close" };
        resp = resp.header("Connection", conn_value);
        if keep_alive {
            resp = resp.header("Keep-Alive", "timeout=5, max=100");
        }

        let status = resp.status;

        // ── Write response ────────────────────────────────────────────────────
        if let Err(e) = resp.write_to(&mut &stream, send_body) {
            eprintln!("  Write error: {e}");
            break;
        }

        // ── Log ───────────────────────────────────────────────────────────────
        logger::log(&req, status, start.elapsed());

        if !keep_alive {
            break;
        }
    }
}
