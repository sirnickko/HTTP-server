use std::{
    io::{BufReader, Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::ServerConfig;

use crate::{
    handlers, logger, redirect,
    request::{self, ParseError},
    response::Response,
    tls::{self, TlsStream},
};

// ── HSTS max-age (1 year in seconds, as recommended by HSTS spec) ─────────────
const HSTS_MAX_AGE: &str = "max-age=31536000; includeSubDomains";

/// Idle timeout per keep-alive window, also bounding the TLS handshake.
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// A connection is closed after this long however busy it is.
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_secs(300);

/// Most requests served on one connection before we ask the client to
/// reconnect. This is the `max=` value advertised in the `Keep-Alive` header.
pub const MAX_REQUESTS_PER_CONNECTION: u32 = 100;

/// How long a single read may wait while draining a rejected request.
const LINGER_READ_TIMEOUT: Duration = Duration::from_millis(200);
/// Total time spent draining a rejected request before giving up.
const LINGER_TOTAL: Duration = Duration::from_secs(1);
/// Most bytes discarded while draining a rejected request.
const LINGER_MAX_BYTES: usize = 1024 * 1024;

/// What a connection is for.
enum Mode {
    /// The HTTPS port: serve files, and add HSTS to every response.
    Https,
    /// The plain-HTTP port: its only job is to redirect to HTTPS.
    Redirect { https_port: u16 },
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Handles one **plain HTTP** connection by redirecting every request to the
/// `https://` equivalent (`301` for GET/HEAD, `308` for anything else so the
/// method and body survive). See [`redirect::to_https`].
pub fn handle_http_redirect(mut stream: TcpStream, https_port: u16) {
    stream.set_read_timeout(Some(IDLE_TIMEOUT)).ok();
    serve(&mut stream, &Mode::Redirect { https_port });
}

/// Handles one **TLS** connection for its full lifetime.
///
/// The handshake is performed lazily by rustls on the first read, which
/// happens inside this connection's own worker, so a slow client can never
/// stall the accept loop.
pub fn handle_https(tcp: TcpStream, config: Arc<ServerConfig>) {
    // Set before wrapping: rustls reads through to the raw socket, so this
    // timeout covers the handshake and every later TLS record read.
    tcp.set_read_timeout(Some(IDLE_TIMEOUT)).ok();

    let mut stream = match tls::accept(config, tcp) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("  TLS setup error: {e}");
            return;
        }
    };

    serve(&mut stream, &Mode::Https);

    // Only close politely if a handshake actually completed. (Port scans and
    // plain-HTTP clients hitting the HTTPS port never get this far.)
    if !stream.conn.is_handshaking() {
        let version = stream.conn.protocol_version();
        let suite = stream.conn.negotiated_cipher_suite().map(|s| s.suite());
        println!("  TLS connection closed: {version:?} {suite:?}");
        // `close_notify` lets the client tell a clean end of stream from a
        // truncation attack.
        stream.conn.send_close_notify();
        stream.flush().ok();
    }
}

// ── Closing a rejected connection politely ────────────────────────────────────

/// A connection that can discard the client's remaining input after we have
/// rejected a request.
///
/// When we answer a bad request (say a 431) the client may still be sending
/// the rest of it. Closing a socket that has unread incoming data makes the
/// kernel send a TCP reset, and the client can then throw our response away
/// and report "connection reset" instead of the real error. So we first read
/// and discard the remaining input, for a short and strictly bounded time.
trait DrainInput {
    fn drain_input(&mut self);
}

fn discard(r: &mut impl Read) {
    let deadline = Instant::now() + LINGER_TOTAL;
    let mut buf = [0u8; 8192];
    let mut total = 0usize;
    while total < LINGER_MAX_BYTES && Instant::now() < deadline {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break, // client finished, hung up, or went quiet
            Ok(n) => total += n,
        }
    }
}

impl DrainInput for TcpStream {
    fn drain_input(&mut self) {
        self.flush().ok();
        // Tell the client our response is complete, then wait for it to finish.
        self.shutdown(Shutdown::Write).ok();
        self.set_read_timeout(Some(LINGER_READ_TIMEOUT)).ok();
        discard(self);
    }
}

impl DrainInput for TlsStream {
    fn drain_input(&mut self) {
        // Push our response out; the caller sends `close_notify` afterwards.
        self.flush().ok();
        self.sock.set_read_timeout(Some(LINGER_READ_TIMEOUT)).ok();
        discard(self);
    }
}

// ── The HTTP/1.1 keep-alive loop ──────────────────────────────────────────────

/// Serves requests on one connection until the client closes it, we hit the
/// idle timeout, the client sends `Connection: close`, or a limit is reached.
/// Shared by the HTTPS port and the redirect port.
fn serve<S: Read + Write + DrainInput>(stream: &mut S, mode: &Mode) {
    // ── ONE BufReader for the whole connection lifetime ───────────────────────
    // BufReader reads ahead from the stream into an internal buffer. A new
    // BufReader per request would drop those already-read bytes, silently
    // losing the start of the next request whenever a client sends two
    // requests back to back (pipelining).
    //
    // Responses are written through `reader.get_mut()` rather than a second
    // handle: a TLS stream needs `&mut` access for both reading and writing,
    // so it cannot be shared the way `&TcpStream` can.
    let mut reader = BufReader::new(&mut *stream);
    let started = Instant::now();
    let mut served: u32 = 0;

    loop {
        // ── Parse the next request off the wire ──────────────────────────────
        let req = match request::parse(&mut reader) {
            Ok(r) => r,
            Err(e) => {
                // A bad request gets a real answer (400, 413, 414, 431, 501)
                // before the connection is closed. After a framing error we
                // cannot know where the next request would start, so the
                // connection is never kept open. Closed or broken connections
                // have nobody left to answer.
                match e.status() {
                    Some(status) => {
                        let resp = finish(error_response(status, &e), false, 0, mode);
                        if resp.write_to(reader.get_mut(), true).is_ok() {
                            eprintln!("  Rejected request: {e:?} -> {status}");
                            // Let the client finish sending before we close,
                            // so it sees this response, not a reset.
                            reader.get_mut().drain_input();
                        }
                    }
                    None => {
                        if let ParseError::Io(err) = &e {
                            eprintln!("  Connection error: {err}");
                        }
                    }
                }
                break;
            }
        };
        served += 1;

        // ── Decide keep-alive ─────────────────────────────────────────────────
        // HTTP/1.1: persistent by default unless the client says "close".
        // HTTP/1.0: close by default unless the client says "keep-alive".
        // Either way, stop at the request and lifetime caps.
        let conn_header = req
            .headers
            .get("connection")
            .map(|v| v.to_ascii_lowercase());

        let client_wants_keep_alive = match req.version.as_str() {
            "1.1" => conn_header.as_deref() != Some("close"),
            _     => conn_header.as_deref() == Some("keep-alive"),
        };
        let keep_alive = client_wants_keep_alive
            && served < MAX_REQUESTS_PER_CONNECTION
            && started.elapsed() < MAX_CONNECTION_LIFETIME;

        // ── Dispatch ──────────────────────────────────────────────────────────
        let t0 = Instant::now();
        let (resp, send_body) = match mode {
            Mode::Redirect { https_port } => {
                (redirect::to_https(&req, *https_port), req.method != "HEAD")
            }
            Mode::Https => handlers::dispatch(&req),
        };

        let remaining = MAX_REQUESTS_PER_CONNECTION - served;
        let resp = finish(resp, keep_alive, remaining, mode);
        let status = resp.status;

        // ── Write response ────────────────────────────────────────────────────
        if let Err(e) = resp.write_to(reader.get_mut(), send_body) {
            eprintln!("  Write error: {e}");
            break;
        }

        logger::log(&req, status, t0.elapsed());

        if !keep_alive {
            break;
        }
    }
}

/// Adds the headers every response carries, whichever handler produced it.
fn finish(mut resp: Response, keep_alive: bool, remaining: u32, mode: &Mode) -> Response {
    // Tell the client what we decided about the connection.
    resp = resp.header("Connection", if keep_alive { "keep-alive" } else { "close" });
    if keep_alive {
        resp = resp.header(
            "Keep-Alive",
            format!("timeout={}, max={remaining}", IDLE_TIMEOUT.as_secs()),
        );
    }

    // ── HSTS — injected on every HTTPS response ───────────────────────────────
    // This tells browsers to always use HTTPS for this origin for 1 year.
    // After receiving this header, a browser will refuse to connect over
    // plain HTTP (even if the user types http://). That's the point.
    if let Mode::Https = mode {
        resp = resp.header("Strict-Transport-Security", HSTS_MAX_AGE);
    }
    resp
}

/// Plain-text error page for a request that could not be parsed.
fn error_response(status: u16, err: &ParseError) -> Response {
    let detail = match err {
        ParseError::Malformed(why) | ParseError::NotImplemented(why) => why.as_str(),
        ParseError::UriTooLong      => "the request line is too long",
        ParseError::HeadersTooLarge => "the request headers are too large",
        ParseError::BodyTooLarge    => "the request body is too large",
        ParseError::ConnectionClosed | ParseError::Io(_) => "",
    };
    Response::new(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body_str(&format!("{status}\n{detail}\n"))
}
