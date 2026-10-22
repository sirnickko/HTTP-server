use std::{
    collections::HashMap,
    io::{self, BufRead},
};

// ─── Limits ──────────────────────────────────────────────────────────────────
// Every byte read from an untrusted client is bounded, so one connection can
// never make the server allocate an unbounded amount of memory.

/// Longest accepted request line (`GET /path HTTP/1.1`), in bytes.
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
/// Longest accepted single header line, in bytes.
pub const MAX_HEADER_LINE: usize = 8 * 1024;
/// Most header lines accepted in one request.
pub const MAX_HEADERS: usize = 100;
/// Most bytes accepted across all header lines of one request.
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Largest accepted request body, in bytes.
pub const MAX_BODY: usize = 1024 * 1024;

/// A fully parsed HTTP request.
#[derive(Debug)]
pub struct Request {
    pub method:  String,
    /// URL-decoded path, never contains `..` components.
    pub path:    String,
    /// Raw query string (everything after `?`), empty if absent.
    /// Used to preserve the query when redirecting HTTP to HTTPS.
    pub query:   String,
    /// Protocol version string: `"1.0"` or `"1.1"`.
    pub version: String,
    /// Header map with **lowercased** keys for case-insensitive lookup.
    pub headers: HashMap<String, String>,
    /// Request body bytes (populated from `Content-Length`).
    pub body:    Vec<u8>,
}

/// Errors that can occur while parsing a request off the wire.
#[derive(Debug)]
#[allow(dead_code)] // payloads are used via the Debug impl for diagnostics
pub enum ParseError {
    /// The underlying stream returned no data (client closed connection).
    ConnectionClosed,
    /// The request-line or headers were syntactically invalid → `400`.
    Malformed(String),
    /// The request line exceeded [`MAX_REQUEST_LINE`] → `414`.
    UriTooLong,
    /// A header line, the header count or the total header size exceeded its
    /// limit → `431`.
    HeadersTooLarge,
    /// `Content-Length` exceeded [`MAX_BODY`] → `413`.
    BodyTooLarge,
    /// The client used a feature we do not implement (e.g. chunked bodies) → `501`.
    NotImplemented(String),
    /// An I/O error occurred while reading.
    Io(io::Error),
}

impl ParseError {
    /// The HTTP status to answer with, or `None` when there is nobody left to
    /// answer (the client went away or the socket failed).
    pub fn status(&self) -> Option<u16> {
        match self {
            ParseError::Malformed(_)      => Some(400),
            ParseError::BodyTooLarge      => Some(413),
            ParseError::UriTooLong        => Some(414),
            ParseError::HeadersTooLarge   => Some(431),
            ParseError::NotImplemented(_) => Some(501),
            ParseError::ConnectionClosed | ParseError::Io(_) => None,
        }
    }
}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        use io::ErrorKind::*;
        match e.kind() {
            ConnectionReset | ConnectionAborted | UnexpectedEof | TimedOut | WouldBlock => {
                ParseError::ConnectionClosed
            }
            _ => ParseError::Io(e),
        }
    }
}

/// Reads one line (terminated by `\n`) of at most `limit` bytes, without the
/// line ending. `Ok(None)` means the stream ended before any byte was read.
///
/// Unlike `BufRead::read_line`, this never buffers more than `limit` bytes, so
/// a client that sends gigabytes without a newline gets `too_large` instead of
/// exhausting memory.
fn read_line_limited<R: BufRead>(
    reader: &mut R,
    limit: usize,
    too_large: fn() -> ParseError,
) -> Result<Option<String>, ParseError> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            // EOF. A half-received line is a closed connection, not a request.
            return if line.is_empty() { Ok(None) } else { Err(ParseError::ConnectionClosed) };
        }

        let (take, found_newline) = match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => (i + 1, true),
            None    => (chunk.len(), false),
        };
        if line.len() + take > limit + 2 {
            // +2 leaves room for the trailing `\r\n` that is not counted.
            return Err(too_large());
        }
        line.extend_from_slice(&chunk[..take]);
        reader.consume(take);

        if found_newline {
            break;
        }
    }

    // Strip `\n` and an optional preceding `\r`.
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.len() > limit {
        return Err(too_large());
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|_| ParseError::Malformed("request is not valid UTF-8".into()))
}

/// Reads one HTTP/1.x request from `reader` and returns a parsed [`Request`].
///
/// Generic over any buffered reader, so it works the same for a plain
/// `TcpStream` and for a decrypted TLS stream.
///
/// **Important**: the caller must keep the same buffered reader alive for the
/// entire connection. Creating a new `BufReader` on each call would silently
/// discard any bytes it had already read ahead from the stream, corrupting
/// subsequent keep-alive requests.
///
/// Returns `Err(ParseError::ConnectionClosed)` when the client has cleanly
/// closed the connection (zero-byte read on a keep-alive stream). Every other
/// error has a matching HTTP status, see [`ParseError::status`].
pub fn parse<R: BufRead>(reader: &mut R) -> Result<Request, ParseError> {

    // ── 1. Request line ──────────────────────────────────────────────────────
    let request_line = loop {
        let line = read_line_limited(reader, MAX_REQUEST_LINE, || ParseError::UriTooLong)?
            .ok_or(ParseError::ConnectionClosed)?;
        // Skip blank lines that may precede the request (RFC 7230 §3.5).
        if !line.trim().is_empty() {
            break line;
        }
    };

    let mut parts = request_line.trim().splitn(3, ' ');
    let method = parts
        .next()
        .filter(|m| !m.is_empty())
        .ok_or_else(|| ParseError::Malformed("missing method".into()))?
        .to_ascii_uppercase();
    let raw_target = parts
        .next()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ParseError::Malformed("missing request-target".into()))?;
    let version_str = parts
        .next()
        .ok_or_else(|| ParseError::Malformed("missing HTTP version".into()))?;

    let version = match version_str.strip_prefix("HTTP/") {
        Some(v @ ("1.0" | "1.1")) => v.to_string(),
        Some(other) => {
            return Err(ParseError::Malformed(format!("unsupported HTTP version: {other}")))
        }
        None => return Err(ParseError::Malformed(format!("bad version: {version_str}"))),
    };

    // Split path and query string.
    let (raw_path, query) = match raw_target.find('?') {
        Some(i) => (&raw_target[..i], raw_target[i + 1..].to_string()),
        None    => (raw_target, String::new()),
    };

    let path = url_decode_and_sanitise(raw_path);

    // ── 2. Headers ───────────────────────────────────────────────────────────
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut header_bytes = 0usize;
    let mut header_count = 0usize;
    loop {
        let line = read_line_limited(reader, MAX_HEADER_LINE, || ParseError::HeadersTooLarge)?
            .ok_or(ParseError::ConnectionClosed)?;
        if line.is_empty() {
            break; // blank line = end of headers
        }

        header_count += 1;
        header_bytes += line.len() + 2;
        if header_count > MAX_HEADERS || header_bytes > MAX_HEADER_BYTES {
            return Err(ParseError::HeadersTooLarge);
        }

        let (k, v) = line
            .split_once(':')
            .ok_or_else(|| ParseError::Malformed("header line without ':'".into()))?;
        let key = k.to_ascii_lowercase();
        // A name with spaces or other junk (including a leading space, i.e.
        // obsolete line folding) is rejected rather than guessed at.
        if key.is_empty() || !key.bytes().all(is_token_byte) {
            return Err(ParseError::Malformed(format!("bad header name: {k:?}")));
        }
        let value = v.trim().to_string();

        // Two different Content-Length values is a request-smuggling vector.
        if key == "content-length" {
            if let Some(existing) = headers.get(&key) {
                if *existing != value {
                    return Err(ParseError::Malformed("conflicting Content-Length headers".into()));
                }
            }
        }
        headers.insert(key, value);
    }

    // ── 3. Body ──────────────────────────────────────────────────────────────
    // We only understand Content-Length framing. Silently ignoring a chunked
    // body would leave its bytes on the wire to be misread as the next request.
    if headers.contains_key("transfer-encoding") {
        return Err(ParseError::NotImplemented("Transfer-Encoding is not supported".into()));
    }

    let body = match headers.get("content-length") {
        Some(len_str) => {
            let len: usize = len_str
                .parse()
                .map_err(|_| ParseError::Malformed("bad Content-Length".into()))?;
            // Check BEFORE allocating: this is the line that stops a
            // `Content-Length: 99999999999` from taking the server down.
            if len > MAX_BODY {
                return Err(ParseError::BodyTooLarge);
            }
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf)?;
            buf
        }
        None => Vec::new(),
    };

    Ok(Request { method, path, query, version, headers, body })
}

/// RFC 7230 `tchar`: the bytes allowed in a header field name.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Percent-decodes a URL path and removes any `..` components to prevent
/// directory traversal attacks. The result always starts with `/`.
fn url_decode_and_sanitise(raw: &str) -> String {
    // Percent-decode.
    let decoded = percent_decode(raw);

    // Normalise: split on `/`, drop empty and `.` segments, reject `..`.
    let mut parts: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".."     => { parts.pop(); } // go up (capped at root)
            other    => parts.push(other),
        }
    }

    let mut path = String::from("/");
    path.push_str(&parts.join("/"));
    // Preserve trailing slash.
    if raw.ends_with('/') && path != "/" {
        path.push('/');
    }
    path
}

/// Decodes `%XX` percent-encoded sequences in a URL string.
///
/// Collects raw bytes first so that multi-byte UTF-8 sequences (e.g. `%C3%A9` → `é`)
/// are decoded correctly. Invalid byte sequences are replaced with the Unicode
/// replacement character (`U+FFFD`) via [`String::from_utf8_lossy`].
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _           => None,
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Parser: happy path and limits ────────────────────────────────────────

    fn parse_bytes(raw: &[u8]) -> Result<Request, ParseError> {
        parse(&mut io::Cursor::new(raw.to_vec()))
    }

    #[test]
    fn parses_a_normal_request() {
        let req = parse_bytes(b"POST /a%20b?x=1 HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc").unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/a b");
        assert_eq!(req.query, "x=1");
        assert_eq!(req.version, "1.1");
        assert_eq!(req.headers["host"], "h");
        assert_eq!(req.body, b"abc");
    }

    #[test]
    fn accepts_bare_lf_line_endings() {
        assert!(parse_bytes(b"GET / HTTP/1.1\nHost: h\n\n").is_ok());
    }

    #[test]
    fn eof_is_connection_closed() {
        assert!(matches!(parse_bytes(b""), Err(ParseError::ConnectionClosed)));
        // Half a request line is also just a dropped connection.
        assert!(matches!(parse_bytes(b"GET / HT"), Err(ParseError::ConnectionClosed)));
    }

    #[test]
    fn rejects_garbage_with_400() {
        for raw in [
            &b"GARBAGE\r\n\r\n"[..],
            b"GET /\r\n\r\n",                       // no version
            b"GET / HTTP/9.9\r\n\r\n",              // unsupported version
            b"GET / FTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nno-colon-here\r\n\r\n",
            b"GET / HTTP/1.1\r\n folded: x\r\n\r\n", // leading space in name
            b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
            b"GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        ] {
            let err = parse_bytes(raw).unwrap_err();
            assert_eq!(err.status(), Some(400), "{:?} -> {err:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        let err = parse_bytes(b"GET /\xff HTTP/1.1\r\n\r\n").unwrap_err();
        assert_eq!(err.status(), Some(400));
    }

    #[test]
    fn long_request_line_is_414_without_buffering_it_all() {
        let raw = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_REQUEST_LINE));
        assert_eq!(parse_bytes(raw.as_bytes()).unwrap_err().status(), Some(414));

        // No newline at all: must fail at the limit instead of reading forever.
        let endless = vec![b'a'; MAX_REQUEST_LINE * 4];
        assert_eq!(parse_bytes(&endless).unwrap_err().status(), Some(414));
    }

    #[test]
    fn request_line_exactly_at_the_limit_is_accepted() {
        let path = "a".repeat(MAX_REQUEST_LINE - "GET / HTTP/1.1".len());
        let raw = format!("GET /{path} HTTP/1.1\r\n\r\n");
        assert_eq!(raw.len() - 4, MAX_REQUEST_LINE);
        assert!(parse_bytes(raw.as_bytes()).is_ok());
    }

    #[test]
    fn oversized_header_line_is_431() {
        let raw = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEADER_LINE));
        assert_eq!(parse_bytes(raw.as_bytes()).unwrap_err().status(), Some(431));
    }

    #[test]
    fn too_many_headers_is_431() {
        let mut raw = String::from("GET / HTTP/1.1\r\n");
        for i in 0..=MAX_HEADERS {
            raw.push_str(&format!("X-{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        assert_eq!(parse_bytes(raw.as_bytes()).unwrap_err().status(), Some(431));
    }

    #[test]
    fn total_header_size_is_capped() {
        // 10 lines of ~4 KB each: every line is legal, the total is not.
        let mut raw = String::from("GET / HTTP/1.1\r\n");
        for i in 0..10 {
            raw.push_str(&format!("X-{i}: {}\r\n", "a".repeat(4000)));
        }
        raw.push_str("\r\n");
        assert_eq!(parse_bytes(raw.as_bytes()).unwrap_err().status(), Some(431));
    }

    #[test]
    fn huge_content_length_is_413_before_any_allocation() {
        // If this tried to allocate 99 GB the test process would die.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n";
        assert_eq!(parse_bytes(raw).unwrap_err().status(), Some(413));
        let raw = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(parse_bytes(raw.as_bytes()).unwrap_err().status(), Some(413));
    }

    #[test]
    fn body_exactly_at_the_limit_is_accepted() {
        let mut raw = format!("POST / HTTP/1.1\r\nContent-Length: {MAX_BODY}\r\n\r\n").into_bytes();
        raw.extend(std::iter::repeat_n(b'x', MAX_BODY));
        assert_eq!(parse_bytes(&raw).unwrap().body.len(), MAX_BODY);
    }

    #[test]
    fn short_body_is_a_closed_connection() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc";
        assert!(matches!(parse_bytes(raw), Err(ParseError::ConnectionClosed)));
    }

    #[test]
    fn conflicting_content_lengths_are_rejected() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd";
        assert_eq!(parse_bytes(raw).unwrap_err().status(), Some(400));
        // Repeating the same value is harmless.
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc";
        assert!(parse_bytes(raw).is_ok());
    }

    #[test]
    fn chunked_bodies_are_501() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(parse_bytes(raw).unwrap_err().status(), Some(501));
    }

    #[test]
    fn two_requests_on_one_stream_are_parsed_in_order() {
        let mut cur = io::Cursor::new(
            b"GET /one HTTP/1.1\r\n\r\nPOST /two HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi".to_vec(),
        );
        assert_eq!(parse(&mut cur).unwrap().path, "/one");
        let second = parse(&mut cur).unwrap();
        assert_eq!((second.path.as_str(), second.body.as_slice()), ("/two", &b"hi"[..]));
        assert!(matches!(parse(&mut cur), Err(ParseError::ConnectionClosed)));
    }

    #[test]
    fn sanitise_normal_path() {
        assert_eq!(url_decode_and_sanitise("/index.html"), "/index.html");
        assert_eq!(url_decode_and_sanitise("/"),           "/");
        assert_eq!(url_decode_and_sanitise("/a/b/c"),      "/a/b/c");
    }

    #[test]
    fn sanitise_traversal() {
        // `..` must never escape the root.
        assert_eq!(url_decode_and_sanitise("/../etc/passwd"), "/etc/passwd");
        assert_eq!(url_decode_and_sanitise("/a/../../b"),     "/b");
        assert_eq!(url_decode_and_sanitise("/../../.."),      "/");
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("/hello%20world"), "/hello world");
        assert_eq!(percent_decode("/caf%C3%A9"),     "/café");
        assert_eq!(percent_decode("/no-encoding"),   "/no-encoding");
    }

    #[test]
    fn trailing_slash_preserved() {
        assert_eq!(url_decode_and_sanitise("/dir/"), "/dir/");
    }
}
