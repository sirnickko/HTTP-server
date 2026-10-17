use std::{
    collections::HashMap,
    io::{self, BufRead, BufReader, Read},
};


/// A fully parsed HTTP request.
#[derive(Debug)]
pub struct Request {
    pub method:  String,
    /// URL-decoded path, never contains `..` components.
    pub path:    String,
    /// Raw query string (everything after `?`), empty if absent.
    /// Kept for future use (e.g. POST form parsing, routing).
    #[allow(dead_code)]
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
    /// The request-line or headers were syntactically invalid.
    Malformed(String),
    /// An I/O error occurred while reading.
    Io(io::Error),
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

/// Reads one HTTP/1.x request from `reader` and returns a parsed [`Request`].
///
/// **Important**: the caller must keep the same `BufReader` alive for the entire
/// connection. Creating a new `BufReader` on each call would silently discard
/// any bytes it had already read ahead from the TCP stream, corrupting subsequent
/// keep-alive requests.
///
/// Returns `Err(ParseError::ConnectionClosed)` when the client has cleanly
/// closed the connection (zero-byte read on a keep-alive stream).
/// Works over any `Read` implementor — plain `TcpStream` or a TLS-wrapped
/// stream both satisfy the bound, so no specialised code is needed.
pub fn parse<R: Read>(reader: &mut BufReader<R>) -> Result<Request, ParseError> {

    // ── 1. Request line ──────────────────────────────────────────────────────
    let mut request_line = String::new();
    loop {
        let n = reader.read_line(&mut request_line)?;
        if n == 0 {
            return Err(ParseError::ConnectionClosed);
        }
        // Skip blank lines that may precede the request (RFC 7230 §3.5).
        if request_line.trim().is_empty() {
            request_line.clear();
            continue;
        }
        break;
    }

    let request_line = request_line.trim();
    let mut parts = request_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| ParseError::Malformed("missing method".into()))?
        .to_ascii_uppercase();
    let raw_target = parts
        .next()
        .ok_or_else(|| ParseError::Malformed("missing request-target".into()))?;
    let version_str = parts
        .next()
        .ok_or_else(|| ParseError::Malformed("missing HTTP version".into()))?;

    let version = if version_str.starts_with("HTTP/") {
        version_str["HTTP/".len()..].to_string()
    } else {
        return Err(ParseError::Malformed(format!("bad version: {version_str}")));
    };

    // Split path and query string.
    let (raw_path, query) = match raw_target.find('?') {
        Some(i) => (&raw_target[..i], raw_target[i + 1..].to_string()),
        None    => (raw_target, String::new()),
    };

    let path = url_decode_and_sanitise(raw_path);

    // ── 2. Headers ───────────────────────────────────────────────────────────
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err(ParseError::ConnectionClosed);
        }
        let line = line.trim();
        if line.is_empty() {
            break; // blank line = end of headers
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
        // Lines without `:` are malformed continuation lines — we silently skip them.
    }

    // ── 3. Body ──────────────────────────────────────────────────────────────
    let body = if let Some(len_str) = headers.get("content-length") {
        let len: usize = len_str
            .parse()
            .map_err(|_| ParseError::Malformed("bad Content-Length".into()))?;
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        Vec::new()
    };

    Ok(Request { method, path, query, version, headers, body })
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
