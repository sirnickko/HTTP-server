//! HTTP → HTTPS redirects, served by the plain-HTTP port when TLS is enabled.

use crate::{request::Request, response::Response};

/// Builds the redirect response for a request that arrived over plain HTTP.
///
/// GET and HEAD get `301`. Everything else (e.g. POST) gets `308`, which tells
/// the client to repeat the *same method and body* at the new URL; a `301`
/// would let many clients turn a POST into a GET and silently drop the body.
pub fn to_https(req: &Request, https_port: u16) -> Response {
    let location = location(
        req.headers.get("host").map(String::as_str),
        &req.path,
        &req.query,
        https_port,
    );
    let status = if matches!(req.method.as_str(), "GET" | "HEAD") { 301 } else { 308 };

    Response::new(status)
        .header("Location", &location)
        .header("Content-Type", "text/plain; charset=utf-8")
        .body_str(&format!("Moved to {location}\n"))
}

/// Builds the `https://` URL to redirect to.
///
/// Nothing from the request is trusted:
/// * the `Host` header is checked against a strict character set (a CR/LF in it
///   would let an attacker inject extra response headers), falling back to
///   `localhost` when it is missing or suspicious;
/// * the path and query are percent-encoded again before being echoed back.
fn location(host_header: Option<&str>, path: &str, query: &str, https_port: u16) -> String {
    let host = clean_host(host_header);

    let mut url = format!("https://{host}");
    if https_port != 443 {
        url.push_str(&format!(":{https_port}"));
    }

    // Path was already percent-decoded by the parser, so `%` itself must be encoded.
    url.push_str(&encode(path, b"/!$&'()*+,;=:@"));

    // Query was left raw by the parser; keep existing `%XX` escapes untouched.
    if !query.is_empty() {
        url.push('?');
        url.push_str(&encode(query, b"/!$&'()*+,;=:@?%"));
    }
    url
}

/// Extracts just the hostname (no port) from a `Host` header, or returns
/// `"localhost"` if it is absent or contains anything unexpected.
fn clean_host(host_header: Option<&str>) -> String {
    let raw = host_header.unwrap_or("").trim();

    let host = if raw.starts_with('[') {
        // Bracketed IPv6 literal, e.g. `[::1]:7878`: keep the brackets, drop the port.
        match raw.find(']') {
            Some(end) => &raw[..=end],
            None => "",
        }
    } else {
        raw.split(':').next().unwrap_or("")
    };

    let valid = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'[' | b']' | b':'));

    if valid { host.to_string() } else { "localhost".to_string() }
}

/// Percent-encodes every byte except unreserved characters (`A-Z a-z 0-9 - . _ ~`)
/// and the extra bytes listed in `keep`.
fn encode(input: &str, keep: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') || keep.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swaps_scheme_and_port() {
        assert_eq!(
            location(Some("example.com:7878"), "/index.html", "", 7443),
            "https://example.com:7443/index.html"
        );
    }

    #[test]
    fn default_https_port_is_omitted() {
        assert_eq!(location(Some("example.com"), "/", "", 443), "https://example.com/");
    }

    #[test]
    fn query_string_is_preserved() {
        assert_eq!(
            location(Some("example.com"), "/search", "q=rust&page=2", 443),
            "https://example.com/search?q=rust&page=2"
        );
    }

    #[test]
    fn ipv6_host_keeps_brackets_and_drops_port() {
        assert_eq!(location(Some("[::1]:7878"), "/", "", 7443), "https://[::1]:7443/");
    }

    #[test]
    fn missing_host_falls_back_to_localhost() {
        assert_eq!(location(None, "/", "", 7443), "https://localhost:7443/");
    }

    #[test]
    fn hostile_host_headers_are_rejected() {
        for bad in [
            "a.com\rSet-Cookie: x=1", // header injection
            "evil.com@good.com",      // userinfo trick
            "a.com/path",             // path smuggling
            "a b",                    // whitespace
            "",                       // empty
            "[::1",                   // unterminated IPv6
        ] {
            assert_eq!(clean_host(Some(bad)), "localhost", "host {bad:?} should be rejected");
        }
    }

    #[test]
    fn path_is_reencoded() {
        assert_eq!(location(Some("a.com"), "/a b/ü", "", 443), "https://a.com/a%20b/%C3%BC");
        // A literal `%` in a decoded path must not become an escape sequence.
        assert_eq!(location(Some("a.com"), "/100%", "", 443), "https://a.com/100%25");
    }

    #[test]
    fn control_characters_in_query_cannot_inject_headers() {
        let url = location(Some("a.com"), "/", "x=1\r\nSet-Cookie: y", 443);
        assert!(!url.contains('\r') && !url.contains('\n') && !url.contains(' '));
        assert_eq!(url, "https://a.com/?x=1%0D%0ASet-Cookie:%20y");
    }

    #[test]
    fn existing_escapes_in_query_are_not_double_encoded() {
        assert_eq!(location(Some("a.com"), "/", "q=a%20b", 443), "https://a.com/?q=a%20b");
    }
}
