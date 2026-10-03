use std::io::{self, Write};

/// An HTTP response ready to be serialised onto a TCP stream.
pub struct Response {
    pub status:  u16,
    headers:     Vec<(String, String)>,
    body:        Vec<u8>,
}

impl Response {
    /// Create a response with the given status code and an empty body.
    pub fn new(status: u16) -> Self {
        Self { status, headers: Vec::new(), body: Vec::new() }
    }

    /// Append a response header. Takes `self` so calls can be chained.
    pub fn header(mut self, key: &str, value: impl Into<String>) -> Self {
        self.headers.push((key.to_string(), value.into()));
        self
    }

    /// Set the response body. Replaces any previously set body.
    pub fn body(mut self, data: Vec<u8>) -> Self {
        self.body = data;
        self
    }

    /// Convenience: set a UTF-8 text body.
    pub fn body_str(self, s: &str) -> Self {
        self.body(s.as_bytes().to_vec())
    }

    /// Serialise the response to `writer`.
    ///
    /// The `Content-Length` header is always added automatically from `body.len()`.
    /// If `send_body` is `false` (HEAD requests), headers are written but the body
    /// bytes are not sent (the `Content-Length` still reflects the true body size,
    /// as required by RFC 7231 §4.3.2).
    pub fn write_to(&self, writer: &mut impl Write, send_body: bool) -> io::Result<()> {
        let reason = reason_phrase(self.status);
        // Status line
        write!(writer, "HTTP/1.1 {} {}\r\n", self.status, reason)?;
        // Headers provided by caller
        for (k, v) in &self.headers {
            write!(writer, "{k}: {v}\r\n")?;
        }
        // Auto content-length
        write!(writer, "Content-Length: {}\r\n", self.body.len())?;
        // Blank line
        writer.write_all(b"\r\n")?;
        // Body (skipped for HEAD)
        if send_body {
            writer.write_all(&self.body)?;
        }
        writer.flush()
    }
}

/// Maps a status code to the standard reason phrase.
fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _   => "Unknown",
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn write_response(resp: &Response, send_body: bool) -> String {
        let mut buf = Vec::new();
        resp.write_to(&mut buf, send_body).unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn basic_200_response() {
        let resp = Response::new(200)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body_str("hello");
        let out = write_response(&resp, true);
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(out.contains("Content-Length: 5\r\n"));
        assert!(out.ends_with("\r\nhello"));
    }

    #[test]
    fn head_omits_body() {
        let resp = Response::new(200).body_str("secret");
        let out = write_response(&resp, false);
        assert!(out.contains("Content-Length: 6\r\n")); // length still accurate
        assert!(!out.contains("secret"));              // body not sent
    }

    #[test]
    fn status_lines() {
        for (code, phrase) in [(301, "Moved Permanently"), (404, "Not Found"), (500, "Internal Server Error")] {
            let resp = Response::new(code);
            let out = write_response(&resp, true);
            assert!(out.starts_with(&format!("HTTP/1.1 {code} {phrase}\r\n")));
        }
    }

    #[test]
    fn chaining() {
        let resp = Response::new(404)
            .header("X-Foo", "bar")
            .header("X-Baz", "qux")
            .body_str("not found");
        let out = write_response(&resp, true);
        assert!(out.contains("X-Foo: bar\r\n"));
        assert!(out.contains("X-Baz: qux\r\n"));
    }
}
