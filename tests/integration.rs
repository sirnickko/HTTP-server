//! End-to-end tests: each test starts the real server binary on free ports and
//! talks to it over actual sockets, with plain TCP and with a rustls client.

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, ProtocolVersion,
    RootCertStore, SignatureScheme, StreamOwned,
};

// ─── Test server ─────────────────────────────────────────────────────────────

/// Picking free ports and starting servers one at a time keeps parallel tests
/// from racing for the same port.
static START_LOCK: Mutex<()> = Mutex::new(());
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A running server: HTTPS on `https`, the redirect listener on `http`.
struct Server {
    child: Child,
    http: u16,
    https: u16,
    dir: PathBuf,
}

impl Server {
    /// Default mode: the server generates its own self-signed certificate.
    fn start(extra: &[&str]) -> Server {
        Self::spawn(false, extra)
    }

    /// `--cert` / `--key` mode with a freshly generated PEM pair.
    fn with_pem_files(extra: &[&str]) -> Server {
        Self::spawn(true, extra)
    }

    fn spawn(pem_files: bool, extra: &[&str]) -> Server {
        let _guard = START_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // Hold both listeners until both ports are known so they differ.
        let a = TcpListener::bind("127.0.0.1:0").unwrap();
        let b = TcpListener::bind("127.0.0.1:0").unwrap();
        let (http, https) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());
        drop((a, b));

        let dir = std::env::temp_dir().join(format!(
            "http-server-it-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_http-server"));
        // The server serves `./www` relative to its working directory.
        cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["--port", &http.to_string(), "--https-port", &https.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if pem_files {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
            fs::write(&cert_path, ck.cert.pem()).unwrap();
            fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();
            cmd.arg("--cert").arg(&cert_path).arg("--key").arg(&key_path);
        }
        cmd.args(extra);

        let child = cmd.spawn().expect("failed to start the server binary");
        let server = Server { child, http, https, dir };

        // Wait until both listeners accept connections.
        let deadline = Instant::now() + Duration::from_secs(10);
        for port in [http, https] {
            while TcpStream::connect(("127.0.0.1", port)).is_err() {
                assert!(Instant::now() < deadline, "server did not start listening on {port}");
                thread::sleep(Duration::from_millis(25));
            }
        }
        server
    }

    /// Sends `raw` over TLS (certificate not verified) and returns the answer.
    fn tls(&self, raw: &[u8]) -> String {
        tls_exchange(self.https, lenient_client(), raw).0
    }

    /// Sends `raw` to the plain-HTTP redirect port.
    fn plain(&self, raw: &[u8]) -> String {
        exchange(self.http, raw)
    }

    fn https_get(&self, path: &str) -> String {
        self.tls(&get(path))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        fs::remove_dir_all(&self.dir).ok();
    }
}

/// Runs the binary with bad arguments and returns (exit code, stderr).
fn run_with_args(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_http-server"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
}

// ─── Plain-TCP helpers ───────────────────────────────────────────────────────

/// Reads until EOF or error and returns whatever arrived. A reset after the
/// response has been delivered must not hide the response itself.
fn read_all(r: &mut impl Read) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Sends `raw` over plain TCP and returns everything the server answers
/// before it closes the connection.
fn exchange(port: u16, raw: &[u8]) -> String {
    let mut s = connect(port);
    s.write_all(raw).unwrap();
    read_all(&mut s)
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").into_bytes()
}

fn status_line(resp: &str) -> &str {
    resp.lines().next().unwrap_or("")
}

/// Case-insensitive header lookup in the head of a response.
fn header(resp: &str, name: &str) -> Option<String> {
    let head = resp.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

fn body(resp: &str) -> &str {
    resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

// ─── TLS helpers ─────────────────────────────────────────────────────────────

/// Accepts any certificate, like `curl -k`. Signatures are still checked, so
/// the handshake itself is fully exercised.
#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn lenient_client() -> ClientConfig {
    let provider = Arc::new(ring::default_provider());
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth()
}

/// A client that only trusts the (empty) root store, so a self-signed server
/// certificate must be refused.
fn strict_client() -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth()
}

/// One HTTPS exchange: the response text plus the negotiated TLS version.
fn tls_exchange(port: u16, config: ClientConfig, raw: &[u8]) -> (String, ProtocolVersion) {
    let conn = ClientConnection::new(Arc::new(config), "localhost".try_into().unwrap()).unwrap();
    let mut stream = StreamOwned::new(conn, connect(port));
    stream.write_all(raw).unwrap();
    let text = read_all(&mut stream);
    let version = stream.conn.protocol_version().expect("handshake did not complete");
    (text, version)
}

// ─── Serving files (over HTTPS) ──────────────────────────────────────────────

#[test]
fn serves_index_and_static_files_with_correct_types() {
    let s = Server::start(&[]);

    let r = s.https_get("/");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(header(&r, "content-type").unwrap(), "text/html; charset=utf-8");
    assert!(body(&r).to_lowercase().contains("<html"));

    let r = s.https_get("/style.css");
    assert_eq!(header(&r, "content-type").unwrap(), "text/css; charset=utf-8");
}

#[test]
fn content_length_matches_the_body() {
    let s = Server::start(&[]);
    let r = s.https_get("/index.html");
    let declared: usize = header(&r, "content-length").unwrap().parse().unwrap();
    assert_eq!(body(&r).len(), declared);
}

#[test]
fn head_sends_headers_but_no_body() {
    let s = Server::start(&[]);
    let r = s.tls(b"HEAD /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert!(header(&r, "content-length").unwrap().parse::<usize>().unwrap() > 0);
    assert_eq!(body(&r), "");
}

#[test]
fn missing_file_is_404_and_unknown_method_is_405() {
    let s = Server::start(&[]);
    assert!(status_line(&s.https_get("/no-such-file")).contains("404"));

    let r = s.tls(b"DELETE / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    assert!(status_line(&r).contains("405"));
    assert!(header(&r, "allow").unwrap().contains("GET"));
}

#[test]
fn post_body_reaches_the_handler() {
    let s = Server::start(&[]);
    let r = s.tls(
        b"POST /form HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello=world",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert!(body(&r).contains("hello=world"));
}

#[test]
fn etag_round_trip_gives_304() {
    let s = Server::start(&[]);
    let etag = header(&s.https_get("/index.html"), "etag").unwrap();

    let req = format!(
        "GET /index.html HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\nConnection: close\r\n\r\n"
    );
    let r = s.tls(req.as_bytes());
    assert_eq!(status_line(&r), "HTTP/1.1 304 Not Modified");
    assert_eq!(body(&r), "");
}

#[test]
fn path_traversal_cannot_escape_the_web_root() {
    let s = Server::start(&[]);
    for path in ["/../../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2fetc/passwd"] {
        let r = s.https_get(path);
        assert!(status_line(&r).contains("404"), "{path} -> {}", status_line(&r));
        assert!(!r.contains("root:"), "{path} leaked a system file");
    }
}

// ─── Keep-alive and pipelining ───────────────────────────────────────────────

#[test]
fn two_requests_sent_back_to_back_both_get_answered() {
    // Regression test: the server used to create a new buffered reader for
    // every request, silently discarding bytes it had already read ahead. The
    // second of two back-to-back requests was lost.
    let s = Server::start(&[]);
    let mut two = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    two.extend(get("/style.css")); // second one closes the connection
    let r = s.tls(&two);

    assert_eq!(r.matches("HTTP/1.1 200 OK").count(), 2, "{r}");
    assert!(r.contains("Content-Type: text/html"));
    assert!(r.contains("Content-Type: text/css"));
    assert_eq!(r.matches("Strict-Transport-Security").count(), 2);
}

#[test]
fn many_pipelined_requests_are_all_answered_in_order() {
    let s = Server::start(&[]);
    let mut raw = Vec::new();
    for i in 0..30 {
        let path = if i % 2 == 0 { "/index.html" } else { "/style.css" };
        raw.extend(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes());
    }
    let r = s.tls(&raw);

    assert_eq!(r.matches("HTTP/1.1 200 OK").count(), 30);
    // The content types alternate, proving the order is preserved.
    let types: Vec<&str> = r
        .lines()
        .filter_map(|l| l.strip_prefix("Content-Type: "))
        .map(|t| if t.starts_with("text/html") { "html" } else { "css" })
        .collect();
    let expected: Vec<&str> = (0..30).map(|i| if i % 2 == 0 { "html" } else { "css" }).collect();
    assert_eq!(types, expected);
}

#[test]
fn connection_is_closed_after_max_requests() {
    let s = Server::start(&[]);
    let one = "GET /style.css HTTP/1.1\r\nHost: x\r\n\r\n";
    // 150 pipelined requests: the server must stop after 100.
    let r = s.tls(one.repeat(150).as_bytes());

    assert_eq!(r.matches("HTTP/1.1 200 OK").count(), 100);
    assert!(r.contains("Keep-Alive: timeout=5, max=99"), "first response advertises 99 left");
    assert!(r.contains("Keep-Alive: timeout=5, max=1"));
    let last = r.rsplit("HTTP/1.1 200 OK").next().unwrap();
    assert!(last.contains("Connection: close"), "the 100th response must close");
}

// ─── Bad input ───────────────────────────────────────────────────────────────

#[test]
fn malformed_requests_get_400_on_both_ports() {
    let s = Server::start(&[]);
    for raw in [
        &b"GARBAGE\r\n\r\n"[..],
        b"GET / HTTP/9.9\r\n\r\n",
        b"GET / HTTP/1.1\r\nbroken header line\r\n\r\n",
        b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
    ] {
        for r in [s.tls(raw), s.plain(raw)] {
            assert!(status_line(&r).contains("400"), "{:?} -> {r:?}", String::from_utf8_lossy(raw));
            assert_eq!(header(&r, "connection").unwrap(), "close");
        }
    }
}

#[test]
fn oversized_requests_are_rejected_with_the_right_status() {
    let s = Server::start(&[]);

    let long_uri = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(20_000));
    let big_header = format!("GET / HTTP/1.1\r\nX-Big: {}\r\n\r\n", "a".repeat(20_000));
    let mut many = String::from("GET / HTTP/1.1\r\n");
    for i in 0..200 {
        many.push_str(&format!("X-{i}: v\r\n"));
    }
    many.push_str("\r\n");
    // Declares 50 GB but sends nothing. It used to abort the whole process.
    let huge: &[u8] = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 50000000000\r\n\r\n";
    let chunked: &[u8] = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";

    for (raw, code) in [
        (long_uri.as_bytes(), "414"),
        (big_header.as_bytes(), "431"),
        (many.as_bytes(), "431"),
        (huge, "413"),
        (chunked, "501"),
    ] {
        assert!(status_line(&s.tls(raw)).contains(code), "TLS port, expected {code}");
        assert!(status_line(&s.plain(raw)).contains(code), "HTTP port, expected {code}");
    }

    // And the server is still there afterwards.
    assert_eq!(status_line(&s.https_get("/")), "HTTP/1.1 200 OK");
}

#[test]
fn rejected_requests_arrive_as_a_response_not_a_connection_reset() {
    // The client is still sending when the server rejects the request. Closing
    // straight away would reset the connection and swallow the 431.
    let s = Server::start(&[]);
    let big = format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Big: {}\r\n\r\n", "a".repeat(200_000));

    for attempt in 0..5 {
        let r = s.tls(big.as_bytes());
        assert!(status_line(&r).contains("431"), "TLS attempt {attempt}: got {r:?}");
    }
    for attempt in 0..5 {
        let r = s.plain(big.as_bytes());
        assert!(status_line(&r).contains("431"), "plain attempt {attempt}: got {r:?}");
    }
}

#[test]
fn server_survives_abusive_clients() {
    let s = Server::start(&[]);

    // Hang up mid-request, send binary junk, open and close silently.
    for port in [s.http, s.https] {
        for junk in [&b"GET / HT"[..], &[0xff, 0xfe, 0x00, 0x01][..], b""] {
            let mut c = connect(port);
            c.write_all(junk).ok();
            drop(c);
        }
        let mut endless = connect(port);
        endless.write_all(&vec![b'a'; 100_000]).ok(); // no newline, ever
        drop(endless);
    }

    assert_eq!(status_line(&s.https_get("/")), "HTTP/1.1 200 OK", "server must still answer");
    assert!(status_line(&s.plain(&get("/"))).contains("301"));
}

#[test]
fn full_pool_refuses_new_connections_then_recovers() {
    // One worker, queue of four → at most five connections can be held.
    let s = Server::start(&["--threads", "1"]);

    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(connect(s.http)); // idle: occupies the worker or a queue slot
        thread::sleep(Duration::from_millis(150));
    }

    // The sixth is closed by the server straight away instead of queueing.
    let mut sixth = connect(s.http);
    sixth.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 16];
    match sixth.read(&mut buf) {
        Ok(0) => {}
        Err(e) if e.kind() != std::io::ErrorKind::WouldBlock && e.kind() != std::io::ErrorKind::TimedOut => {}
        other => panic!("expected the overflow connection to be closed, got {other:?}"),
    }

    // Free everything: the server must recover and serve again.
    drop(held);
    drop(sixth);
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let mut c = connect(s.http);
        c.write_all(&get("/")).ok();
        if status_line(&read_all(&mut c)).contains("301") {
            break;
        }
        assert!(Instant::now() < deadline, "server did not recover after the pool drained");
        thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn many_concurrent_clients_all_succeed() {
    let s = Server::start(&[]);
    let port = s.https;
    let handles: Vec<_> = (0..40)
        .map(|_| {
            thread::spawn(move || {
                let (r, _) = tls_exchange(port, lenient_client(), &get("/style.css"));
                status_line(&r).to_string()
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), "HTTP/1.1 200 OK");
    }
}

// ─── HTTPS ───────────────────────────────────────────────────────────────────

#[test]
fn https_serves_pages_over_tls_1_3_with_hsts() {
    let s = Server::start(&[]);
    let (r, version) = tls_exchange(s.https, lenient_client(), &get("/"));

    assert_eq!(version, ProtocolVersion::TLSv1_3);
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(
        header(&r, "strict-transport-security").unwrap(),
        "max-age=31536000; includeSubDomains"
    );
    assert!(body(&r).to_lowercase().contains("<html"));
}

#[test]
fn tls_1_2_clients_are_still_supported() {
    let s = Server::start(&[]);
    let provider = Arc::new(ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
        .with_no_client_auth();

    let (r, version) = tls_exchange(s.https, config, &get("/"));
    assert_eq!(version, ProtocolVersion::TLSv1_2);
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
}

#[test]
fn a_client_that_verifies_certificates_rejects_the_self_signed_one() {
    let s = Server::start(&[]);
    let mut conn =
        ClientConnection::new(Arc::new(strict_client()), "localhost".try_into().unwrap()).unwrap();
    let mut tcp = connect(s.https);

    let err = conn.complete_io(&mut tcp).expect_err("handshake must fail");
    assert!(format!("{err:?}").contains("UnknownIssuer"), "unexpected error: {err:?}");
}

#[test]
fn hsts_is_on_every_https_response_including_errors() {
    let s = Server::start(&[]);

    let missing = s.https_get("/definitely-missing");
    assert!(status_line(&missing).contains("404"));
    assert!(header(&missing, "strict-transport-security").is_some());

    let huge = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50000000000\r\n\r\n";
    let rejected = s.tls(huge);
    assert!(status_line(&rejected).contains("413"));
    assert!(header(&rejected, "strict-transport-security").is_some());
}

#[test]
fn hsts_is_never_sent_over_plain_http() {
    let s = Server::start(&[]);
    let r = s.plain(&get("/"));
    assert!(status_line(&r).contains("301"));
    assert!(header(&r, "strict-transport-security").is_none());
}

#[test]
fn https_post_and_large_download_are_intact() {
    let s = Server::start(&[]);
    let r = s.tls(
        b"POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrust=ok",
    );
    assert!(body(&r).contains("rust=ok"));

    // style.css is several KB: make sure multi-record TLS bodies arrive whole.
    let r = s.https_get("/style.css");
    let declared: usize = header(&r, "content-length").unwrap().parse().unwrap();
    assert_eq!(body(&r).len(), declared);
}

#[test]
fn certificate_and_key_files_can_be_supplied() {
    let s = Server::with_pem_files(&[]);
    let (r, version) = tls_exchange(s.https, lenient_client(), &get("/"));
    assert_eq!(status_line(&r), "HTTP/1.1 200 OK");
    assert_eq!(version, ProtocolVersion::TLSv1_3);
}

// ─── HTTP → HTTPS redirect ───────────────────────────────────────────────────

#[test]
fn plain_port_redirects_get_to_https_keeping_path_and_query() {
    let s = Server::start(&[]);
    let req = format!(
        "GET /docs/a%20b?x=1&y=2 HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        s.http
    );
    let r = s.plain(req.as_bytes());

    assert_eq!(status_line(&r), "HTTP/1.1 301 Moved Permanently");
    assert_eq!(
        header(&r, "location").unwrap(),
        format!("https://localhost:{}/docs/a%20b?x=1&y=2", s.https)
    );
}

#[test]
fn plain_port_uses_308_for_post_so_the_body_is_not_lost() {
    let s = Server::start(&[]);
    let r = s.plain(
        b"POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
    );
    assert_eq!(status_line(&r), "HTTP/1.1 308 Permanent Redirect");
    assert!(header(&r, "location").unwrap().starts_with("https://"));
}

#[test]
fn redirect_cannot_be_used_for_header_injection_or_open_redirects() {
    let s = Server::start(&[]);

    // A carriage return inside Host must not become a second header.
    let r = s.plain(b"GET /x HTTP/1.1\r\nHost: evil.com\rSet-Cookie: pwned=1\r\nConnection: close\r\n\r\n");
    assert!(!r.contains("pwned"), "injected value leaked into the response: {r:?}");
    assert!(header(&r, "set-cookie").is_none());

    // `user@host` tricks fall back to a safe host instead of redirecting away.
    let r = s.plain(b"GET / HTTP/1.1\r\nHost: evil.com@good.com\r\nConnection: close\r\n\r\n");
    assert!(header(&r, "location").unwrap().starts_with("https://localhost:"));
}

#[test]
fn the_redirect_port_never_serves_files() {
    let s = Server::start(&[]);
    let r = s.plain(&get("/index.html"));
    assert!(status_line(&r).contains("301"));
    assert!(!body(&r).to_lowercase().contains("<!doctype"), "a page was served over plain HTTP");
}

// ─── Mixing up the two ports ─────────────────────────────────────────────────

#[test]
fn plain_http_sent_to_the_tls_port_is_dropped_and_the_server_lives_on() {
    let s = Server::start(&[]);

    let r = exchange(s.https, &get("/"));
    assert!(!r.contains("HTTP/1.1 200"), "plaintext must never be answered on the TLS port");

    // And TLS on the plain port goes nowhere useful either.
    let mut c = connect(s.http);
    c.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]).ok();
    drop(c);

    assert_eq!(status_line(&s.https_get("/")), "HTTP/1.1 200 OK");
}

// ─── Command line ────────────────────────────────────────────────────────────

#[test]
fn bad_command_lines_fail_with_a_clear_message_instead_of_using_defaults() {
    for (args, expected) in [
        (&["--threads", "0"][..], "at least 1"),
        (&["--port", "abc"][..], "expects a number"),
        (&["--bogus"][..], "unknown option"),
        (&["--port", "9000", "--https-port", "9000"][..], "must be different"),
        (&["--threads"][..], "needs a value"),
    ] {
        let (code, stderr) = run_with_args(args);
        assert_eq!(code, Some(2), "{args:?}");
        assert!(stderr.contains(expected), "{args:?} -> {stderr}");
    }

    // --cert without --key is refused too.
    let (code, stderr) = run_with_args(&["--cert", "only-a-cert.pem"]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("must be provided together"), "{stderr}");
}
