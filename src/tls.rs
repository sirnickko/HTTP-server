//! TLS support for the HTTP server.
//!
//! # Two certificate sources
//!
//! 1. **Self-signed (development / Route 1)**
//!    When no `--cert` / `--key` flags are provided the server calls
//!    [`build_self_signed`], which uses `rcgen` to generate a fresh
//!    RSA-2048 self-signed certificate entirely in-process.  No files are
//!    written to disk; the cert only lives in memory for that run.
//!
//! 2. **PEM files (production / Route 2)**
//!    Pass `--cert path/to/fullchain.pem --key path/to/privkey.pem` to load
//!    a real certificate chain (e.g. from Let's Encrypt).
//!    Generate a self-signed PEM pair with:
//!    ```text
//!    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
//!      -days 365 -nodes -subj "/CN=localhost"
//!    ```
//!
//! # Inspecting the handshake
//!
//! ```text
//! openssl s_client -connect 127.0.0.1:4433 -CAfile cert.pem
//! ```
//! or just watch with Wireshark (filter: `tcp.port == 4433`).

use std::{
    fs::File,
    io::{self, BufReader},
    net::TcpStream,
    sync::Arc,
};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// A TLS-wrapped `TcpStream` that implements `Read + Write`.
pub type TlsStream = StreamOwned<ServerConnection, TcpStream>;

// ── Config builders ───────────────────────────────────────────────────────────

/// Builds a [`ServerConfig`] that uses a **self-signed** certificate generated
/// in-memory by `rcgen`.  Perfect for development / local testing.
///
/// The generated cert is valid for `localhost` and `127.0.0.1`.
pub fn build_self_signed() -> Arc<ServerConfig> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let subject_alt_names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];

    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(subject_alt_names)
            .expect("rcgen: failed to generate self-signed certificate");

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der  = PrivateKeyDer::try_from(key_pair.serialize_der())
        .expect("rcgen: invalid private key DER");

    build_config(vec![cert_der], key_der)
}

/// Builds a [`ServerConfig`] by loading a PEM certificate chain and a PEM
/// private key from the given file paths.
///
/// Use this for Let's Encrypt certificates or any externally generated cert.
pub fn build_from_files(cert_path: &str, key_path: &str) -> Arc<ServerConfig> {
    // ── Certificate chain ─────────────────────────────────────────────────────
    let cert_file = File::open(cert_path)
        .unwrap_or_else(|e| panic!("Cannot open cert file {cert_path:?}: {e}"));
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.expect("PEM cert parse error"))
        .collect();

    if certs.is_empty() {
        panic!("No certificates found in {cert_path:?}");
    }

    // ── Private key ───────────────────────────────────────────────────────────
    let key_file = File::open(key_path)
        .unwrap_or_else(|e| panic!("Cannot open key file {key_path:?}: {e}"));
    let mut key_reader = BufReader::new(key_file);

    // Try PKCS#8 first (Let's Encrypt default), then fall back to RSA (PKCS#1).
    let key = rustls_pemfile::private_key(&mut key_reader)
        .expect("PEM key parse error")
        .unwrap_or_else(|| panic!("No private key found in {key_path:?}"));

    build_config(certs, key)
}

// ── Internal helper ───────────────────────────────────────────────────────────

fn build_config(
    certs: Vec<CertificateDer<'static>>,
    key:   PrivateKeyDer<'static>,
) -> Arc<ServerConfig> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("TLS config: invalid cert/key pair");
    Arc::new(config)
}

// ── TLS accept ────────────────────────────────────────────────────────────────

/// Wraps a plain `TcpStream` in a TLS server-side connection.
///
/// Returns an opaque [`TlsStream`] that implements `Read + Write`, which can
/// be passed directly to [`crate::server::handle_connection`].
///
/// Returns `Err` if the TLS handshake fails (e.g. client sent garbage, or the
/// client rejected our self-signed certificate without the `-k` flag).
pub fn accept(config: Arc<ServerConfig>, stream: TcpStream) -> io::Result<TlsStream> {
    let conn = ServerConnection::new(config)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(StreamOwned::new(conn, stream))
}
