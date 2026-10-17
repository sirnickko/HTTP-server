mod handlers;
mod logger;
mod mime;
mod request;
mod response;
mod server;
mod tls;

use std::{env, net::TcpListener, sync::Arc};

fn main() {
    // ── CLI flags ─────────────────────────────────────────────────────────────
    let args = Args::parse();

    // ── TLS config ────────────────────────────────────────────────────────────
    //
    // Route 1 (self-signed, development):
    //   cargo run                           ← generates cert in-memory
    //
    // Route 2 (PEM files, production / Let's Encrypt):
    //   cargo run -- --cert fullchain.pem --key privkey.pem
    //
    // Generate a self-signed PEM pair with OpenSSL for testing Route 2:
    //   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    //     -days 365 -nodes -subj "/CN=localhost"
    //
    // Inspect the handshake afterwards:
    //   openssl s_client -connect 127.0.0.1:4433 -CAfile cert.pem
    //   (or skip verification: openssl s_client -connect 127.0.0.1:4433)
    let tls_config = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => {
            println!("  TLS: loading certificate from {cert:?}");
            tls::build_from_files(cert, key)
        }
        (None, None) => {
            println!("  TLS: generating self-signed certificate (development mode)");
            tls::build_self_signed()
        }
        _ => {
            eprintln!("Error: --cert and --key must be provided together.");
            std::process::exit(1);
        }
    };

    let tls_config = Arc::new((*tls_config).clone());

    // ── Bind listeners ────────────────────────────────────────────────────────
    let https_addr = format!("0.0.0.0:{}", args.https_port);
    let http_addr  = format!("0.0.0.0:{}", args.http_port);

    let https_listener = TcpListener::bind(&https_addr).unwrap_or_else(|e| {
        eprintln!("Error: cannot bind HTTPS to {https_addr}: {e}");
        std::process::exit(1);
    });

    let http_listener = TcpListener::bind(&http_addr).unwrap_or_else(|e| {
        eprintln!("Error: cannot bind HTTP to {http_addr}: {e}");
        std::process::exit(1);
    });

    // ── Banner ────────────────────────────────────────────────────────────────
    let cert_source = if args.cert.is_some() { "PEM files" } else { "self-signed (rcgen)" };
    println!("╔══════════════════════════════════════════════════╗");
    println!("║         Rust HTTPS Server  v0.2                 ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  HTTPS on  https://{https_addr:<28}║");
    println!("║  HTTP  on  http://{http_addr:<29}║");
    println!("║  HTTP  → auto-redirects to HTTPS                ║");
    println!("║  TLS cert  {cert_source:<37}║");
    println!("║  HSTS      max-age=31536000; includeSubDomains  ║");
    println!("║  Serving from  ./www/                           ║");
    println!("║  Press Ctrl+C to stop                           ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    // ── Spawn HTTP redirect listener on its own thread ────────────────────────
    let https_port_for_redirect = args.https_port;
    std::thread::spawn(move || {
        for stream in http_listener.incoming() {
            match stream {
                Ok(s) => {
                    std::thread::spawn(move || {
                        server::handle_http_redirect(s, https_port_for_redirect);
                    });
                }
                Err(e) => eprintln!("HTTP accept error: {e}"),
            }
        }
    });

    // ── HTTPS main loop ───────────────────────────────────────────────────────
    for stream in https_listener.incoming() {
        match stream {
            Ok(tcp) => {
                // Set the read timeout on the raw TCP socket BEFORE wrapping
                // in TLS — rustls propagates reads to the inner stream, so
                // this timeout applies to the TLS record reads as well.
                tcp.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();

                let cfg = Arc::clone(&tls_config);
                std::thread::spawn(move || {
                    match tls::accept(cfg, tcp) {
                        Ok(tls_stream) => server::handle_connection(tls_stream),
                        Err(e)        => eprintln!("TLS handshake error: {e}"),
                    }
                });
            }
            Err(e) => eprintln!("HTTPS accept error: {e}"),
        }
    }
}

// ── CLI argument parsing ──────────────────────────────────────────────────────

struct Args {
    /// HTTPS port  (default 4433; use 443 in production)
    https_port: u16,
    /// HTTP port for the redirect listener  (default 8080; use 80 in production)
    http_port:  u16,
    /// Path to a PEM certificate chain (optional; self-signed used if absent)
    cert: Option<String>,
    /// Path to a PEM private key (optional; self-signed used if absent)
    key:  Option<String>,
}

impl Args {
    fn parse() -> Self {
        let raw: Vec<String> = env::args().collect();
        let mut args = Args {
            https_port: 4433,
            http_port:  8080,
            cert: None,
            key:  None,
        };

        let mut i = 1;
        while i < raw.len() {
            match raw[i].as_str() {
                "--https-port" | "-s" => {
                    if let Some(v) = raw.get(i + 1) {
                        args.https_port = v.parse().unwrap_or(4433);
                        i += 1;
                    }
                }
                "--port" | "-p" | "--http-port" => {
                    if let Some(v) = raw.get(i + 1) {
                        args.http_port = v.parse().unwrap_or(8080);
                        i += 1;
                    }
                }
                "--cert" => {
                    args.cert = raw.get(i + 1).cloned();
                    i += 1;
                }
                "--key" => {
                    args.key = raw.get(i + 1).cloned();
                    i += 1;
                }
                arg if arg.starts_with("--https-port=") => {
                    args.https_port = arg["--https-port=".len()..].parse().unwrap_or(4433);
                }
                arg if arg.starts_with("--port=") => {
                    args.http_port = arg["--port=".len()..].parse().unwrap_or(8080);
                }
                _ => {}
            }
            i += 1;
        }

        args
    }
}
