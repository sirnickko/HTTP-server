mod handlers;
mod logger;
mod mime;
mod pool;
mod redirect;
mod request;
mod response;
mod server;
mod tls;

use std::{
    env,
    net::{TcpListener, TcpStream},
    process,
    sync::Arc,
    thread,
};

use pool::ThreadPool;

/// Worker threads handling connections. A keep-alive connection occupies its
/// worker while idle (up to the 5 s timeout), so this is also roughly the
/// number of clients that can be connected at once.
const DEFAULT_THREADS: usize = 64;
/// Connections allowed to wait for a free worker, per worker. Beyond that,
/// new connections are refused instead of queueing without bound.
const QUEUE_PER_WORKER: usize = 4;

const USAGE: &str = "\
Usage: http-server [OPTIONS]

  -s, --https-port <N>    HTTPS port                       (default 4433)
  -p, --port <N>          HTTP port, redirects to HTTPS    (default 8080)
      --cert <FILE>       PEM certificate or chain         (needs --key)
      --key <FILE>        PEM private key                  (needs --cert)
      --threads <N>       Worker threads for connections   (default 64)
  -h, --help              Show this help

Without --cert and --key a self-signed certificate is generated in memory.";

fn main() {
    // ── CLI flags ─────────────────────────────────────────────────────────────
    let args = Args::parse().unwrap_or_else(|e| {
        eprintln!("Error: {e}\n\n{USAGE}");
        process::exit(2);
    });

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
            process::exit(1);
        }
    };

    // ── Bind listeners ────────────────────────────────────────────────────────
    let https_addr = format!("0.0.0.0:{}", args.https_port);
    let http_addr  = format!("0.0.0.0:{}", args.http_port);

    let https_listener = TcpListener::bind(&https_addr).unwrap_or_else(|e| {
        eprintln!("Error: cannot bind HTTPS to {https_addr}: {e}");
        process::exit(1);
    });

    let http_listener = TcpListener::bind(&http_addr).unwrap_or_else(|e| {
        eprintln!("Error: cannot bind HTTP to {http_addr}: {e}");
        process::exit(1);
    });

    // One pool shared by both listeners: the thread count is a global cap.
    let pool = ThreadPool::new(args.threads, args.threads * QUEUE_PER_WORKER);

    // ── Banner ────────────────────────────────────────────────────────────────
    let cert_source = if args.cert.is_some() { "PEM files" } else { "self-signed (rcgen)" };
    let workers = format!("{} threads", args.threads);
    println!("╔══════════════════════════════════════════════════╗");
    println!("║         Rust HTTPS Server  v0.2                 ║");
    println!("╠══════════════════════════════════════════════════╣");
    println!("║  HTTPS on  https://{https_addr:<28}║");
    println!("║  HTTP  on  http://{http_addr:<29}║");
    println!("║  HTTP  → auto-redirects to HTTPS                ║");
    println!("║  TLS cert  {cert_source:<37}║");
    println!("║  HSTS      max-age=31536000; includeSubDomains  ║");
    println!("║  Workers   {workers:<37}║");
    println!("║  Serving from  ./www/                           ║");
    println!("║  Press Ctrl+C to stop                           ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();

    // ── HTTP redirect listener on its own thread ──────────────────────────────
    let https_port_for_redirect = args.https_port;
    let redirect_pool = pool.clone();
    thread::spawn(move || {
        accept_loop(http_listener, &redirect_pool, move |s| {
            server::handle_http_redirect(s, https_port_for_redirect);
        });
    });

    // ── HTTPS main loop ───────────────────────────────────────────────────────
    accept_loop(https_listener, &pool, move |tcp| {
        server::handle_https(tcp, Arc::clone(&tls_config));
    });
}

/// Accepts connections forever and hands each one to the worker pool.
///
/// If every worker is busy and the queue is full, the connection is closed at
/// once. Refusing early keeps the server responsive for the clients it already
/// has, rather than slowing down for everyone.
fn accept_loop(
    listener: TcpListener,
    pool: &ThreadPool,
    handler: impl Fn(TcpStream) + Send + Sync + 'static,
) {
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let handler = Arc::clone(&handler);
                if !pool.try_execute(move || handler(s)) {
                    eprintln!("Overloaded: every worker is busy and the queue is full, connection refused");
                }
            }
            Err(e) => eprintln!("Accept error: {e}"),
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
    /// Worker threads serving connections
    threads: usize,
}

impl Args {
    /// Parses the command line. Every option accepts `--name value` or
    /// `--name=value`. Unknown options and bad values are errors rather than
    /// being silently replaced by defaults.
    fn parse() -> Result<Self, String> {
        let mut args = Args {
            https_port: 4433,
            http_port:  8080,
            cert: None,
            key:  None,
            threads: DEFAULT_THREADS,
        };

        let mut raw = env::args().skip(1);
        while let Some(arg) = raw.next() {
            let (flag, mut inline) = match arg.split_once('=') {
                Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
                _                                   => (arg, None),
            };

            // Value for the current flag: the `=value` part, or else the next argument.
            let mut value = || -> Result<String, String> {
                inline
                    .take()
                    .or_else(|| raw.next())
                    .ok_or_else(|| format!("{flag} needs a value"))
            };

            match flag.as_str() {
                "--https-port" | "-s"             => args.https_port = number(&flag, &value()?)?,
                "--port" | "-p" | "--http-port"   => args.http_port = number(&flag, &value()?)?,
                "--threads"                       => args.threads = number(&flag, &value()?)?,
                "--cert"                          => args.cert = Some(value()?),
                "--key"                           => args.key = Some(value()?),
                "--help" | "-h" => {
                    println!("{USAGE}");
                    process::exit(0);
                }
                other => return Err(format!("unknown option: {other}")),
            }
        }

        if args.threads == 0 {
            return Err("--threads must be at least 1".into());
        }
        if args.https_port == args.http_port {
            return Err("the HTTP and HTTPS ports must be different".into());
        }
        Ok(args)
    }
}

fn number<T: std::str::FromStr>(flag: &str, raw: &str) -> Result<T, String> {
    raw.parse().map_err(|_| format!("{flag} expects a number, got '{raw}'"))
}
