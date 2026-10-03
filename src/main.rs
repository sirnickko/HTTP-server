mod handlers;
mod logger;
mod mime;
mod request;
mod response;
mod server;

use std::{env, net::TcpListener};

fn main() {
    let port = parse_args().unwrap_or(7878);
    let addr = format!("0.0.0.0:{port}");

    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("Error: cannot bind to {addr}: {e}");
        std::process::exit(1);
    });

    println!("╔══════════════════════════════════════════╗");
    println!("║       Rust HTTP Server (pure std)        ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║  Listening on  http://{addr:<19}║");
    println!("║  Serving from  ./www/                    ║");
    println!("║  Press Ctrl+C to stop                    ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                std::thread::spawn(|| server::handle_connection(s));
            }
            Err(e) => {
                eprintln!("Accept error: {e}");
            }
        }
    }
}

/// Parses `--port <N>` or `-p <N>` from the command-line arguments.
/// Returns `None` if no port flag is present.
fn parse_args() -> Option<u16> {
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--port" || args[i] == "-p" {
            if let Some(val) = args.get(i + 1) {
                return val.parse().ok();
            }
        }
        // Also support `--port=8080` form.
        if let Some(rest) = args[i].strip_prefix("--port=") {
            return rest.parse().ok();
        }
        i += 1;
    }
    None
}
