# HTTP-server

An HTTP/1.1 static file server in Rust. The HTTP side is hand-written on
`std::net`; TLS comes from [rustls](https://github.com/rustls/rustls).
See [HTTPS.md](HTTPS.md) for the certificate and handshake walkthrough.

```bash
cargo run                  # HTTPS on :4433, HTTP on :8080 redirecting to it
cargo run -- --help
cargo test
```

Files are served from `./www/`. Without `--cert`/`--key` a self-signed
certificate is generated in memory, so use `curl -k https://localhost:4433/`.

| Option | Default | |
|---|---|---|
| `-s, --https-port <N>` | 4433 | HTTPS port |
| `-p, --port <N>` | 8080 | HTTP port (redirects to HTTPS) |
| `--cert <FILE>` / `--key <FILE>` | self-signed | PEM certificate chain and key |
| `--threads <N>` | 64 | worker threads |

## Limits

Everything read from a client is bounded, and the check happens before any
buffer is allocated.

| Limit | Value | Response |
|---|---|---|
| request line | 8 KB | `414` |
| header line / count / total | 8 KB / 100 / 32 KB | `431` |
| body (`Content-Length`) | 1 MB | `413` |
| syntax errors, bad or conflicting `Content-Length` | | `400` |
| `Transfer-Encoding` (chunked) | unsupported | `501` |
| requests per connection | 100 | connection closed |

After rejecting a request the server drains the rest of it for at most 1 s or
1 MB before closing, so clients see the error and not a TCP reset.

Connections run on a fixed pool of `--threads` workers with a queue of four
waiting connections per worker. When both are full, new connections are closed
immediately instead of queueing without limit. Keep-alive connections hold a
worker while idle (5 s timeout).

The redirect port answers `301` for GET/HEAD and `308` for other methods (so a
POST body survives), and validates the `Host` header before echoing it.

## Tests

`cargo test` runs unit tests (parser limits, redirect logic, pool, MIME types)
and `tests/integration.rs`, which starts the real binary and talks to it over
real sockets with a rustls client: files, ETag/304, pipelining, keep-alive
cap, limits, pool exhaustion, TLS 1.2/1.3, certificate rejection, HSTS and
redirects. No setup needed; certificates are generated on the fly.

## Known limitations

* A client that trickles bytes slowly can hold a worker, because the 5 s
  timeout applies to each read rather than to a whole request.
* HTTP/1.1 only: no chunked request bodies, no range requests.
