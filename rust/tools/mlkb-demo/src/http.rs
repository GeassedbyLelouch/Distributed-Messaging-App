//! A blocking HTTP/1.1 server on `std::net::TcpListener`, thread per
//! connection.
//!
//! # This is not a production server, and is not trying to be
//!
//! There is no async runtime, no keep-alive, no chunked transfer encoding, no
//! TLS, no compression and no concurrency limit beyond the operating system's.
//! `mlkb-transport` is the crate that owns real I/O for this project; this file
//! exists because the workspace has no HTTP dependency and may not gain one,
//! and because a demo needs a browser to talk to.
//!
//! What it *does* do, because a parser is a parser even in a demo:
//!
//! - binds `127.0.0.1` only, so nothing on the network can reach it;
//! - bounds the request line, the header block and the body before allocating
//!   for any of them, and closes the connection on anything larger;
//! - sets read and write timeouts, so a stalled peer cannot hold a thread;
//! - answers every request with `Connection: close`, so there is no
//!   request-pipelining state to get wrong.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Largest request line this server will read, in bytes.
const MAX_REQUEST_LINE: usize = 8 * 1024;

/// Largest header block, in bytes.
const MAX_HEADERS: usize = 16 * 1024;

/// Largest body, in bytes. The demo's largest request is a chat line.
const MAX_BODY: usize = 64 * 1024;

/// How long a connection may stall before its thread is released.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// One parsed request.
#[derive(Debug)]
pub(crate) struct Request {
    /// `GET` or `POST`.
    pub(crate) method: String,
    /// Path with any query string removed.
    pub(crate) path: String,
    /// Decoded `application/x-www-form-urlencoded` body fields.
    pub(crate) form: BTreeMap<String, String>,
}

/// One response to write.
#[derive(Debug)]
pub(crate) struct Response {
    /// HTTP status code.
    pub(crate) status: u16,
    /// `Content-Type` header value.
    pub(crate) content_type: &'static str,
    /// Body bytes.
    pub(crate) body: Vec<u8>,
}

impl Response {
    /// A `200 application/json` response.
    #[must_use]
    pub(crate) fn json(body: String) -> Self {
        Self {
            status: 200,
            content_type: "application/json; charset=utf-8",
            body: body.into_bytes(),
        }
    }

    /// A `200 text/html` response.
    #[must_use]
    pub(crate) fn html(body: &str) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }

    /// A bare status response with a plain-text body.
    #[must_use]
    pub(crate) fn status(status: u16, message: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: message.as_bytes().to_vec(),
        }
    }
}

/// Serves forever, calling `handler` once per request.
///
/// `handler` must be `Send + Sync + 'static` because each connection is served
/// on its own thread; shared mutable state belongs behind a `Mutex` inside it.
pub(crate) fn serve<H>(listener: &TcpListener, handler: H) -> !
where
    H: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let handler = std::sync::Arc::new(handler);
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let handler = std::sync::Arc::clone(&handler);
                // A failed spawn drops the connection rather than taking the
                // server down; the browser will retry.
                let _ = std::thread::Builder::new()
                    .name(String::from("mlkb-demo-conn"))
                    .spawn(move || {
                        let _ = handle(&stream, handler.as_ref());
                    });
            }
            Err(e) => eprintln!("mlkb-demo: accept failed: {e}"),
        }
    }
}

fn handle<H>(stream: &TcpStream, handler: &H) -> std::io::Result<()>
where
    H: Fn(&Request) -> Response,
{
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let response = match read_request(stream) {
        Ok(Some(req)) => handler(&req),
        Ok(None) => Response::status(400, "malformed request"),
        Err(e) => return Err(e),
    };
    write_response(stream, &response)
}

/// Reads one request. `Ok(None)` means the input was refused, not that the
/// socket failed.
fn read_request(stream: &TcpStream) -> std::io::Result<Option<Request>> {
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    if reader
        .by_ref()
        .take(MAX_REQUEST_LINE as u64)
        .read_line(&mut line)?
        == 0
    {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Ok(None);
    };
    let method = method.to_owned();
    // The query string is not used by any endpoint; every parameter arrives in
    // a form body. Dropping it here means no handler can accidentally read one.
    let path = target.split_once('?').map_or(target, |(p, _)| p).to_owned();

    // Headers. Only `Content-Length` is consulted.
    let mut content_length = 0usize;
    let mut header_bytes = 0usize;
    loop {
        let mut header = String::new();
        let n = reader
            .by_ref()
            .take(MAX_REQUEST_LINE as u64)
            .read_line(&mut header)?;
        if n == 0 {
            return Ok(None);
        }
        header_bytes = header_bytes.saturating_add(n);
        if header_bytes > MAX_HEADERS {
            return Ok(None);
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            match value.trim().parse::<usize>() {
                Ok(v) if v <= MAX_BODY => content_length = v,
                // Both an unparsable length and an oversized one are refused
                // before any buffer is allocated for them.
                _ => return Ok(None),
            }
        }
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let form = crate::json::parse_form(&String::from_utf8_lossy(&body));

    Ok(Some(Request { method, path, form }))
}

fn write_response(mut stream: &TcpStream, res: &Response) -> std::io::Result<()> {
    let reason = match res.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        res.status,
        reason,
        res.content_type,
        res.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&res.body)?;
    stream.flush()
}
