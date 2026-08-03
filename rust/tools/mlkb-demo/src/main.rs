//! `mlkb-demo` — a local verification harness with a browser front end.
//!
//! # What this is
//!
//! A binary that runs **two real ML-KEM-Braid sessions in one process** and
//! exposes them over a loopback HTTP server so a human can watch the protocol
//! work and watch it refuse things. Every key, signature, encapsulation, nonce,
//! frame and error the page shows came out of `mlkb-crypto`, `mlkb-wire` and
//! `mlkb-protocol` a moment earlier. There is no mock, no fixture and no canned
//! output anywhere in this crate.
//!
//! # What this is not
//!
//! Not a shipping component, and not a client. It is in `tools/` rather than
//! `crates/` so that it can never become a dependency of the library, and so
//! that the parent §7 crate DAG and `deny.toml` — which govern `crates/` —
//! stay unaffected by it. It binds `127.0.0.1` only. It has no persistence, no
//! authentication and no transport security, and it does not need any: it
//! serves one local browser and it lasts as long as the process.
//!
//! # Lints, honestly
//!
//! This crate takes the workspace lint table, so parent §11 gate 7's panic-free
//! set applies to it. It re-allows exactly four of them at the root, listed
//! with reasons below. `clippy::indexing_slicing` and
//! `clippy::arithmetic_side_effects` are **not** re-allowed: the tamper code is
//! the one place in this binary where an off-by-one would produce a
//! *misleading demonstration*, which is worse than a crash, so it is written
//! under the same discipline as the library.

#![forbid(unsafe_code)]
// Gate 7 exceptions, four of them, each for a reason a library would not have:
//
// - `unwrap_used`: `Mutex::lock` returns a `PoisonError`, and this binary
//   recovers from it deliberately (see `App::world`). Nothing else unwraps.
// - `expect_used` / `panic`: reachable only from `main`'s startup path, where
//   a failure means the demo cannot start and the right answer is to say so
//   and exit rather than to serve a half-built page.
// - `exit`: this crate is a `main`, not a library. Two paths take it — a
//   startup failure, and `getrandom` reporting that the OS entropy source is
//   gone (`entropy::OsRng::fill`). The second is the important one: continuing
//   with unknown bytes after a CSPRNG failure is how nonce reuse happens
//   (M1 §I.3), so stopping is the only correct answer available to a binary.
//
// The library crates re-allow none of these outside `#[cfg(test)]`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::exit)]

mod api;
mod demo;
mod entropy;
mod gates;
mod http;
mod json;

use std::net::TcpListener;
use std::sync::Arc;

/// The port tried first. If it is taken, the OS picks one.
const PREFERRED_PORT: u16 = 8787;

fn main() {
    let app = match api::App::new() {
        Ok(app) => Arc::new(app),
        Err(e) => {
            eprintln!("mlkb-demo: the handshake failed at startup: {e:?} ({e})");
            std::process::exit(1);
        }
    };

    let listener = bind();
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("mlkb-demo: could not read the listening address: {e}");
            std::process::exit(1);
        }
    };

    println!();
    println!("  ML-KEM-Braid demo harness");
    println!("  local verification tool - NOT a shipping component");
    println!();
    println!("  http://{addr}/");
    println!();
    println!("  Two real sessions are already live in this process:");
    println!("  the PQXDH handshake ran at startup with real ML-KEM-1024,");
    println!("  ML-DSA-65 and X25519 keys from the platform CSPRNG.");
    println!();
    println!("  Ctrl-C to stop.");
    println!();

    http::serve(&listener, move |req| app.route(req));
}

/// Binds loopback, preferring [`PREFERRED_PORT`] and falling back to an
/// ephemeral one.
///
/// `127.0.0.1` and nothing else: this process holds two live sessions' key
/// material, and there is no reason for anything off this machine to reach it.
fn bind() -> TcpListener {
    match TcpListener::bind(("127.0.0.1", PREFERRED_PORT)) {
        Ok(l) => l,
        Err(_) => TcpListener::bind(("127.0.0.1", 0)).unwrap_or_else(|e| {
            eprintln!("mlkb-demo: could not bind 127.0.0.1: {e}");
            std::process::exit(1);
        }),
    }
}
