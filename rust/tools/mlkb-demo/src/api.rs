//! The HTTP surface: routing, and rendering the world as JSON.
//!
//! Request bodies are `application/x-www-form-urlencoded` so that this binary
//! needs no JSON parser (see [`crate::json`]). Responses are JSON.
//!
//! | method | path | body | does |
//! |---|---|---|---|
//! | GET | `/` | | the page |
//! | GET | `/api/state` | | full snapshot |
//! | POST | `/api/reset` | | new identities, new handshake |
//! | POST | `/api/send` | `from`, `text` | seal a frame, leave it in flight |
//! | POST | `/api/deliver` | `id`, `tamper` | deliver it, optionally mutated |
//! | POST | `/api/replay` | `id` | re-deliver an already-accepted frame |
//! | POST | `/api/replay_handshake` | | replay the captured `0x01` frame |
//! | POST | `/api/probe` | `from` | liveness: send + deliver a real message |
//! | POST | `/api/registry` | `byte` | ask `MsgType::from_u8` directly |
//! | POST | `/api/gates` | | run `cargo test`; slow |

use std::sync::{Mutex, PoisonError};

use crate::demo::{Side, Tamper, World, registry_probe};
use crate::http::{Request, Response};
use crate::json::{Obj, array, str_array};

/// The page, compiled in. No build step, no CDN, no external fetch.
const INDEX_HTML: &str = include_str!("index.html");

/// Everything the server shares between connection threads.
#[derive(Debug)]
pub(crate) struct App {
    world: Mutex<World>,
}

impl App {
    /// Bootstraps a world.
    ///
    /// # Errors
    /// Any error the real handshake returns.
    pub(crate) fn new() -> Result<Self, mlkb_secrets::ProtocolError> {
        Ok(Self {
            world: Mutex::new(World::bootstrap()?),
        })
    }

    /// Routes one request.
    #[must_use]
    pub(crate) fn route(&self, req: &Request) -> Response {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/" | "/index.html") => Response::html(INDEX_HTML),
            ("GET", "/api/state") => self.state(),
            ("POST", "/api/reset") => self.reset(),
            ("POST", "/api/send") => self.send(req),
            ("POST", "/api/deliver") => self.deliver(req),
            ("POST", "/api/replay") => self.replay(req),
            ("POST", "/api/replay_handshake") => self.replay_handshake(),
            ("POST", "/api/probe") => self.probe(req),
            ("POST", "/api/registry") => Self::registry(req),
            ("POST", "/api/gates") => Self::gates(),
            ("GET" | "POST", _) => Response::status(404, "no such endpoint"),
            _ => Response::status(405, "method not allowed"),
        }
    }

    /// The world, recovering the guard if a thread panicked while holding it.
    ///
    /// A poisoned lock in this demo means a connection thread died mid-request;
    /// the world is a plain value with no partially-applied invariant, so
    /// recovering is correct here. (`mlkb-protocol` would report
    /// `ProtocolError::Internal`, per parent §8.5; a demo binary has no caller
    /// to report to.)
    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn state(&self) -> Response {
        Response::json(snapshot(&self.world()))
    }

    fn reset(&self) -> Response {
        match World::bootstrap() {
            Ok(fresh) => {
                *self.world() = fresh;
                Response::json(snapshot(&self.world()))
            }
            Err(e) => Response::json(error_obj(&format!("{e:?}"), &e.to_string())),
        }
    }

    fn send(&self, req: &Request) -> Response {
        let Some(from) = req
            .form
            .get("from")
            .map(String::as_str)
            .and_then(Side::parse)
        else {
            return Response::json(error_obj("Malformed", "unknown sender"));
        };
        let text = req.form.get("text").map_or("", String::as_str);
        if text.is_empty() {
            return Response::json(error_obj("Malformed", "empty message"));
        }
        let mut world = self.world();
        match world.send(from, text) {
            Ok(_) => Response::json(snapshot(&world)),
            Err(e) => {
                // The interesting one: Bob before he has received anything.
                // M1 §C.3 gives him nothing to encapsulate to, so the library
                // refuses, and the UI shows exactly that.
                let snap = snapshot(&world);
                Response::json(with_last_error(&snap, &format!("{e:?}"), &e.to_string()))
            }
        }
    }

    fn deliver(&self, req: &Request) -> Response {
        let Some(id) = req.form.get("id").and_then(|s| s.parse::<u64>().ok()) else {
            return Response::json(error_obj("Malformed", "missing frame id"));
        };
        let Some(tamper) = req
            .form
            .get("tamper")
            .map(String::as_str)
            .and_then(Tamper::parse)
        else {
            return Response::json(error_obj("Malformed", "unknown tamper mode"));
        };

        let mut world = self.world();
        let before_a = world.fingerprint(Side::Alice);
        let before_b = world.fingerprint(Side::Bob);
        match world.deliver(id, tamper) {
            Ok(outcome) => {
                let after_a = world.fingerprint(Side::Alice);
                let after_b = world.fingerprint(Side::Bob);
                let mut o = Obj::new();
                o.raw("state", &snapshot(&world))
                    .raw("outcome", &outcome_obj(&outcome))
                    .str("tamper", tamper.describe())
                    .raw("before", &fingerprints(&before_a, &before_b))
                    .raw("after", &fingerprints(&after_a, &after_b))
                    .bool(
                        "state_unchanged",
                        before_a.digest == after_a.digest && before_b.digest == after_b.digest,
                    );
                Response::json(o.done())
            }
            Err(e) => Response::json(error_obj(&format!("{e:?}"), &e.to_string())),
        }
    }

    fn replay(&self, req: &Request) -> Response {
        let Some(id) = req.form.get("id").and_then(|s| s.parse::<u64>().ok()) else {
            return Response::json(error_obj("Malformed", "missing frame id"));
        };
        let mut world = self.world();
        let before_a = world.fingerprint(Side::Alice);
        let before_b = world.fingerprint(Side::Bob);
        match world.replay(id) {
            Ok(outcome) => {
                let after_a = world.fingerprint(Side::Alice);
                let after_b = world.fingerprint(Side::Bob);
                let mut o = Obj::new();
                o.raw("state", &snapshot(&world))
                    .raw("outcome", &outcome_obj(&outcome))
                    .str(
                        "tamper",
                        "delivered a second time, bytes untouched - the frame MAC verifies exactly as it did the first time",
                    )
                    .raw("before", &fingerprints(&before_a, &before_b))
                    .raw("after", &fingerprints(&after_a, &after_b))
                    .bool(
                        "state_unchanged",
                        before_a.digest == after_a.digest && before_b.digest == after_b.digest,
                    );
                Response::json(o.done())
            }
            Err(e) => Response::json(error_obj(&format!("{e:?}"), &e.to_string())),
        }
    }

    fn replay_handshake(&self) -> Response {
        let mut world = self.world();
        match world.replay_handshake() {
            Ok((same_sid, guard_err)) => {
                let mut o = Obj::new();
                o.raw("state", &snapshot(&world))
                    .bool("respond_accepted", true)
                    .bool("same_session_id", same_sid)
                    .str(
                        "guard_error",
                        &guard_err.map_or_else(
                            || String::from("none - the guard admitted it"),
                            |e| format!("{e:?}"),
                        ),
                    );
                Response::json(o.done())
            }
            Err(e) => Response::json(error_obj(&format!("{e:?}"), &e.to_string())),
        }
    }

    fn probe(&self, req: &Request) -> Response {
        let Some(from) = req
            .form
            .get("from")
            .map(String::as_str)
            .and_then(Side::parse)
        else {
            return Response::json(error_obj("Malformed", "unknown sender"));
        };
        let mut world = self.world();
        match world.probe(from) {
            Ok(outcome) => {
                let mut o = Obj::new();
                o.raw("state", &snapshot(&world))
                    .raw("outcome", &outcome_obj(&outcome));
                Response::json(o.done())
            }
            Err(e) => {
                let snap = snapshot(&world);
                Response::json(with_last_error(&snap, &format!("{e:?}"), &e.to_string()))
            }
        }
    }

    fn registry(req: &Request) -> Response {
        let byte = req
            .form
            .get("byte")
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0x07);
        let mut o = Obj::new();
        o.num("byte", u64::from(byte));
        match registry_probe(byte) {
            Ok(t) => {
                o.bool("accepted", true).str("result", &format!("{t:?}"));
            }
            Err(e) => {
                o.bool("accepted", false)
                    .str("result", &format!("{e:?}"))
                    .str("message", &e.to_string());
            }
        }
        Response::json(o.done())
    }

    fn gates() -> Response {
        let workspace = crate::gates::run(&["test", "--workspace"]);
        let kat = crate::gates::run(&[
            "test",
            "-p",
            "mlkb-crypto",
            "--test",
            "key_schedule_kat",
            "--test",
            "xeddsa_kat",
        ]);
        let mut o = Obj::new();
        o.raw("workspace", &run_obj(&workspace))
            .raw("kat", &run_obj(&kat));
        Response::json(o.done())
    }
}

fn run_obj(r: &crate::gates::Run) -> String {
    let mut o = Obj::new();
    o.str("command", &r.command)
        .bool("ok", r.ok)
        .num("passed", r.passed)
        .num("failed", r.failed)
        .num("ignored", r.ignored)
        .str("tail", &r.tail);
    o.done()
}

fn error_obj(code: &str, message: &str) -> String {
    let mut o = Obj::new();
    o.str("error", code).str("message", message);
    o.done()
}

/// Splices a `last_error` field onto an already-rendered snapshot object.
///
/// Cheap and obvious: the snapshot is `{...}` and this replaces the final `}`.
fn with_last_error(snapshot: &str, code: &str, message: &str) -> String {
    let mut o = Obj::new();
    o.raw("state", snapshot)
        .str("error", code)
        .str("message", message);
    o.done()
}

fn fingerprints(a: &crate::demo::StateFingerprint, b: &crate::demo::StateFingerprint) -> String {
    let mut o = Obj::new();
    o.raw("alice", &fingerprint_obj(a))
        .raw("bob", &fingerprint_obj(b));
    o.done()
}

fn fingerprint_obj(f: &crate::demo::StateFingerprint) -> String {
    let mut o = Obj::new();
    o.num("send_epoch", f.send_epoch)
        .num("recv_generation", f.recv_generation)
        .num("skipped_keys", f.skipped_keys)
        .bool("ratchet_due", f.ratchet_due)
        .str("digest", &f.digest);
    o.done()
}

fn outcome_obj(o: &crate::demo::Outcome) -> String {
    let mut obj = Obj::new();
    obj.str("stage", o.stage)
        .bool("accepted", o.accepted)
        .raw("events", &str_array(&o.events));
    match o.error {
        Some(e) => {
            obj.str("error", &format!("{e:?}"))
                .str("message", &e.to_string());
        }
        None => {
            obj.bool("error", false);
        }
    }
    match &o.plaintext {
        Some(pt) => {
            obj.str("plaintext", pt);
        }
        None => {
            obj.bool("plaintext", false);
        }
    }
    obj.done()
}

/// The whole world, as one JSON object.
fn snapshot(world: &World) -> String {
    let h = &world.handshake;
    let mut hs = Obj::new();
    hs.str("alice_id", &h.alice_id)
        .str("bob_id", &h.bob_id)
        .bool("bundle_verified", h.bundle_verified)
        .num("bundle_bytes", h.bundle_bytes as u64)
        .num("mldsa_vk_bytes", h.mldsa_vk_bytes as u64)
        .num("kem_ek_bytes", h.kem_ek_bytes as u64)
        .num("hybrid_sig_bytes", h.hybrid_sig_bytes as u64)
        .num("initial_frame_bytes", h.initial_frame_bytes as u64)
        .num("kem_ct_bytes", h.kem_ct_bytes as u64)
        .str("alice_sid", &h.alice_sid)
        .str("bob_sid", &h.bob_sid)
        .bool("sid_match", h.sid_match)
        .str("initial_wire", &h.initial_wire)
        .num("handshake_seq", world.handshake_seq());

    let inflight: Vec<String> = world
        .inflight
        .iter()
        .map(|f| {
            let mut o = Obj::new();
            o.num("id", f.id)
                .str("from", f.from.name())
                .str("to", f.from.peer().name())
                .num("epoch", f.epoch)
                .num("n", f.n.unwrap_or(u64::MAX))
                .bool("has_n", f.n.is_some())
                .bool("opens_chain", f.opens_chain)
                .num("bytes", f.wire.len() as u64)
                .str("wire", &crate::json::hex(&f.wire))
                .str("plaintext", &f.plaintext);
            o.done()
        })
        .collect();

    let delivered: Vec<String> = world
        .delivered
        .iter()
        .map(|d| {
            let mut o = Obj::new();
            o.num("id", d.id)
                .str("from", d.from.name())
                .str("to", d.from.peer().name())
                .num("bytes", d.wire.len() as u64)
                .str("plaintext", &d.plaintext);
            o.done()
        })
        .collect();

    let log: Vec<String> = world
        .log
        .iter()
        .map(|l| {
            let mut o = Obj::new();
            o.str("kind", &l.kind)
                .str("text", &l.text)
                .bool("rejected", l.rejected);
            o.done()
        })
        .collect();

    let (peers, sessions) = world.guard_counts();
    let mut guard = Obj::new();
    guard
        .num("peers", peers as u64)
        .num("sessions", sessions as u64);

    let mut root = Obj::new();
    root.raw("handshake", &hs.done())
        .raw("alice", &fingerprint_obj(&world.fingerprint(Side::Alice)))
        .raw("bob", &fingerprint_obj(&world.fingerprint(Side::Bob)))
        .raw("guard", &guard.done())
        .bool("bundle_ok", world.bundle_ok())
        .raw("inflight", &array(&inflight))
        .raw("delivered", &array(&delivered))
        .raw("log", &array(&log));
    root.done()
}
