# `mlkb-demo` — local verification harness

**This is not a shipping component.** It is a developer tool: a single binary
that runs two real ML-KEM-Braid sessions in one process and serves a browser
page so a human can watch the protocol work and watch it refuse things.

```
cargo run -p mlkb-demo
```

It prints the URL it bound (`http://127.0.0.1:8787/` by default, or an
OS-assigned port if that one is taken). Open it. Ctrl-C to stop.

## What it demonstrates

Everything on the page was produced live by `mlkb-crypto`, `mlkb-wire` and
`mlkb-protocol`, from the platform CSPRNG. There is no mock, no fixture and no
canned output in this crate.

1. **Two hybrid identities** — X25519 + ML-DSA-65 — and their `IdentityId`s.
2. **Bob's prekey bundle**, verified by Alice with `verify_bundle` before any
   key in it is used (parent §4.3), with the sizes surfaced: the bundle is
   ~13.9 KB, of which 1952 bytes is one ML-DSA-65 verifying key, 1568 is one
   ML-KEM-1024 encapsulation key and 3381 is *one* hybrid signature. That is the
   honest post-quantum cost and the page does not hide it.
3. **PQXDH**, and whether both sides derived the same `SK` — shown as the two
   independently computed `session_id` values, because `SK` itself has no
   accessor and that equality is the only observation of agreement either end
   can make.
4. **A live chat.** Sending seals a frame and leaves it *in flight*; nothing
   moves until you deliver it. The real wire hex, the frame epoch and the
   in-chain index are all shown, and the ratchet counters advance as you go.
5. **Tamper controls** (see below).
6. **A gates panel** that shells out to `cargo test --workspace` and the two KAT
   suites and reports what cargo actually printed.

## The tamper controls, and what they honestly show

The frame MAC's preimage is `label ‖ wire[0 .. 15+payload_len]` (M1 §A.1) — the
whole frame except the tag. So **every** byte-level mutation is refused at
`decode_frame`, before the state machine sees anything:

| button | real result |
|---|---|
| flip a ciphertext bit | `Unauthenticated` at `decode_frame` |
| flip a frame-MAC bit | `Unauthenticated` at `decode_frame` |
| set a reserved `msg_type` | `Unauthenticated` at `decode_frame` |
| flip an epoch bit | `Unauthenticated` at `decode_frame` |

Those four giving the *same* answer is the point, not a shortcoming of the demo:
audit M1's defect was a MAC that did not cover the framing. It does now.

A consequence worth stating: M1 §A.1 rule 6 ("validate `msg_type` only *after*
the MAC verifies") is therefore unreachable from outside without the frame key,
which `Session` does not expose and this tool does not add. The page instead
calls `MsgType::from_u8` directly so you can see the closed registry (M1 §A.2)
reject `0x00`, `0x07` and `0xFF`.

The attacks that *do* reach the state machine are the ones that change no bytes:

| button | real result |
|---|---|
| replay a delivered frame | `ReplayDetected` at `classify` |
| deliver `n=1` before its `n=0` sibling | `Malformed` at `classify` (M1 §D.3) |
| deliver out of order within a chain | accepted, `KeysSkipped`, then the delayed message opens from the cache (M1 §D.4) |
| replay the captured handshake | `respond` accepts it (it has no replay defence, by design); `HandshakeGuard::admit` refuses it with `ReplayDetected` |

### The state fingerprint, and its limits

After every delivery the page shows a before/after fingerprint for both sides so
you can see that a rejected frame moved nothing (parent §8.1). Read the small
print: the fingerprint is `SHA-256` over `send_epoch`, `recv_generation`, the
skipped-key count, `ratchet_due` and the `session_id`. `Session` exposes no
reader for the root key, either chain key, the frame keys or the ratchet
keypairs, and this tool does not add one, so those are **not** covered.

Use the **liveness probe** for the part the counters cannot show: it seals a
genuine message and delivers it, and a successful decrypt proves the receiving
chain key did not move either.

## Things the protocol itself makes visible here

- **The initiator necessarily speaks first.** `InitialMessageV2` (M1 §C.3)
  carries no ML-KEM encapsulation key for the initiator, so the responder has
  nothing to encapsulate to until it has received one application message. Try
  sending as Bob before Alice has spoken: `Session::send` really does return
  `Malformed`, and the page shows it.
- **A new chain cannot be entered out of order.** `"ek"`/`"kc"` travel only on
  the `n == 0` message, so an `n != 0` frame from an unopened chain is
  `Malformed`. Because `classify` cannot mutate, the demo keeps the frame in
  flight and you can re-offer it once its sibling arrives — which is exactly
  what a reorder buffer at `mlkb-session` would do for you.

## Why it lives in `tools/`

So that it can never become a dependency of the shipping library. `deny.toml`
and the parent §7 crate DAG govern `crates/`; putting a demo with an HTTP server
and a JSON writer in there would be putting a second serializer and an I/O stack
inside the graph those rules exist to protect.

## Constraints it was built under

- **No new dependencies.** There is no `axum`, no `tokio` and no `serde` in this
  workspace (`serde` is banned outright by `deny.toml`), and none were added.
  The binary carries its own blocking HTTP/1.1 server on `std::net::TcpListener`
  (thread per connection, `Connection: close`, bounded request line / header
  block / body, read and write timeouts) and its own JSON *writer*. Request
  bodies are `application/x-www-form-urlencoded`, so there is no JSON parser to
  get wrong.
- **No build step, no CDN, no external fetch.** One `index.html`, compiled in
  with `include_str!`, with inline CSS and JS.
- **Loopback only.** `127.0.0.1`, never `0.0.0.0`. This process holds two live
  sessions' key material.
- **Lints.** The crate takes the workspace lint table. It re-allows four of the
  parent §11 gate 7 set at the crate root — `unwrap_used`, `expect_used`,
  `panic` and `exit` — each with its reason stated in `src/main.rs`.
  `indexing_slicing` and `arithmetic_side_effects` are **not** re-allowed: the
  tamper code is the one place where an off-by-one would produce a *misleading
  demonstration*, which is worse than a crash.

## HTTP API

| method | path | body | does |
|---|---|---|---|
| GET | `/` | | the page |
| GET | `/api/state` | | full snapshot |
| POST | `/api/reset` | | new identities, new handshake |
| POST | `/api/send` | `from`, `text` | seal a frame, leave it in flight |
| POST | `/api/deliver` | `id`, `tamper` | deliver it (`none`/`ct`/`mac`/`type`/`epoch`) |
| POST | `/api/replay` | `id` | re-deliver an already-accepted frame |
| POST | `/api/replay_handshake` | | replay the captured `0x01` frame |
| POST | `/api/probe` | `from` | liveness: send and deliver a real message |
| POST | `/api/registry` | `byte` | ask `MsgType::from_u8` directly |
| POST | `/api/gates` | | run `cargo test`; slow |

It is drivable from `curl`:

```sh
curl -s localhost:8787/api/state
curl -s -X POST localhost:8787/api/send    -d 'from=alice&text=hello'
curl -s -X POST localhost:8787/api/deliver -d 'id=1&tamper=mac'
curl -s -X POST localhost:8787/api/deliver -d 'id=1&tamper=none'
curl -s -X POST localhost:8787/api/replay  -d 'id=1'
```

## One bound this tool imposes that the library does not

`World::send` refuses a plaintext over 4096 bytes before calling
`Session::send`. That is not decoration. `Session::send` performs its DH ratchet
step *before* `Frame::seal` can refuse an oversized payload, so a refused send
leaves the ratchet advanced and the peer permanently unable to enter the new
chain — the MEDIUM finding from the `mlkb-protocol` review. A chain-opening
message already carries `"ek"` (1568) and `"kc"` (1568), so a plaintext above
~62 KB trips `MAX_FRAME_PAYLOAD` and would silently kill the demo session. The
bound is the caller-side check that review says `mlkb-session` must impose in
any case, set well below the cliff rather than at it.
