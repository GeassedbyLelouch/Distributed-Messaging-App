# ML-KEM-Braid — General Chat Protocol Security Audit

**Date:** 2026-07-31
**Scope:** The general chat protocol (excludes the SP2 `attestation/` subsystem, audited separately).
**Method:** Four parallel adversarial code audits (verify-only), one per subsystem, followed by
controller spot-verification of every HIGH and the marquee protocol finding against source.
**Hard requirement:** Post-quantum compatibility is mandatory — findings that touch the PQ posture
are called out explicitly in the [PQ Assessment](#post-quantum-assessment).

Files covered (~9,200 LOC): `crypto/`, `core/`, `pqxdh/`, `protocol/`, `server/`, `transport/`,
`client/`, `sesame/`, `decentralized/`, `encoding/`, `wire.py`, `tls.py`.

---

## 1. Executive Summary

The cryptographic core is **sound**. The load-bearing security properties hold:

- **PQ confidentiality is correctly bound.** `SK = HKDF(F ‖ DH1..DHn ‖ SS, info=INFO‖IK_A‖IK_B)`
  (`pqxdh/pqxdh.py:209-211`) mixes the ML-KEM shared secret **and** every DH output into the root
  key. There is **no negotiation or downgrade path** that drops the PQ leg — verified.
- **No SQL injection.** Every statement in `sesame/sqlite_store.py` uses `?` placeholder binding;
  the only interpolated SQL uses hardcoded module constants (`sqlite_store.py:179-185`).
- **No IDOR** in messaging/contacts — routes are token-scoped with ownership checks.
- **Constant-time discipline** on all authenticated equality (`hmac.compare_digest` throughout).
- **Fail-closed state machines** — ratchet/authenticator commit state *only after* AEAD/MAC verify;
  no exception path turns a crypto failure into a silent accept.
- Prekey signatures are verified before use with distinct XEdDSA domain contexts.

The real weaknesses are **availability/DoS, replay, atomicity, and integrity-of-untrusted-inputs** —
not confidentiality breaks. Three HIGH, fourteen MEDIUM, fourteen LOW.

The two issues most relevant to the PQ hard requirement are the **OPK forward-secrecy degradations**
(H1, H2) and the **classical-only identity signatures** (see §5) — the latter is a design decision
for iteration 2, not a bug.

---

## 2. Consolidated Findings

| ID  | Sev  | Subsystem | Title | Location |
|-----|------|-----------|-------|----------|
| H1  | HIGH | server | Unauthenticated OPK depletion → FS degradation | `server/app.py:636` |
| H2  | HIGH | decentralized | Non-atomic OPK claim (TOCTOU) double-leases one-time prekey | `decentralized/opk.py:55-61` |
| H3  | HIGH | encoding | Erasure shards have no per-share integrity → silent corruption | `encoding/erasure.py:52-64,146-183` |
| M1  | MED  | protocol | Unauthenticated framing → one packet permanently desyncs SCKA | `protocol/states.py:966`, `protocol/messages.py:109` |
| M2  | MED  | pqxdh | Replayable handshake on no-OPK / last-resort path | `pqxdh/pqxdh.py:254-280` |
| M3  | MED  | ratchet | Skipped-key store unbounded (only per-msg cap) → memory DoS | `core/double_ratchet.py:257-262` |
| M4  | MED  | crypto | AES-GCM random 96-bit nonce; single-use-key not enforced | `core/aead.py:23`, `core/provider.py:47` |
| M5  | MED  | decentralized | Circuit GCM nonce from caller seq, uniqueness unenforced | `decentralized/circuits.py:151-159` |
| M6  | MED  | decentralized | `size_class` ignored — no padding, on-wire length leaks | `decentralized/circuits.py:84-123` |
| M7  | MED  | decentralized | Record `expires_at`/sequence not enforced → replay/rollback | `decentralized/records.py:196`, `services.py:21-45` |
| M8  | MED  | decentralized | Canonical form is JSON — non-injective, float-nondeterministic | `decentralized/canonical.py:8-15` |
| M9  | MED  | decentralized | Username squatting — no preimage proof, permanent | `decentralized/services.py:36-45,120-133` |
| M10 | MED  | decentralized | Rendezvous join unauthenticated — squat/DoS 2-slot channel | `decentralized/rendezvous.py:16-29` |
| M11 | MED  | server | `X-Forwarded-Proto` trusted unconditionally → TLS-gate bypass | `server/app.py:96-98` |
| M12 | MED  | server | Unauthenticated unlimited registration; `int(k)` → 500 | `server/app.py:445-474` |
| M13 | MED  | server | No rate limiting; mailbox flooding; unbounded `body` dict | `server/app.py:643-661` |
| M14 | MED  | server | Circuit relay: unbounded map + unbounded JSON recursion | `server/decentralized_routes.py:21-33,72-91` |
| L1  | LOW  | crypto | `decaps` bypasses FIPS-203 length validation | `core/ml_kem.py:247` |
| L2  | LOW  | crypto | `encaps1` trusts caller `hek`, no in-module binding | `core/ml_kem.py:196` |
| L3  | LOW  | crypto | VRF length invariant is `assert` (stripped under `-O`) | `crypto/vxeddsa.py:43` |
| L4  | LOW  | crypto | AEAD `associated_data` defaults empty — epoch not bound by default | `core/aead.py:19` |
| L5  | LOW  | crypto/ratchet | No zeroization of chain/root/message keys (Python `bytes`) | multiple |
| L6  | LOW  | ratchet | Non-canonical AD/MAC-input concatenation (fragile) | `core/double_ratchet.py:205`, `authenticator.py:154` |
| L7  | LOW  | protocol | `Message.from_bytes` silently ignores trailing bytes | `protocol/messages.py:145-149` |
| L8  | LOW  | ratchet | Cross-epoch out-of-order messages permanently undecryptable | `core/double_ratchet.py:223-248` |
| L9  | LOW  | server | Bearer token in WebSocket query string → logs/history | `server/app.py:683-704` |
| L10 | LOW  | server | Envelope IDs reset per process → collide after restart | `server/app.py:317-321` |
| L11 | LOW  | server | Error strings confirm account existence / leak internals | `server/app.py:468`, `decentralized_routes.py:50` |
| L12 | LOW  | decentralized | Unauthenticated mailbox delivery + open relay forwarding | `decentralized/services.py:47-56,101-117` |
| L13 | LOW  | decentralized | Relay capabilities/`min_circuit_hops` self-asserted | `decentralized/descriptors.py:25-49` |
| L14 | LOW  | decentralized | Vault stores secrets cleartext, unauth, no rollback guard | `decentralized/vault.py:15-55` |

---

## 3. HIGH Findings (detail + fix)

### H1 — Unauthenticated OPK depletion → forward-secrecy degradation
`server/app.py:636-641` → `sesame/sqlite_store.py:829-867`

`GET /keys/{username}/{device_id}` has **no `Depends(auth_device)`** (contrast `/messages`,
`app.py:645`) and `take_prekey_bundle` deletes one OPK per call
(`DELETE FROM one_time_prekeys ... LIMIT 1`). Any network client can loop the endpoint, drain the
finite pool (default 4), after which every initiator silently falls back to `opk_id=None`.

**Impact:** degraded forward secrecy for all future sessions against that device (fewer ephemeral
DH contributions). **Note:** this is a *forward-secrecy* degradation, not a *PQ* downgrade — the
PQ ML-KEM leg comes from the signed last-resort `pqspk` and is still present without an OPK.

**Fix:** keep the endpoint reachable (Signal model) but (a) per-source-IP rate-limit, (b) refuse to
consume the last OPK for anonymous callers / cap consumption per requester, (c) alert-and-replenish.

### H2 — Non-atomic OPK claim double-leases a one-time prekey
`decentralized/opk.py:55-61`

`lease_opk` scans for the first `state == "available"` entry then sets `"leased"` — a check-then-act
with **no lock** spanning the two operations. Two concurrent leases for the same device both observe
the entry available and both return the same `opk_id`/`opk_pub`.

**Impact:** the one-time prekey is consumed in two handshakes → breaks OPK uniqueness → forward
secrecy / KCI resistance for those sessions. Secondary: expired leases go `leased → "expired"`
(`opk.py:89-94`) and are never returned to `available`, permanently burning the OPK (exhaustion DoS).

**Fix:** atomic compare-and-set — under a mutex in-memory, or `UPDATE ... WHERE state='available'
... RETURNING` (single-statement CAS) in a DB backend. Reclaim expired leases to `available`, or
document burn-once explicitly.

### H3 — Erasure shards have no per-share integrity
`encoding/erasure.py:52-64,146-183`

`Chunk` is `index + data` only — no authenticator (verified: `erasure.py:56-57`). `add_chunk`
accepts any in-range index and overwrites on duplicate index (`:148`); RS **erasure** decoding treats
all present chunks as correct (error positions = missing indices only, `:172,180`) and cannot detect
byte-flips in delivered shards.

**Impact:** a malicious relay flips one byte, or replays a duplicate index with different data →
reconstruction succeeds and returns a **corrupted object with no error signalled**.

**Fix:** per-share keyed tag (HMAC / keyed-BLAKE2 over `index ‖ data`) verified in `add_chunk` before
insertion; reject duplicate-index-with-differing-data; add an AEAD/hash tag over the whole
reconstructed message. Keep RS for loss only, never for corruption detection.

---

## 4. MEDIUM & LOW Findings (grouped by remediation theme)

**AEAD misuse-resistance (M4, M5, L4).** Two independent random/deterministic-nonce paths rely on an
unenforced single-use-key assumption. A nonce collision under one AES-GCM key is a *full* break
(leaks the GHASH key → forgery). Fix: bind nonces to a module-owned monotonic counter with overflow
rejection, **or** adopt a misuse-resistant AEAD (AES-GCM-SIV / XChaCha20-Poly1305). Make AEAD
`associated_data` required so epoch/header is always bound.

**Unauthenticated framing / desync (M1, L7, L6).** The Braid MAC covers header contents and
ciphertext bytes but **not** the wire framing (`MessageType`, length prefix, `epoch` on
non-header/ct messages). State transitions key off these unauthenticated fields
(`states.py:966`), so a single spoofed `Message(epoch+1)` drives `Ct2Sampled → KeysUnsampled`,
`braid.py` bumps `self.epoch`, and — because `epoch` is bound into every subsequent MAC — the session
halts permanently and undetectably. Fix: feed the **entire serialized frame** into the MAC/AEAD AD;
reject trailing bytes; length-prefix every MAC-input component.

**Replay / rollback (M2, M7).** (M2) The no-OPK / last-resort PQXDH path consumes no state, so a
captured `InitialMessage` re-derives the identical `SK` on replay — the docstring overclaims replay
protection. Fix: require an OPK, or add a replay cache on `(ik_pub, ek_pub, kem_ct)`; rotate the
signed prekey; fix the docstring. (M7) `verify_record` never checks `expires_at` against a clock and
`publish_record` enforces no `sequence` monotonicity → expired/old signed records replay, and
`derive_contact_state` accepts non-terminal→terminal reorderings. Fix: enforce freshness windows and
per-`(type, author)` monotonic sequence; make terminal contact states immutable.

**Unbounded state / DoS (M3, M13, M14, M12, L12).** `MAX_SKIP` caps per-message catch-up but not
cumulative `_skipped` storage (`double_ratchet.py:257`); `/messages` has no rate limit and an
unbounded `body` dict; the decentralized circuit relay appends attacker JSON to a process-global map
with no caps and recurses over unbounded nesting (`RecursionError` → 500); registration is
unauthenticated and unlimited (plus `int(k)` on a non-int key → 500). Fix: global skip-key cap with
LRU eviction; request-body size limit + per-recipient mailbox quota; authenticate + bound + TTL-evict
the circuit map, iterative metadata scan; rate-limit registration, cap `one_time_prekeys`, wrap
`int(k)`.

**Metadata / anonymity (M6, M10, L13).** `build_three_hop_frame` never calls `pad_payload`, so
frame length = `len(payload)+48` leaks the true length despite the advertised size class; rendezvous
stream-join is unauthenticated (squat/DoS the 2-slot channel); relay capabilities and
`min_circuit_hops` are self-asserted. Fix: pad to `size_class` before the first encryption and reject
off-size frames; authenticate joins with a MAC over the rendezvous token; enforce a client-side
`min_circuit_hops` floor and anchor relay identity to a trust list.

**Canonical encoding (M8, M9).** `canonical_json` uses `json.dumps`, which is non-injective
(int keys coerced to strings) and serializes floats (`created_at`/`expires_at`) via runtime
`repr(float)` — two honest verifiers on different builds can compute different canonical bytes for the
same record (consensus split). Username hashes carry no preimage binding → squatting. Fix: strict
binary canonical codec (deterministic DAG-CBOR / RFC 8785 JCS), **integer-only** timestamps
(epoch-ms), forbid floats, length-prefix all fields; require a preimage/commitment proof for
usernames and make records owner-updatable with monotonic sequence.

**TLS trust (M11).** `X-Forwarded-Proto` is trusted with no trusted-proxy allow-list, defeating the
426 TLS gate and poisoning HSTS over cleartext. Fix: honor the header only when `request.client.host`
is in a configured trusted-proxy set.

**KEM input validation (L1, L2).** `decaps` bypasses FIPS-203 public-API length checks (relies on
implicit rejection to mask malformed ct); `encaps1` trusts caller `hek` without binding it to
`ek_vector` in-module. Both are caught downstream by the authenticator MAC (not breaks), but should
validate lengths / recompute `hek` and raise typed errors.

**Robustness / hygiene (L3, L5, L8, L9, L10, L11, L14).** `-O`-strippable `assert` on VRF length;
no key zeroization; cross-epoch OOO loss; bearer token in WS URL; per-process envelope-ID collision
after restart; existence-oracle error strings; cleartext unauthenticated vault. Fixes are the obvious
per-item hardening (see the finding table locations).

---

## 5. Post-Quantum Assessment

| Property | Status | Notes |
|----------|--------|-------|
| Confidentiality (KEM) | **PQ ✓** | ML-KEM-1024 SS bound into root key; no downgrade path (`pqxdh.py:209-211`). Harvest-now-decrypt-later resistant. |
| Forward secrecy | **Degradable (H1, H2)** | Active/resource attacker can force the no-OPK path; PQ leg survives but ephemeral FS weakens. Fix H1/H2 to restore. |
| Authentication (identity) | **Classical only** | XEdDSA over Curve25519. A future CRQC could forge identity signatures for an *active* MITM. This is the standard PQXDH posture (PQ-confidential, classically-authenticated). |

**Design decision for iteration 2 — DECIDED (2026-07-31): HYBRID PQ AUTH.** The identity/prekey
signature path will be **hybrid Curve25519-XEdDSA + ML-DSA-65** (dual signatures; a signature is
valid only if *both* legs verify), preserving classical interop while adding CRQC resistance to the
authentication path. Pure ML-DSA would drop the single-key X25519/DH reuse the current design depends
on, so the hybrid keeps the X25519 identity for DH and adds a co-located ML-DSA key for signing. The
KEM is already PQ and needs no change. This is an **iteration-2 (Rust) protocol feature**, not part of
the Python hardening pass — it changes key-bundle format, signature size, and the identity model, and
belongs in the from-scratch rewrite. See §7.6 for the port seam.

---

## 6. Remediation Priority

1. **Fix now (HIGH + FS-relevant):** H1, H2, H3, M1, M2 — these are the exploitable
   integrity/FS/desync issues.
2. **Fix before any multi-tenant deployment (server DoS + TLS):** M11, M12, M13, M14, H1's rate-limit.
3. **Fix before the decentralized layer is trusted:** M5, M6, M7, M8, M9, M10, H2.
4. **Hardening sweep:** M3, M4, all LOWs.

Note items 2–4 in the **decentralized/circuit** layer are gated on `enable_decentralized=True`; if
that path is not yet shipped, they can be folded straight into the Rust rewrite rather than patched
in Python.

---

## 7. Rust-Rewrite Prep (iteration 2)

### 7.1 Crate stack (all PQ-capable)

| Concern | Crate | Why |
|---------|-------|-----|
| ML-KEM (FIPS-203) | `ml-kem` (RustCrypto) or `libcrux-ml-kem` | **Caveat:** the Braid *split* (`ct1` in header, `ct2` later) needs K-PKE `u/v` internals RustCrypto doesn't expose publicly — plan to use `libcrux`'s lower-level API or vendor/fork, same reason kyber-py was chosen. |
| X25519 / XEdDSA | `x25519-dalek` + `curve25519-dalek` | XEdDSA sign/verify has no first-class dalek API — port the vendored Signal routine or use `libsignal`'s XEdDSA. |
| PQ signatures (if hybrid chosen) | `ml-dsa` (RustCrypto) / `pqcrypto` | For the §5 hybrid-auth decision. |
| AEAD | `aes-gcm-siv` or `chacha20poly1305` | Misuse-resistant — closes M4/M5 structurally. |
| KDF/MAC | `hkdf`, `hmac`, `sha2` | Drop the hand-rolled `hkdf_expand`. |
| Secret hygiene | `zeroize` (`Zeroizing`, `ZeroizeOnDrop`) | Closes L5 — Python cannot wipe `bytes`. |
| Const-time | `subtle` (`ConstantTimeEq`) | Port `hmac.compare_digest`. |
| Canonical codec | `ciborium` + canonical/DAG-CBOR, or `serde_json_canonicalizer` | Closes M8; integer-only timestamps. |
| Server | `axum` + `tokio` | — |
| TLS | `rustls` via `tokio-rustls` | — |
| DB | `sqlx` (compile-checked queries) | SQLi structurally impossible. |
| Rate limit / limits | `governor`, `tower`/`tower-http` (`DefaultBodyLimit`) | Closes M13/M14 body/frame vectors. |
| Bounded maps | `heapless` / capped LRU / `moka` (TTL) | Closes M3/M14 unbounded growth. |
| Deserialize | `serde` + `#[serde(deny_unknown_fields)]` | Closes unknown-field injection; serde recursion limit closes M14. |

### 7.2 Defects that become *structurally impossible* in Rust

- **SQLi** — `sqlx::query!` verifies SQL against the schema at compile time.
- **Sender spoofing** — model the authenticated `Device` as an axum `FromRequestParts` extractor so a
  handler *cannot* be written without resolving identity from the token.
- **Nonce reuse (M4/M5)** — one-shot move-only AEAD key (`fn seal(self, …)`) or a `NonceSequence` that
  rejects reuse/overflow; misuse-resistant AEAD as backstop.
- **Key-after-ratchet reuse / no-zeroize (L5)** — chain-step functions **consume** the old key by
  value and keys are `Zeroizing<[u8;32]>`.
- **Unbounded skip map (M3)** — fixed-capacity map whose insert returns `Err(TooManySkipped)`.
- **State confusion (M1)** — type-state machine: `Braid<Ct2Sampled>::receive(self, …) -> Result<Next>`;
  illegal transitions fail to compile instead of silently no-op-ing.
- **`int(k)`/nested-JSON 500s (M12/M14)** — typed serde structs + built-in recursion limit.
- **Trailing-byte malleability (L7)** — exact-length `#[derive]`d parsing rejects trailing bytes.

### 7.3 Defects that still need *deliberate design* (not free from the language)

- Rate limits / quotas (H1, M12, M13) — policy, not memory-safety: add `governor`/`tower::limit`,
  per-recipient mailbox quota, "don't burn the last OPK anonymously" rule.
- Atomic OPK claim (H2) — DB `UPDATE … WHERE state='available' … RETURNING` or `Mutex` CAS; typestate
  `Available → Leased → Consumed`; reclaim expired leases.
- Per-share MAC (H3), record freshness/monotonicity (M7), canonical binary codec (M8), constant-size
  rendezvous framing + authenticated join (M6, M10), `X-Forwarded-Proto` trusted-proxy allow-list
  (M11), hybrid PQ auth (§5) — all architectural decisions the language enables but does not mandate.

### 7.4 Invariants the Rust port MUST preserve (do not regress)

1. `SK = HKDF(F ‖ DH1..DHn ‖ SS, info=INFO ‖ IK_A ‖ IK_B)` — PQ KEM SS **and** all DH legs bound; no
   downgrade path. (The PQ hard requirement lives here.)
2. Prekey signatures verified **before** use, with distinct domain contexts per role.
3. XEdDSA domain framing `TAG ‖ u16(len(ctx)) ‖ ctx ‖ msg`, injective and disjoint from the raw path.
4. Commit ratchet/authenticator state **only after** AEAD/MAC verification.
5. Constant-time equality on every authenticated comparison.
6. Single Curve25519 identity does both DH and signing (unless §5 hybrid changes this deliberately).

### 7.5 Python footguns to drop in the port

`bytes` immutability preventing key-wipe; `json` float-repr nondeterminism; `MappingProxyType`
freeze/thaw round-trips; `bool`-is-`int`; silent dict-key overwrite (`add_chunk`, `publish_record`);
exception-as-control-flow conflating "auth failed" with "need more data"; in-place mutation of
caller-owned dicts (`responder_handshake` mutates `secrets.opk_priv`); `-O`-strippable `assert`s;
silent bignum promotion masking counter overflow (use `checked_add` on `u64` epoch/index).

---

# 8. Hardening Outcome (rounds 1–2) and the Architectural Finding

**Status:** 802 tests passing (from 712 baseline / 458 pre-audit). 42 files changed,
+6,766/−663, 13 new files. **Nothing committed** — the tree awaits human review.

## 8.1 What was applied

Round 1 applied all 31 findings. Three independent adversarial verifiers then attacked the result;
**all three returned DEFECTIVE (23 defects, 1 CRITICAL + 3 HIGH)**. Round 2 fixed those. Three fresh
verifiers attacked again: **all three returned DEFECTIVE (17 defects, 2 CRITICAL + 6 HIGH)**, while
independently confirming 23 fixes as genuinely sound.

Genuinely closed and independently re-confirmed: M1 frame authentication (now directional — reflection
fails), H2 OPK claim atomicity, H3 erasure per-share integrity (now ON by default on the real
`states.py` path — round 1's version was opt-in and **no caller opted in**), M6 circuit padding, M7/M8
canonical encoding + record freshness, M11 trusted-proxy TLS gating, M5 circuit nonce high-water mark,
plus deduplication of three copy-pasted controls (JSON codec, client-IP keying, token bucket) whose
divergence *was* the round-1 bug.

Two process findings worth keeping: the integrator caught a **duplicate JSON codec in
`transport/http_client.py` that silently dropped the new frame MAC** — a total availability break on a
production path no test covered; and a rate limit that throttled the **handshake itself** (~46 posts
per epoch against a 120-token bucket).

## 8.2 The architectural finding — a bounded-resource oscillation

The two rounds produced mirror-image failures:

| | Round 1 | Round 2 |
|---|---|---|
| Pattern | bounded cache **evicts** on overflow | bounded cache **rejects** on overflow |
| Failure | attacker floods → victim's entry evicted → **original attack restored** | attacker floods → shared capacity consumed → **victim locked out permanently** |
| Instances | replay cache, skip-key map, AEAD guard, circuit store, forward quota, sequence guard | replay-guard partition table, forward-quota table, mailbox cap, AEAD guard, circuit partition |

Fixing fail-open produced fail-closed; fixing fail-closed would reproduce fail-open. **This is not a
sequence of implementation mistakes — it is a structural property of the current design.**

**Root cause:** every control is keyed on an identity that is *free to mint*. `POST /register` is
unauthenticated by design, and an X25519 identity is one keygen. So every bounded structure keyed by
caller — replay partitions, quotas, mailboxes, rate buckets — can be filled by one attacker at
negligible cost. With a free-to-mint key, **both** overflow policies lose:

- evict → the attacker displaces the victim's entry;
- reject → the attacker consumes the victim's capacity.

No overflow policy resolves this. The dominant remaining defects (PQXDH replay-partition lockout,
relay forward-quota lockout, mailbox jamming, OPK depletion) are all one bug wearing different hats.

**The two resolutions, neither of which is a cache-tuning exercise:**

1. **Make identity minting cost something** — the control must be anchored to a scarce principal
   (rate-limited/attested registration, invite, stake, or proof-of-work). Then per-principal
   partitioning finally means something and *both* overflow policies become safe.
2. **Replace remembered-event sets with unforgeable-small state** — a monotonic per-peer sequence
   (`handshake_seq` in `InitialMessage` + a per-initiator floor) makes replay detection O(1) per known
   peer and unfloodable by strangers. This **requires a wire-format change**, which is precisely why
   round 2's agents correctly deferred it.

Both belong in **iteration 2 (Rust)**, not in another Python patch round. A third round would very
likely oscillate back to fail-open.

## 8.3 H1 (OPK depletion): the control is the wrong shape

Declared fixed twice; still broken, verified directly. With the default pool of 4
(`client/client.py:123`) and `opk_reserve_floor = 1` (`server/app.py:192`), three requests from a
free-to-mint account drive `remaining <= floor`, and **the reserved prekey is then served to nobody**
(`app.py:896-912`) — every subsequent session takes the no-OPK path permanently. A reserve that is
never handed out is indistinguishable from an empty pool.

**Assessment:** the severity is *lower* than "CRITICAL" implies. Falling back to the signed prekey on
OPK exhaustion is **standard Signal/X3DH behavior**, and the PQ leg survives intact via the signed
last-resort ML-KEM prekey — so this is a bounded forward-secrecy degradation, **not** a PQ downgrade.
The correct fix is operational (client-side replenishment + the depletion telemetry now in place),
combined with §8.2's scarce-identity change. It is not a floor-tuning problem.

## 8.4 Carried into the Rust design (additions to §7)

- **Scarce principals first.** Design the identity/registration cost model *before* the quota model.
  Every per-principal bound is only as strong as the cost of minting a principal.
- **Prefer monotonic counters over remembered sets** for replay/uniqueness. Put `handshake_seq` in the
  wire format from day one — retrofitting it is what forced the deferral here.
- **Persist the AEAD nonce counter with the key.** `vault.py` restarts `CounterAeadKey` at 0
  (`vault.py:113`), which repeats nonces under a stable at-rest key — a full AEAD break. In Rust, make
  the counter inseparable from the key at the type level (a key handle that cannot be constructed
  without its counter).
- **No unbounded-in-time growth in a security decision.** The single-use AEAD guard grows one entry per
  message and hard-fails at 2^18 (`core/aead.py:100`); the correct answer is the type-state one-shot
  key from §7.2, not a fingerprint set.
- **Ship no dev-only crypto in a public class.** `client/anonymous_transport.py:30-35` hardcodes
  published layer keys with no runtime guard.
- **An opt-in security feature nobody opts into is not a feature.** H3 and L13 both shipped inert.
  In Rust, make the secure path the only constructible one.
