# ML-KEM-Braid — Iteration 2 (Rust) Implementation Specification

**Status:** Normative. Supersedes all design-track documents.
**Date:** 2026-07-31
**Supersedes:** the four parallel design tracks (core-architecture, pq-crypto, structural-fixes, ffi-mobile).
Where this document and a design track disagree, **this document wins**.
**Predecessor:** `docs/security/2026-07-31-chat-protocol-audit.md` (the audit that motivates the rewrite).

---

## 0. Why this document exists, and how to read it

Four engineers independently designed parts of this rewrite. An adversarial review found **19
contradictions and 12 gaps** between them: three incompatible `InitialMessage` layouts, three different
identity-hash preimages (producing three different session keys), three `derive_sk` signatures, three
crate graphs, and three mutually-rebutting AEAD choices — each citing the same audit finding as support.

That outcome is not a failure of the designers. It is **the audit's own root finding, reproduced at
design time**: the most instructive defect in the Python implementation was a *duplicated definition of
one control that diverged silently* (a second JSON codec that dropped the frame MAC; three copies of the
rate-limit key function fixed in none of them). Given four owners and no normative document, the same
divergence reappeared in a day.

**Therefore rule zero:** every wire byte, every KDF label, every key type has exactly one normative
definition, and it is in §3–§5 of this document. No crate, no design note, and no code comment may
restate them. Implementations reference; they do not repeat.

Reader's guide:

| Section | Contains |
|---|---|
| §1–2 | Goals, threat model, scope cut (what ships first) |
| **§3–5** | **Normative:** wire format, key schedule, cryptographic suite |
| §6 | The structural fixes that resolve the audit's architectural finding |
| §7–8 | Crate architecture and the type-level mechanisms |
| §9 | Storage and durability |
| §10 | FFI and mobile integration |
| §11 | Build, CI, and the gates that must pass |
| §12 | Phased roadmap, risks, open questions |

Anything marked **[VERIFY]** is a claim this document does *not* assert as fact: it must be confirmed
during Phase 0 before it becomes load-bearing. A confident wrong number in a specification is worse than
a flagged unknown.

---

## 1. Goals and threat model

### 1.1 Goals

1. **Post-quantum confidentiality is mandatory and structural.** ML-KEM-1024 must be bound into every
   key derivation with no downgrade path — enforced by the type system, not by review.
2. **Post-quantum authentication** via hybrid Curve25519-XEdDSA + ML-DSA-65 dual signatures. Decided;
   not optional. Both legs must verify.
3. **Library-first.** One Rust core consumed by Rust, Kotlin/Java (Android), and Swift (iOS).
4. **Resolve the bounded-resource oscillation** (§6) — the finding two rounds of Python patching could
   not fix.
5. **Secrets never leave Rust.** No key material in JVM or Swift heaps, which cannot be zeroized.

### 1.2 Non-goals for iteration 2

- Byte-compatible interop with the Python implementation. The v2 wire format is **intentionally
  incompatible** (§3.1). There is no migration path; v2 is a new protocol version and old sessions are
  not upgraded. This decision is made here because no design track accepted it.
- Group messaging, multi-device sync, and the decentralized layer in the first shippable core (§2).

### 1.3 Threat model

| Adversary | Assumed capability | Must not achieve |
|---|---|---|
| Network attacker | Full read/write on the wire | Read plaintext, forge/replay a frame, desync a session, downgrade the PQ leg |
| Malicious server | Operates the directory/mailbox; sees all metadata it is given | Read plaintext, impersonate a user, silently substitute keys |
| Malicious peer | A valid, admitted identity | Exhaust another peer's resources, force another peer offline, reuse a one-time prekey |
| Free-identity flooder | Can mint identities at keygen cost | **Evict or lock out** any honest peer's security state (§6) |
| Device attacker (post-compromise) | Reads device memory/storage at time T | Decrypt traffic from before T (forward secrecy) |
| **CRQC** | Large quantum computer, retroactive | Decrypt recorded traffic; **and** (new in v2) forge identity signatures for an active MITM |

**Explicitly out of scope:** a compromised device at the time of use, malicious OS/hardware, and
side-channel attacks requiring physical possession.

---

## 2. Scope cut — what actually ships first

Every design track named a *different* item as "the largest risk". The combined design is a vendored
lattice fork, a hand-reimplemented XEdDSA, hybrid PQ auth, a blind-signature issuer service, a two-
platform FFI, a decentralized layer, and a from-scratch rewrite of 9,200 LOC. That is not one project.

**Minimum shippable core (M1).** In dependency order:

1. Phase 0 API-verification spike (§11.4) — gates everything.
2. `mlkb-secrets`, `mlkb-bounded`, `mlkb-codec` (canonical encoding), `mlkb-crypto`.
3. **PQXDH over the *monolithic, unmodified* ML-KEM-1024** — no Braid split yet.
4. Hybrid identity + prekey bundles (§4.3).
5. Double Ratchet + authenticated framing (§3.3).
6. Admission control, tier 1: attestation- and rate-limit-backed (§6.2).
7. Store + FFI + one reference app path per platform.

**Deferred to M2+, explicitly:**

| Deferred | Gate that must pass first |
|---|---|
| **Braid SCKA ciphertext split** | The vendored-K-PKE differential-equivalence gate (§11.4). Until it passes, the split does not exist. |
| Blind-signed voucher issuance | M1 admission shipped and measured; issuer service designed and staffed |
| Decentralized layer (circuits, rendezvous, records, erasure) | M1 shipped |
| Group / multi-device | M1 shipped |

**Rationale for deferring the Braid split — the most important scope decision here.** The split requires
K-PKE internals (`u`/`v` from `k_pke_encrypt`) that no maintained Rust crate exposes publicly. Taking a
patched, unaudited lattice implementation and putting it on the *initial key-agreement* path is the
single largest security risk in the rewrite. M1 therefore runs PQXDH on an unmodified upstream ML-KEM.
The Braid split, when it lands, is confined to the SCKA layer and never to PQXDH. This resolves the
crypto-vs-core-architecture contradiction over the trust perimeter: **the crypto track was right.**

---

## 3. NORMATIVE: wire format

All integers are **big-endian, fixed-width**. There are **no floats anywhere in any signed or
authenticated structure** — the Python canonical encoder serialized floats via the runtime's `repr`,
so two honest verifiers on different builds could compute different signed bytes.

### 3.1 Versioning

```
PROTOCOL_VERSION: u16 = 0x0200   // v2.0
```
Every top-level wire struct begins with `PROTOCOL_VERSION`. A mismatch is a hard reject — there is no
negotiation, because negotiation is a downgrade surface.

### 3.2 Canonical encoding

**Deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding)**, with these additional
restrictions, enforced by the encoder *and* re-checked by the decoder:

1. No floating-point major type. Encoding one is an error.
2. Timestamps are `u64` **milliseconds since Unix epoch**.
3. Map keys are text strings only, sorted by the RFC 8949 deterministic rule. Integer keys are rejected
   (Python's JSON coerced them to strings, making the encoding non-injective).
4. Every variable-length field is length-prefixed.
5. **Round-trip check:** the decoder re-encodes and requires byte equality before accepting. Non-canonical
   input is rejected, not normalized.

Exactly one implementation exists, in `mlkb-codec`. No other crate may depend on a serialization library.

### 3.3 Frame

The Python defect (audit M1) was that the MAC covered header contents and ciphertext but *not* the
framing, so one spoofed `Message(epoch+1)` permanently desynced a session.

```rust
struct Frame {
    version:   u16,
    epoch:     u64,
    msg_type:  u8,
    payload:   Vec<u8>,   // u32 length-prefixed on the wire
    frame_mac: [u8; 32],
}
```

**Normative MAC input** — the entire frame, length-prefixed, with a directional label:

```
frame_mac = HMAC-SHA256(
    K_frame_dir,
    "MLKEMBraid/frame/v2"     ||
    u16(version)              ||
    u64(epoch)                ||
    u8(msg_type)              ||
    u32(payload.len())        ||
    payload
)
```

`K_frame_dir` is **directional** (§4.4): initiator→responder and responder→initiator use different keys,
so a peer's own frame reflected back at it does not verify.

`frame_mac` is **mandatory**. There is no `Option<frame_mac>`, no unsealed path, and a decoder that
receives a frame without one rejects it. The decoder rejects trailing bytes (audit L7).

**PCS status of the framing layer — decided.** The frame key is derived from `SK` per §4.4 and does
**not** ratchet. `core/authenticator.py:127-139` documents the asymmetry that forces this: the
encapsulator ratchets on send, the decapsulator only after `ct2` is fully reassembled, and the Braid is
pipelined, so epoch-`e` frames can be in flight while `e-1` completes. A ratcheting frame key would make
honest frames unverifiable. **Therefore: frame authentication is an outsider-only control and this
specification makes no post-compromise-security claim for it.** Content authenticity and PCS come from
the ratcheting message keys. The core-architecture track's proposal to derive frame keys from
`output_key(N)` is **rejected** — it rested on an unverified claim about epoch timing that the Python
source contradicts.

### 3.4 InitialMessage (PQXDH)

**Decided against carrying the full ML-DSA-65 public key** (~1,952 B **[VERIFY]**). Push payload limits
are ~4 KB **[VERIFY]**, and a ~3.6 KB initial message leaves no headroom.

```rust
struct InitialMessageV2 {
    version:        u16,
    device_id:      u32,
    handshake_seq:  u64,          // §6.3 — monotonic per (initiator, responder device)
    ik_x25519:      [u8; 32],     // full key: also the DH leg
    ik_mldsa_hash:  [u8; 32],     // SHA-256 of the ML-DSA-65 public key
    ek_x25519:      [u8; 32],     // ephemeral
    kem_ct:         Vec<u8>,      // ML-KEM-1024 ciphertext
    spk_id:         u32,
    opk_id:         Option<u32>,  // None = last-resort path
    confirm:        [u8; 32],
}
```

The responder resolves the full ML-DSA key from the directory and **verifies it against
`ik_mldsa_hash` before use**. This is why `IdentityId` (§3.5) hashes the ML-DSA key rather than
embedding it: the identity is computable from the wire on first contact.

### 3.5 Identity

**One definition.** Three tracks proposed three, which would have produced three different session keys.

```
IdentityId = SHA-256(
    "MLKEMBraid/identity/v2" ||
    ik_x25519                ||          // 32 bytes
    SHA-256(ik_mldsa65_pk)               // 32 bytes
)
```

The nested hash of the ML-DSA key is deliberate: it makes `IdentityId` computable from
`InitialMessageV2` alone.

### 3.6 Hybrid signature

```
HybridSignature = u16(version) || u16(suite) || u16(len_ed) || sig_xeddsa || u16(len_ml) || sig_mldsa
```

**Signed byte string** — preserves the Python framing, which was already injective and provably disjoint
from the raw signing path, and adds identity binding:

```
signed_msg = "MLKEMBraid/xeddsa/v2\x00" || u16(len(ctx)) || ctx || IdentityId || payload
```

**Verification rule:** both legs verify, or the signature is invalid. There is no "either" mode, no
suite negotiation, and no downgrade. `HybridSignature::verify` returns `Result<(), Unauthenticated>` and
has no variant that succeeds on one leg.

The raw (unframed) signing path continues to reject any message beginning with the domain tag, so the
framed and raw byte-spaces stay disjoint.

---

## 4. NORMATIVE: key schedule

### 4.1 The PQ invariant, made structural

```rust
/// No public constructor. Obtainable only from `MlKem::decapsulate` / `encapsulate`.
pub struct KemSharedSecret(Zeroizing<[u8; 32]>);

pub fn derive_sk(
    legs: DhLegs,              // by value, consumed
    kem_ss: KemSharedSecret,   // by value, consumed — NOT Option, NOT &[u8]
    info: &SkInfo,
) -> RootKey;
```

`derive_sk` is the **only** constructor of `RootKey`. Because `KemSharedSecret` has no public
constructor and is taken by value, **there is no way to write code that derives a root key without a
real ML-KEM output.** The structural track's `&Zeroizing<[u8;32]>` signature is **rejected**: a raw
32-byte reference lets a caller pass zeros, which would silently satisfy "the KEM leg is present".

```
SK = HKDF-SHA256(
    ikm  = F || DH1 || DH2 || DH3 [|| DH4] || KEM_SS,
    salt = 0x00 * 32,
    info = "MLKEMBraid/pqxdh/v2" || IdentityId_A || IdentityId_B,
    len  = 32)
```
`F = 0xFF * 32`. Identity ordering is initiator-then-responder on both sides. Binding both identities
into `info` is what defeats unknown-key-share.

### 4.2 Confirmation tag

```
k_cf    = HKDF-Expand(SK, "MLKEMBraid/pqxdh/confirm/v2", 32)
confirm = HMAC-SHA256(k_cf, canonical(InitialMessageV2 without `confirm`))
```

Deriving a separate MAC key is required. Using `SK` directly as the MAC key (as one track proposed)
violates key separation and places a 32-byte function of the root secret on the wire in cleartext.

**Security note, stated correctly:** `confirm` proves the sender computed `SK`. It does **not** prove
the sender is the claimed identity to a third party — an attacker who mints its own identity can produce
a valid `confirm` *under that identity*. The property that holds is that an attacker cannot forge a
`confirm` for a **victim's** identity without the victim's `ik_x25519` private key. One design track
stated this incorrectly; the incorrect form is what a reader would have taken as the security argument.

### 4.3 Prekey bundle

```rust
struct PrekeyBundleV2 {
    version:        u16,
    identity:       HybridIdentityPublic,   // x25519 (32 B) + ML-DSA-65 pk
    signed_prekey:  SignedPrekey,           // X25519 + HybridSignature
    pq_prekey:      SignedPqPrekey,         // ML-KEM-1024 ek + HybridSignature  (last-resort)
    one_time:       Option<OneTimePrekey>,  // X25519, unsigned (standard X3DH)
    enrolment:      EnrolmentProof,         // §6.2 — lets a peer verify scarcity locally
    expires_at_ms:  u64,
}
```

Every signature is verified **before** any key in the bundle is used. `pq_prekey` is signed and is the
last-resort PQ contribution: this is why OPK exhaustion is a bounded forward-secrecy degradation and
**not** a PQ downgrade.

### 4.4 Derived keys

| Key | Derivation | Notes |
|---|---|---|
| `RootKey` | `derive_sk(...)` | Only constructor |
| `K_frame_i2r` | `HKDF-Expand(SK, "MLKEMBraid/frame/i2r/v2", 32)` | Directional; no PCS (§3.3) |
| `K_frame_r2i` | `HKDF-Expand(SK, "MLKEMBraid/frame/r2i/v2", 32)` | Directional |
| `k_cf` | `HKDF-Expand(SK, "MLKEMBraid/pqxdh/confirm/v2", 32)` | |
| `session_id` | `HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)` | Replay defence (§6.3) |
| `K_chunk` | `HKDF-Expand(SK, "MLKEMBraid/erasure-chunk/v2", 32)` | Per-share integrity (M2+) |
| Chain/message keys | Standard Double Ratchet | §5.2 |

This table is the complete set of HKDF labels. Adding one requires editing this table.

---

## 5. NORMATIVE: cryptographic suite

### 5.1 One AEAD decision, all four use cases

Three tracks gave three mutually-rebutting answers (AES-GCM for hardware throughput vs.
ChaCha20-Poly1305 for software constant-time vs. XChaCha for at-rest). **Decision: the ChaCha family
everywhere.**

| Use case | Cipher | Nonce |
|---|---|---|
| Message keys (ratchet) | **XChaCha20-Poly1305** | 192-bit **random** |
| At-rest / vault | **XChaCha20-Poly1305** | 192-bit **random** |
| Circuit layers (M2+) | **XChaCha20-Poly1305** | 192-bit **random** |
| Transport framing | (TLS 1.3 via `rustls`) | — |

**Rationale, and why this is not a preference but a defect-elimination:**

1. **Constant-time everywhere with no hardware dependency.** ChaCha20 is constant-time in software by
   construction. AES-GCM's timing safety depends on hardware AES being present *and selected*; on a
   device or emulator without it, the software fallback is a timing risk.
2. **A 192-bit random nonce eliminates three separate defect classes at once.** Collision probability is
   negligible without any durable counter, which means:
   - The **vault-restart bug is impossible** (`vault.py:113` reconstructed a counter AEAD at 0 on every
     load, repeating nonces under a stable at-rest key). No counter, no restart-to-zero.
   - The **circuit sequence guard is deleted, not bounded.** The audit's M5 control existed only because
     a deterministic nonce needed a uniqueness guard; that guard then became a fail-open eviction
     primitive whose failure meant nonce reuse. Removing the deterministic nonce removes the control and
     its failure mode. This is tier 1 of §6.1 — eliminate the state rather than bound it.
   - The **counter-persistence contradiction disappears** (three tracks disagreed on lease-ahead vs.
     per-seal `fsync`; with random nonces there is nothing to persist).
3. **It resolves the ratchet-rollback defect (§5.3).**

The cost is throughput on hardware-AES devices. For a messenger's payload sizes this is not the
bottleneck; if measurement (§11.4) shows otherwise for bulk attachments, a separate bulk-transfer
profile may be added — but never for the ratchet path.

### 5.2 Ratchet-state rollback — the defect nobody designed for

**This is the most severe gap the design review found, and it is a genuinely new finding.**

The "one-shot key ⇒ nonce 0 is safe" argument is a **move-semantics** argument. It is valid only within
one process lifetime. A device restored from backup, a cloned VM image, or a crash after send-but-
before-commit **replays the same chain key**, re-derives the *same* `MessageKey`, and seals a *different*
plaintext under the same (key, nonce). Under AES-GCM this leaks the GHASH authentication key; under
ChaCha20-Poly1305 with a fixed nonce it leaks the Poly1305 key and the plaintext XOR. Both are
catastrophic. This is the `vault.py:113` failure class moved up one layer, and no track owned it.

**Mitigation, in depth:**

1. **Primary — random nonces make rollback non-catastrophic.** Under XChaCha20-Poly1305 with a fresh
   192-bit random nonce per seal, re-deriving the same key after a rollback produces a *different* nonce
   with overwhelming probability. Two ciphertexts under one key with **distinct** nonces is a safe
   operation. The catastrophe requires nonce *reuse*, which random nonces make negligible. This
   converts a protocol-breaking event into a benign duplicate.
2. **Secondary — detect the rewind and fail closed.** The store keeps a durable, monotonically
   increasing `send_epoch_counter` per session, advanced with a **lease-ahead** reservation (reserve N,
   `fsync` once, consume from the lease) so it costs one durable write per N messages rather than per
   message. On load, if the reconstructed ratchet index is **below** the persisted high-water mark, the
   session is marked `Rewound`: it refuses to send and requires a fresh handshake.
3. **Tertiary — hardware anti-rollback where available.** iOS Secure Enclave and Android StrongBox
   monotonic counters, where present, anchor the high-water mark. **[VERIFY]** availability and API
   shape on both platforms; this is an enhancement, not a dependency.

Defence 1 is the load-bearing one; 2 and 3 are detection and depth.

### 5.3 Primitive selection

All entries **[VERIFY]** for current version, API shape, maintenance and audit status during Phase 0.
Several structural guarantees in the design tracks were written against APIs nobody has run.

| Purpose | Crate | Notes |
|---|---|---|
| ML-KEM-1024 (FIPS 203) | `ml-kem` (RustCrypto) or `libcrux-ml-kem` | M1 uses **unmodified upstream**. `libcrux` is formally verified — prefer if the API suffices. |
| ML-DSA-65 (FIPS 204) | `ml-dsa` (RustCrypto) or `fips204` | **[VERIFY]** seed-based keygen (`KeyGen_internal(ξ)`) exists — the 32-byte-seed storage plan (§9) depends on it. |
| X25519 / Ed25519 arithmetic | `curve25519-dalek`, `x25519-dalek` | **[VERIFY]** `Scalar::from_canonical_bytes` returns `CtOption`, and `MontgomeryPoint::to_edwards` shape. |
| XEdDSA | Port from vendored Signal C | See §5.4 |
| AEAD | `chacha20poly1305` (XChaCha20Poly1305) | §5.1 |
| KDF / hash | `hkdf`, `sha2` | Drop the hand-rolled HKDF; keep the RFC 5869 KATs. |
| Constant-time | `subtle` | `ConstantTimeEq` on every authenticated comparison |
| Zeroization | `zeroize` | §8.2 |
| Canonical CBOR | `ciborium` + own deterministic profile | **[VERIFY]** determinism guarantees; the round-trip check (§3.2) is the backstop either way. |

### 5.4 XEdDSA — do not add rejections Signal does not perform

The port must be **byte-for-byte compatible with the vendored Signal C** on the existing KAT vectors.
One design track proposed adding a small-order-subgroup rejection to `verify`. That is an *addition* to
Signal's XEdDSA, not a restatement of it, and it will make adversarial-input cross-vectors disagree.
**Decision:** match Signal's behaviour exactly; if a stricter check is wanted, it goes in a separately
named function with its own tests, never silently inside `verify`.

---

## 6. Resolving the architectural finding

Audit §8.2: round 1 made bounded security caches **evict** on overflow (attacker floods → victim's entry
evicted → original attack restored). Round 2 made them **reject** (attacker floods → victim locked out).
Root cause: **every control was keyed on a free-to-mint identity**, and with a free principal *both*
overflow policies lose.

### 6.1 The resolution hierarchy (normative for every bounded resource)

1. **Unforgeable-small state.** Derive the decision from data that cannot grow with attacker input — a
   monotonic counter or high-water mark. Prefer this always: there is no overflow policy to get wrong.
2. **Scarce principal + partition.** If state must be remembered, key it on an *admission-controlled*
   identity and partition per principal, charging cost only after authentication.
3. **Fail closed.** Only when 1 and 2 are impossible, and only when the principal is scarce.

Never ship a control whose bypass is "send N cheap invalid messages."

### 6.2 Admission control — making the principal scarce

**M1 (ships first): attestation-backed + rate-limited enrolment.** This project **already has** a working
remote-attestation subsystem (`ml_kem_braid/attestation/`: SGX-DCAP and device-identity attestation over
an attested Noise channel). Reuse it. Enrolment runs over `attested_connect`, and the issued credential
is bound to the attested channel. Where attestation is unavailable, fall back to strongly rate-limited
enrolment. This is a genuine scarcity anchor available *now*, without a new service.

**M2 (privacy upgrade): blind-signed vouchers.** RFC 9474 RSABSSA blind signatures let the server issue
a scarce credential without learning which identity redeems it, carrying `epoch`, `tier`, and a
`nullifier` for double-spend detection.

**[VERIFY] before this becomes load-bearing:** RFC 9474 specifies both randomized and *deterministic*
variants; the unconditional-blindness property that the privacy argument depends on holds for the
randomized variants. Confirm against RFC 9474 Security Considerations, and confirm the maintenance status
of `blind-rsa-signatures`. Also unowned today: the issuer is **a new production service** with key
rotation, a nullifier ledger, and an availability chokepoint at registration. **M2 does not start until
that service has a design and an owner.**

**EnrolmentProof in the bundle — closing the client-side gap.** The design review correctly found that
client-side replay state was keyed on a `ScarcePrincipal` the *client cannot verify*: the responder in
PQXDH is a client, and it runs no admission control. **Decision:** `PrekeyBundleV2` carries an
`EnrolmentProof` (an issuer-signed statement over `IdentityId`, or in M2 a nullifier commitment), so a
responding client verifies scarcity **locally** before allocating per-peer state.

**Honest limitation:** in a future serverless/rendezvous mode there is no issuer, and therefore no
scarcity bound. This specification does not claim one for that mode. Stating this is required; a trait
bound that reads as a compile-time guarantee at a site where it is unverifiable is worse than no bound.

### 6.3 Replay defence — monotonic counters, not remembered sets

`InitialMessageV2.handshake_seq: u64`, **scoped per `(initiator IdentityId, responder device_id)`** —
one definition; three tracks had three.

Responder state, O(1) per known peer:

```rust
struct PeerFloor { last_seq: u64, window: u64 }   // 64-bit sliding window for reordering
```

- `seq <= last_seq - 64` → reject (too old).
- Within the window and already seen → reject.
- Otherwise accept, then advance.

**Why this cannot be flooded:** a stranger cannot cause allocation, because a `PeerFloor` is only created
for a peer whose `EnrolmentProof` verifies (§6.2). Storage is O(1) per *admitted* peer, not O(1) per
*message*. This is tier 1 of §6.1.

**First contact** is the genuinely hard case and needs its own defence, since there is no floor yet:
`session_id = HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)` is inserted with `insert_if_absent`. A replayed
`InitialMessage` derives the identical `session_id` and is rejected as a duplicate.

**A new handshake from a peer must not evict that peer's `session_id` record.** The design review found
this exact hole: one track's session table replaced a peer's row on re-handshake, which would let a
captured no-OPK `InitialMessage` replay cleanly afterwards. The `session_id` uniqueness set is retained
independently of session replacement, bounded per admitted peer, and pruned only by `expires_at`.

### 6.4 The complete bounded-resource table

Every row must be defensible against **both** the fail-open and fail-closed attacks.

| # | Resource | Keyed on | Scarce? | Policy | Why safe |
|---|---|---|---|---|---|
| 1 | Handshake replay floor | admitted peer | ✅ | **Unforgeable-small** | O(1)/peer; strangers cannot allocate |
| 2 | `session_id` uniqueness | admitted peer | ✅ | Bounded/peer, expiry-pruned | Not evicted by re-handshake (§6.3) |
| 3 | Skipped message keys | **session** | ✅ (session ⊂ admitted peer) | Fail closed | Bound is per authenticated session, so a stranger cannot consume it. Resolves the trait-bound violation: `MsgIndex` is not a principal, the *session* is. |
| 4 | One-time prekeys | account | ✅ | Atomic CAS, burn-once | §6.5 |
| 5 | Mailbox depth | (recipient, **sender**) | ✅ | Per-sender sub-quota | A flooder consumes only its own share; no shared cap to exhaust |
| 6 | Rate limits | admitted principal / proxy-aware IP | ✅ | Token bucket, per-principal | Scarcity makes the partition meaningful |
| 7 | Circuit nonce uniqueness | — | — | **Deleted** | Random 192-bit nonces (§5.1); the control no longer exists |
| 8 | Inbox dedupe (FFI) | **ratchet (epoch, index)** | ✅ | **Unforgeable-small** | Re-keyed off the growing `message_id` table one track proposed — that was an unbounded-in-time remembered set feeding a security decision, the exact pattern audit §8.4 forbids |
| 9 | AEAD single-use guard | — | — | **Deleted** | The Python guard grew one entry per message and hard-failed at 2²⁸. One-shot key types (§8.3) make it unnecessary. |

Rows 7, 8 and 9 are the point: **three controls are removed rather than tuned.** A control that does not
exist cannot be flooded.

### 6.5 One-time prekey lifecycle

The Python version failed three times: unauthenticated depletion; a TOCTOU double-lease; and a "reserve
floor" that reserved a prekey **served to nobody**, which is functionally identical to an empty pool.

1. **Claim is atomic** — one statement, no read-then-write:
   `UPDATE one_time_prekeys SET state='claimed', claimed_by=?, claimed_at=? WHERE id=(SELECT id FROM one_time_prekeys WHERE account=? AND state='available' LIMIT 1) RETURNING id, pub;`
2. **Burn-once.** An expired lease goes to a **terminal** state and is never re-served. Returning it to
   `available` re-serves a public key an initiator may already hold, which reinstates the very
   forward-secrecy break the atomic claim fixed. One design track shipped reclamation SQL citing the
   audit; that reading is **wrong** and this specification overrides it.
3. **Replenishment, not reservation.** The server signals a low-water mark; the client uploads more. No
   reserve floor.
4. **On genuine exhaustion:** serve the bundle without an OPK. This is a **bounded forward-secrecy
   degradation, not a PQ downgrade** — the signed last-resort ML-KEM prekey still supplies the PQ leg,
   and §4.1 makes it impossible to derive a session key without it. Fetches are rate-limited per §6.4
   row 6, which is meaningful now that the principal is scarce.

---

## 7. Crate architecture

Adopted from the core-architecture track (the most thoroughly reasoned), trimmed to the §2 scope. Names
are `mlkb-*`; the `braid-*` alternative is rejected purely to have one answer.

```
                        mlkb-ffi  (uniffi → Kotlin/Swift)
                            |
                          mlkb  (facade; the semver surface)
                            |
                      mlkb-session  (composition, concurrency, durability)
           _________________|__________________
          |          |            |            |
    mlkb-protocol  mlkb-store  mlkb-transport  mlkb-policy
     (no_std+alloc)  (std/IO)     (std/IO)      (admission)
          |
    ______|________________
   |          |            |
mlkb-wire  mlkb-crypto  mlkb-bounded
   |          |          (no_std, pure)
   |     mlkb-secrets
mlkb-codec  (no_std, pure)
(no_std+alloc)

mlkb-server    (std, axum — NOT in the mobile build)
mlkb-testkit   (dev-dependency ONLY: deterministic RNG/clock, KATs, fault injection)
mlkb-decentral (feature-gated, M2+)
```

Each crate owns exactly one choke point, so a second implementation has nowhere to live:

| Crate | Owns | Prevents |
|---|---|---|
| `mlkb-secrets` | Every secret byte; the only place `zeroize`/`subtle` are imported | Un-wiped keys; variable-time compares |
| `mlkb-bounded` | Every capacity-bounded structure; the only place an eviction can be written | §6 oscillation |
| `mlkb-codec` | The single canonical encoder | M8; the duplicate-codec class |
| `mlkb-crypto` | Every algorithm and nonce choice | M4, M5, the vault nonce bug |
| `mlkb-wire` | Every wire type and its exact-length parser | M1, L7, parser DoS |
| `mlkb-protocol` | Every state transition and key schedule; sans-io, no clock/RNG/global | M1, M2, §4 invariants |
| `mlkb-store` | Durability, atomic CAS, rollback detection | H2, §5.2 |
| `mlkb-session` | The **only** public constructor path | "opt-in security shipped inert" |

`mlkb-testkit` being a dev-dependency is the structural fix for
`client/anonymous_transport.py:30-35`, which shipped hardcoded development layer keys in an importable
production class.

---

## 8. Type-level mechanisms

### 8.1 Classify / apply — state cannot mutate before authentication

The Python state machine mutated on unauthenticated fields and silently no-op'd on unexpected input.

```rust
impl Session<Established> {
    /// Pure. Borrows. Cannot mutate.
    fn classify(&self, frame: &Frame) -> Result<Plan, Unauthenticated>;
    /// The ONLY mutator, and a `Plan` is only obtainable from `classify`.
    fn apply(self, plan: Plan) -> (Session<Established>, Vec<Event>);
}
```

Because `apply` consumes `self` and `Plan` has no public constructor, "authenticate, then mutate" is a
*shape* rather than a discipline. Illegal transitions fail to compile.

### 8.2 Secrets

```rust
pub struct RootKey(Zeroizing<[u8; 32]>);
pub struct ChainKey(Zeroizing<[u8; 32]>);
pub struct MessageKey(Zeroizing<[u8; 32]>);
pub struct FrameKey(Zeroizing<[u8; 32]>);   // distinct types: cannot be confused

impl ChainKey {
    /// Consumes the old key — a stale chain key cannot be reused after ratcheting.
    pub fn step(self) -> (ChainKey, MessageKey);
}
```

**Honest limitation:** `Zeroizing` wipes on drop, but the bytes exist in an intermediate buffer (an HKDF
output) before the move into the wrapper, and optimiser spills are not controlled. Zeroization reduces
residency; it does not eliminate it.

### 8.3 One-shot AEAD keys

```rust
impl MessageKey {
    /// Consumes the key. A second seal under the same key is a compile error.
    pub fn seal(self, pt: &[u8], aad: Aad<'_>) -> Ciphertext;
}
```

`Aad` is constructible **only** from a canonical encoding (`Aad<'a>(&'a CanonicalBytes)`), which forbids
the ad-hoc concatenation of audit L6. The crypto track's `seal(self, pt, ad: &[u8])` taking a raw slice
is **rejected** — it reopens exactly what `Aad` exists to close.

Note this makes nonce reuse impossible *within a process*; §5.2 handles rollback across process
lifetimes.

### 8.4 Errors — no oracles, no conflation

```rust
pub enum ProtocolError {
    Unauthenticated,          // ZERO fields. Every integrity failure collapses here.
    Malformed,
    ReplayDetected,
    Rewound,
    // ...
}
pub enum Progress<T> { Complete(T), NeedMore }   // incompleteness is NOT an error
```

`Progress<T>` removes the Python footgun of conflating "authentication failed" with "need more data".
`Unauthenticated` carrying no payload is what prevents an oracle from crossing the FFI boundary.

*(The design track proposed enforcing this with a `size_of` test. That does not work: `size_of` on an
enum reflects the largest variant, so adding a field to `Unauthenticated` would often not change it. Use
a `#[non_exhaustive]`-free explicit match plus a review checklist item instead.)*

### 8.5 Concurrency

`Session` is `Send + !Sync`, held behind `std::sync::Mutex` in `mlkb-session`. **`panic = "abort"` is set
in release**, so mutex poisoning never occurs — the design track's rationale for choosing `std::sync::Mutex`
over `parking_lot` (poisoning as a safety feature) is therefore **void**, and the choice stands only on
having no extra dependency. A poisoned lock must **never** be mapped to `AuthenticationFailed`; it is a
process fault (`ProtocolError::Internal`).

---

## 9. Storage and durability

**SQLCipher via `rusqlite`** (or `sqlx`) **[VERIFY]** for mobile packaging. Requirements:

1. **Atomic CAS** for the OPK claim (§6.5) — a single statement, not read-then-write.
2. **Durability barrier:** a frame is not released to the network before the state that produced it is
   durable. In the FFI model (§10) this is the enclosing transaction; the `Uncommitted<T>` type exists
   inside `mlkb-session` for the Rust-native API.
3. **Rollback detection:** the `send_epoch_counter` high-water mark (§5.2), lease-ahead reserved.
4. **Cross-process locking** — an iOS Notification Service Extension and the app can touch the ratchet
   store simultaneously. This is a classic messenger corruption bug. WAL mode plus an explicit advisory
   lock; **[VERIFY]** behaviour under iOS Data Protection when the device is locked.
5. **ML-DSA private key storage:** store the **32-byte FIPS-204 seed ξ** and expand on load, not the
   ~4 KB expanded secret key — contingent on **[VERIFY]** that the chosen crate exposes seed-based
   keygen. If it does not, store the expanded key and note the increased sensitive-blob size.

Ordering rule: **authenticate → commit replay/nonce state → release output.** One design track's
pseudocode enforced the replay floor *before* AEAD verification; the enclosing transaction made it
recoverable, but it inverts §8.1 and must not be written that way.

---

## 10. FFI and mobile

### 10.1 Mechanism — UniFFI

**Decision: UniFFI** (Mozilla). It generates Kotlin and Swift from one Rust definition, expresses
`Result`/enums/records natively, and — decisively — supports **opaque object handles**, so key material
never crosses into JVM/Swift heaps. Rejected: hand-written C ABI + JNI + `swift-bridge` (three surfaces
to keep in sync — the duplicated-definition class this whole document exists to prevent).

**[VERIFY]** UniFFI's current async support and callback-interface shape against the target versions.

### 10.2 Secrets never cross the boundary

All key material stays inside Rust behind opaque handles. JVM and Swift memory cannot be zeroized and may
be relocated by GC/ARC, so a key copied there is unrecoverable. The FFI exposes handles and ciphertext;
never a private key, never a chain key.

### 10.3 Surface (illustrative; §3–5 are normative)

```
namespace mlkb {
  [Throws=MlkbError] Client client_open(string db_path, Voucher voucher);
};
interface Client {
  [Throws=MlkbError] void publish_prekeys(u32 count);
  [Throws=MlkbError] SessionHandle start_session(PeerId peer);
  [Throws=MlkbError] bytes encrypt(SessionHandle s, bytes plaintext);
  [Throws=MlkbError] ReceiveResult receive(bytes envelope);
};
```

`Voucher` **must be the §6.2 credential** — an issuer-signed/blind-signed value with a nullifier — not a
three-variant enum with no signature. An enum with no `None` variant is not scarcity; that design would
have left the entire bounded-resource resolution unenforced at the only boundary that ships.

Session state lives inside the client; there is no `poll_transmit` at the FFI boundary. The durability
barrier is therefore the store transaction (§9.2), not a Rust-side `Uncommitted<T>`. Stating which model
applies at which boundary resolves the core-arch/FFI contradiction.

### 10.4 Platform key storage

- **iOS:** Keychain with `kSecAttrAccessibleAfterFirstUnlock` for the DB wrapping key (an NSE must
  decrypt while the device is locked-but-unlocked-once); Secure Enclave holds a **wrapping** key only —
  it cannot perform X25519 or ML-KEM for us, so ratchet state stays in software under an encrypted store.
- **Android:** Keystore/StrongBox for the wrapping key; `setUserAuthenticationRequired` is **not** used
  for the messaging key, or background decryption breaks.

### 10.5 Background and push

Push carries a **wake signal plus an identifier, not the ciphertext** — the fetch-on-wake model. This
sidesteps the payload-size limits that would otherwise bind against multi-KB PQ material.

**[VERIFY] all of these before they become load-bearing** (they are recollections, and a design decision
rests on each): NSE memory cap (~24 MB), NSE wall clock (~30 s), FCM `onMessageReceived` budget
(~10–20 s), APNs (~4 KB) / FCM (~4 KB) payload limits, Android 16 KB page-size enforcement date and
target-SDK threshold.

### 10.6 Build

- **Android:** `cargo-ndk`; ABIs `arm64-v8a`, `armeabi-v7a`, `x86_64`; `.aar`; **16 KB page-size
  alignment [VERIFY]**.
- **iOS:** `XCFramework` with device + simulator slices; SwiftPM.
- Binary size: ML-KEM + ML-DSA are not small; **[VERIFY]** by measurement, and treat size as a gate.

---

## 11. CI gates

1. **FIPS KATs** (ACVP) for ML-KEM and ML-DSA; **RFC 5869** KATs for HKDF; **Signal XEdDSA** vectors,
   byte-for-byte (§5.4).
2. **Canonical-encoding round-trip + float rejection**, property-tested for injectivity.
3. **Fuzz every parser** (`cargo-fuzz`): `Frame`, `InitialMessageV2`, `PrekeyBundleV2`, CBOR decoder.
4. **Rollback tests:** restore-from-snapshot must be *detected* (`Rewound`) and must not produce a
   nonce-reuse (§5.2).
5. **Flood tests, mandatory for every row of §6.4:** fill/overflow the resource, then assert the
   *original* attack is still rejected **and** an honest peer is still served. Both directions — this is
   the test the Python rounds lacked, and its absence is why the oscillation went two rounds.
6. **`cargo-deny`** enforcing the crate DAG: `mlkb-protocol` must not depend on `std`, a clock, an RNG,
   or `mlkb-store`; `mlkb-transport` must not depend on any serialization crate.
   *(Note: `cargo check --target thumbv7em-none-eabi` proves no-`std`; it does **not** prove absence of
   global mutable state — `static mut`, atomics and spin-locks all compile. Do not claim otherwise.)*
7. **No `unwrap`/`expect`/`panic`/indexing in `mlkb-crypto`, `mlkb-codec`, `mlkb-wire`** — and the lint
   policy must be tested against the code, not merely declared. (One design track's own sample code
   violated the lints it mandated.)

### 11.4 Phase 0 — the verification spike that gates the schedule

**No protocol code until these are answered**, because four structural guarantees are written against
APIs nobody in this project has run:

1. Does an upstream ML-KEM crate expose **deterministic, `m`-injectable** encapsulation over raw `ek`
   bytes? (Required for the differential oracle that would gate any future vendored K-PKE fork.)
2. Does the chosen ML-DSA crate expose **seed-based keygen** and size constants? (The §9 storage plan
   depends on it.)
3. Current `curve25519-dalek` shapes for `from_canonical_bytes` / `to_edwards`.
4. `blind-rsa-signatures` status and the RFC 9474 variant question (§6.2) — **only needed for M2**.
5. Measure: hybrid bundle fetch + 2×XEdDSA + 2×ML-DSA verification cost on a mid-range device; XChaCha
   vs. AES-GCM throughput on target aarch64; binary size.

---

## 12. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **ML-KEM K-PKE split needs unexposed internals** | **Highest** | M1 ships on unmodified upstream ML-KEM; the split is deferred behind an equivalence gate and confined to SCKA, never PQXDH (§2) |
| Ratchet-state rollback | High | Random nonces make it non-catastrophic; detection + fail-closed (§5.2) |
| Hybrid bundles ~5.8× larger | Medium | Fetch-on-wake; measure in Phase 0 |
| Admission control becomes a deanonymization vector | Medium | M1 reuses attestation; M2 blind signatures — but **[VERIFY]** the blindness variant |
| Voucher issuer is an unowned new service | Medium | M2 does not start without a design and an owner |
| Cross-process store corruption (NSE + app) | Medium | WAL + advisory lock; **[VERIFY]** under Data Protection |
| Scope | High | §2 scope cut is normative |

### Open questions requiring a human decision

1. **Serverless mode has no scarcity anchor** (§6.2). Accept the weaker bound, or drop the mode?
2. **No migration path from v1.** Confirmed acceptable?
3. **M2 voucher issuer** — who builds and operates it?
4. Is the deferred Braid SCKA split still a product requirement, given M1 delivers PQ security without
   it?
