# ML-KEM-Braid Iteration 2 — M1 Normative Resolutions

**Status:** Normative. Amends `docs/specs/2026-07-31-rust-rewrite-spec.md` (the "parent spec").
**Date:** 2026-08-01
**Relationship to the parent:** additive. Where this document and the parent disagree, **this document
wins**, and every such disagreement is listed explicitly in §J — nothing is changed silently.

## 0. Why this document exists

The parent spec was reviewed for implementability and for parity with the Python implementation it
replaces, and a Phase 0 API spike compiled and ran against every crate it names. Three things came out:

1. The parent is **normative about the things it defines** and silent about a number of things an
   implementer cannot proceed without — most importantly, **M1 has no source of Double Ratchet epoch
   keys**, because the parent defers the Braid SCKA (§2) and the Python ratchet's only asymmetric input
   *is* the SCKA epoch key (`core/double_ratchet.py:1-25`).
2. Three of the parent's structural guarantees were written against **APIs that do not behave as
   assumed**. These are not opinions; they were compiled and executed (§H).
3. Several constants and registries that CI gates are supposed to test do not exist.

Rule zero from the parent applies unchanged: **every wire byte, every KDF label, every key type has
exactly one normative definition.** This document is where the ones the parent left open now live. No
crate, no code comment, and no design note may restate them.

---

## A. Frame — the wire envelope

### A.1 The frame is NOT CBOR

The parent's §3.2 makes deterministic CBOR the canonical encoding "for everything", while §3.3 describes
`payload` as "u32 length-prefixed on the wire". Those are two different encodings, and under the CBOR
reading the MAC preimage would be a *different* byte string from the transmitted bytes, forcing every
implementer to invent a reconstruction step.

**Resolution.** The frame envelope is a **fixed big-endian layout and is the sole exception to §3.2.**
Deterministic CBOR governs *payload-level* structures only (`InitialMessageV2`, `PrekeyBundleV2`,
`RatchetHeader`, `EnrolmentProof`).

```
Frame (on the wire, big-endian, exactly this order, no padding):

  offset  size  field
       0     2  version      u16   == PROTOCOL_VERSION (0x0200)
       2     8  epoch        u64
      10     1  msg_type     u8
      11     4  payload_len  u32   <= MAX_FRAME_PAYLOAD
      15   var  payload
   15+n    32  frame_mac
```

`FRAME_HEADER_LEN = 15`. Total frame length is exactly `15 + payload_len + 32`.

This makes the transmitted bytes byte-identical to the parent's §3.3 MAC input, minus the 19-byte label
prefix, with the tag appended. Verification is therefore one HMAC pass over
`b"MLKEMBraid/frame/v2" || wire[0 .. 15 + payload_len]` — no re-encode, no reconstruction, no allocation.
The parent's §3.3 MAC definition is unchanged and remains normative; this section only pins the layout it
was already implicitly describing.

**Decoder rules (all hard rejects, `ProtocolError::Malformed` unless stated):**

1. `version != PROTOCOL_VERSION` → reject.
2. `payload_len > MAX_FRAME_PAYLOAD` → reject **before allocating**. The length prefix is never trusted
   as an allocation hint.
3. Buffer shorter than `15 + payload_len + 32` → `Progress::NeedMore`, not an error (parent §8.4).
4. Buffer longer than `15 + payload_len + 32` → reject (parent §3.3, audit L7: no trailing bytes).
5. `frame_mac` verified with `subtle::ConstantTimeEq` → on failure `ProtocolError::Unauthenticated`.
6. **`msg_type` is validated only after the MAC verifies.** Dispatching on an unauthenticated type byte
   would contradict parent §8.1.
7. A payload-free `msg_type` declaring `payload_len != 0` → reject (preserves `protocol/messages.py:203-207`).

### A.2 `msg_type` registry

Closed registry. Unknown values are a hard reject, so no future extension can become a downgrade surface.

| Value | Name | Payload | Meaning |
|---|---|---|---|
| `0x01` | `INITIAL` | `canonical(InitialMessageV2)` | PQXDH handshake, initiator → responder |
| `0x02` | `MESSAGE` | `canonical(RatchetMessage)` | Application message (§D) |
| `0x03` | `ACK` | none (`payload_len == 0`) | Keepalive / delivery ack; carries no key material |
| `0x04`–`0xFF` | — | — | **Reserved. Hard reject.** |

The Python Braid types (`HDR`, `EK`, `CT1_ACK`, `EK_CT1_ACK` — `protocol/messages.py:60-86`) are **not**
in the M1 registry. They belong to the SCKA layer, which is deferred; they will be assigned from the
reserved range when the Braid lands, and assigning them now would freeze a layout that does not exist yet.

### A.3 `epoch` advance rule

In M1, `Frame.epoch` is the **sending chain's DH-ratchet generation** (§D.2), i.e. it increments by one
each time the sender performs a DH ratchet step, and is constant across every message sent within one
sending chain. It is not a free-running counter and a receiver never advances its own state from a peer's
`epoch` field alone — parent §8.1 requires authentication first, and §D.3 defines the only state
transitions.

`epoch` is retained in M1 (rather than deleted and reintroduced with the SCKA) because it is inside the
MAC preimage; removing and re-adding it would be a wire break between M1 and M2.

---

## B. The canonical encoding profile

### B.1 ciborium cannot produce it — we write our own

**Empirical finding (§H, Q8), not a preference.** `ciborium 0.2.2` gives definite lengths and
shortest-form integers, but:

- it **does not sort map keys** (structs serialize in field-declaration order: `{zeta, alpha, m}` →
  `a3 647a657461 01 65616c706861 02 616d 03`), and exposes no hook to make it;
- it **cannot be told to reject floats**, and silently narrows `f64 1.0` to the half-float `f9 3c00`;
- its decoder **accepts indefinite-length input** (`9f010203ff` decodes fine);
- serde `Vec<u8>` encodes as a **CBOR array of integers**, not a byte string, which would roughly double
  every 1568-byte ML-KEM field on the wire.

Every one of those defeats a property the parent spec depends on. Parent §3.2 requires an encoder that
*enforces* determinism and a decoder that *rejects* non-canonical input; a library that silently
normalizes is worse than none.

**Resolution: `mlkb-codec` contains a hand-written deterministic CBOR writer and a strict reader. It
depends on no serialization crate at all.** `ciborium` is removed from the dependency graph, and
`deny.toml` denies it alongside `serde_json`, `serde_cbor` and `rmp-serde`. This *strengthens* parent
§11 gate 6 (`mlkb-transport` must not depend on any serialization crate) into a workspace-wide rule with
exactly one exception, which is the crate whose entire job it is.

The subset we implement is small and closed — that is the point:

| CBOR major type | Supported | Notes |
|---|---|---|
| 0 unsigned int | yes | shortest form only |
| 1 negative int | **no** | no field in any structure needs one; encoding one is an error |
| 2 byte string | yes | definite length only |
| 3 text string | yes | definite length, valid UTF-8, map keys only are additionally sorted |
| 4 array | yes | definite length only |
| 5 map | yes | definite length, text keys only, sorted per B.2 |
| 6 tag | **no** | reject on decode |
| 7 float / simple | **no** | **`false`/`true`/`null` also rejected** — see B.3 |

### B.2 Map key ordering

**RFC 8949 §4.2.1 bytewise lexicographic ordering of the fully encoded key, head byte included.** For
text keys this means shorter keys sort before longer ones (the head byte encodes the length), which is
*not* plain string ordering. Duplicate keys are a hard reject.

### B.3 Absence, `Option`, and the "without `confirm`" rule

**One rule covers all three cases the reviews flagged:**

> An absent value means **the map key is omitted entirely**. CBOR `null` is never emitted, and is
> rejected on decode.

Therefore:

- `opk_id: None` → the `"opk_id"` key does not appear in the map.
- `canonical(InitialMessageV2 without confirm)` (parent §4.2) → the map with the `"confirm"` key removed.
  This keeps the confirmation preimage independent of `confirm`'s own width.
- There is no encoding a verifier could mistake for "present but empty".

### B.4 The round-trip check

Parent §3.2 rule 5 is retained and is the backstop for the whole profile: the decoder re-encodes what it
decoded and requires byte equality before accepting. Because our encoder is canonical by construction,
this makes non-canonical input unrepresentable rather than normalized.

### B.5 Integers and timestamps

All integers are CBOR unsigned, shortest form. All timestamps are `u64` **milliseconds since the Unix
epoch** (parent §3.2 rule 2). There are no floats anywhere, in any structure, signed or not.

---

## C. PQXDH

### C.1 The DH legs — pinned

The parent's §4.1 names `DH1..DH4` in the `ikm` but never defines them, which is enough on its own for
two implementations to derive different session keys. Pinned here, verbatim from the Python
implementation (`pqxdh/pqxdh.py:18-24`, `:406-413`), with **A = initiator, B = responder**:

```
DH1 = X25519(IK_A_priv,  SPK_B)
DH2 = X25519(EK_A_priv,  IK_B)
DH3 = X25519(EK_A_priv,  SPK_B)
DH4 = X25519(EK_A_priv,  OPK_B)     // present iff InitialMessageV2.opk_id.is_some()
KEM_SS = ML-KEM-1024.Decaps(pq_prekey_priv, kem_ct)     // always present, always last
```

```
ikm = F || DH1 || DH2 || DH3 [|| DH4] || KEM_SS       where F = 0xFF * 32
```

- Every component is exactly 32 bytes; the concatenation is unambiguous without length prefixes because
  every element is fixed-width.
- `F` is prepended exactly once.
- **DH4 is omitted from the `ikm` entirely when no OPK was used — it is never zero-filled.** Its presence
  is determined solely by `InitialMessageV2.opk_id`, which is inside the MAC preimage and inside the
  `confirm` preimage, so it cannot be flipped by an attacker.
- `DhLegs` (parent §4.1) is therefore an ordered 3-or-4 element value, consumed by value, whose
  arity is fixed at construction from `opk_id`.

The `SK` derivation itself (salt, info, identity ordering) is unchanged from parent §4.1.

### C.2 X25519 must fail closed — empirical

**`x25519-dalek 3.0.0` does not reject low-order or contributory peer keys.**
`StaticSecret::diffie_hellman(&PublicKey::from([0u8; 32]))` returns the **all-zero shared secret** and
merely sets `SharedSecret::was_contributory() == false`; the free `x25519()` function checks nothing at
all (§H, Q5). A peer that sends an identity or prekey of `[0u8; 32]` would drive a DH leg to a constant
the attacker knows.

**Normative:** every DH site in `mlkb-crypto` rejects, before the output is used:

1. `!shared.was_contributory()` → `ProtocolError::Unauthenticated`; **and**
2. the peer's public key decoded to an Edwards point fails `is_torsion_free()`, or is small-order →
   `ProtocolError::Malformed`.

There is exactly one DH function in `mlkb-crypto` and it always performs both checks. No caller may
reach the raw `x25519-dalek` API; it is not re-exported.

The crate must be built with `features = ["static_secrets"]` — `StaticSecret` is **not** in
`x25519-dalek 3.0.0`'s default feature set, so long-term identity keys are impossible without it (§H, Q5).

### C.3 `InitialMessageV2` — amended

Two fields change from parent §3.4. Both are unfixable later.

```rust
struct InitialMessageV2 {
    version:        u16,          // == 0x0200
    to_device_id:   u32,          // RENAMED (was `device_id`)
    handshake_seq:  u64,
    ik_x25519:      [u8; 32],
    ik_mldsa_hash:  [u8; 32],     // SHA-256 of the ML-DSA-65 public key
    ek_x25519:      [u8; 32],
    kem_ct:         Vec<u8>,      // ML-KEM-1024 ciphertext, exactly 1568 bytes
    spk_id:         u32,
    pqspk_id:       u32,          // ADDED
    opk_id:         Option<u32>,
    confirm:        [u8; 32],
}
```

**`pqspk_id` (added).** The parent carried `spk_id` and `opk_id` but no identifier for the ML-KEM prekey
that `kem_ct` was encapsulated to, so a responder holding more than one PQ prekey — which it must, during
any rotation — cannot select the decapsulation key. Four bytes now; a wire break later. `SignedPqPrekey`
gains a matching `id: u32`. An unknown `pqspk_id`, or one whose private key has been erased, is
`ProtocolError::Malformed`.

**`to_device_id` (renamed).** The parent's `device_id` did not say whose. Parent §6.3 needs the
*responder's* device to key the replay floor, and the responder must be able to compute that key from the
message alone. `to_device_id` is the responder device the handshake is addressed to, taken from the
directory entry the initiator fetched. The initiator's own device is deliberately not on the wire — it is
bound through `IdentityId` and the DH legs. The field is already MAC-covered, so no extra binding is
needed.

**CBOR map keys** (fixed, sorted per B.2): `"c"` confirm, `"ct"` kem_ct, `"ek"` ek_x25519, `"ih"`
ik_mldsa_hash, `"ik"` ik_x25519, `"oid"` opk_id, `"pid"` pqspk_id, `"sid"` spk_id, `"sq"` handshake_seq,
`"td"` to_device_id, `"v"` version. Short keys are used deliberately: they are inside a ~1.7 KB structure
that is pushed to mobile devices, and the names are fixed forever by this table anyway.

### C.4 Replay window — corrected predicate

The parent's §6.3 predicate `seq <= last_seq - 64` **underflows for every peer whose `last_seq < 64`**,
which is every freshly admitted peer, and `PeerFloor.window` has no defined semantics or initial state.

**Normative:**

- Reject if `seq + 64 <= last_seq` (no underflow, same intent).
- Bit *i* of `window` means `last_seq - i` has been seen. Bit 0 is always 1.
- On `seq > last_seq`: `window = if seq - last_seq >= 64 { 1 } else { (window << (seq - last_seq)) | 1 }`,
  then `last_seq = seq`.
- On `seq <= last_seq` within the window: reject if the bit is set, else set it and accept.
- Initial state on a peer's first accepted handshake: `last_seq = seq`, `window = 1`.

---

## D. The M1 Double Ratchet — the hybrid DH + KEM ratchet

**This resolves the highest-severity gap.** Parent §2 defers the Braid SCKA; parent §5.2 says only
"Standard Double Ratchet". But in this protocol the SCKA epoch key *is* the ratchet's asymmetric input
(`core/double_ratchet.py:1-25`), so deferring the Braid leaves M1 with **no asymmetric ratchet driver at
all** — an implementer would either ship a ratchet with no post-compromise security, or invent one.

### D.1 The choice, and why

A classic Signal X25519 DH ratchet would be the smallest change, but its post-compromise security would
be **classical-only**: an adversary who compromises a device and then holds the traffic recovers nothing
today, but a CRQC breaks every subsequent X25519 ratchet step retroactively. The parent's threat model
lists a CRQC explicitly, and post-quantum security is a hard project requirement — so a classically-driven
ratchet is not acceptable, even in M1.

**Normative: M1 runs a hybrid continuous-key-agreement ratchet.** Each DH ratchet step contributes
*both* a fresh X25519 DH output *and* a fresh ML-KEM-1024 encapsulation, and both are mixed into the root
step. Security is the strictly stronger of the two: breaking the chain requires breaking X25519 **and**
ML-KEM.

This is what the Braid SCKA was always for. The Braid's contribution is **bandwidth, not security**: it
splits the 1568-byte ML-KEM ciphertext across epochs so no single message carries it. M1 pays the full
cost on each ratchet step; M2's Braid amortizes it. Stating it this way makes the deferral honest — M1
loses an *efficiency* property, not a *security* property — and confines the vendored-K-PKE risk to
exactly where the parent §2 wanted it.

### D.2 State and the ratchet step

Per-session state (in addition to parent §8.2's key types):

```
RK                  root key
CK_send, CK_recv    chain keys (Option)
Ns, Nr              message index in the current sending / receiving chain
PN                  number of messages in the PREVIOUS sending chain
epoch               sending-chain generation (== Frame.epoch, §A.3)
dh_self             X25519 keypair (ours, current)
dh_remote           X25519 public (peer's, current)
kem_self            ML-KEM-1024 keypair (ours, current — peers encapsulate to this)
kem_remote          ML-KEM-1024 encapsulation key (peer's, current)
skipped             bounded map (epoch, index) -> MessageKey
```

**Root step** — performed on every DH ratchet, in both directions:

```
dh_out  = X25519(dh_self_priv, dh_remote)          // both fail-closed checks of §C.2 apply
kem_ss  = ML-KEM-1024 encapsulation result          // Encaps(kem_remote) when sending,
                                                    // Decaps(kem_self_priv, kem_ct) when receiving
(RK', CK) = HKDF-SHA256(
    ikm  = dh_out || kem_ss,        // exactly 64 bytes
    salt = RK,
    info = "MLKEMBraid/ratchet/root/v2",
    len  = 64)                       // split 32 || 32
```

`KemSharedSecret` is consumed by value here exactly as in parent §4.1, so the PQ leg is structurally
impossible to omit from a ratchet step — the same invariant, at the same strength, one layer up.

**Chain step** — unchanged from Signal and from the Python implementation
(`core/double_ratchet.py:159-169`):

```
MK  = HMAC-SHA256(CK, 0x01)
CK' = HMAC-SHA256(CK, 0x02)
```

`ChainKey::step(self)` consumes the old chain key (parent §8.2), so a stale chain key cannot be reused.

**Initialization.** `RK_0 = SK` from PQXDH (matching `double_ratchet.py:197-207`, which seeds the root key
from the PQXDH SK so the first ratchet mixes both). The responder's `dh_self` is its signed prekey pair
and its `kem_self` is the PQ prekey pair the initiator encapsulated to; the initiator performs the first
DH ratchet step immediately on its first send. The **directional split** of the Python implementation
(`CK_AtoB` / `CK_BtoA`, `double_ratchet.py:146-156`) is **not** carried over — it existed because the SCKA
hands both parties the *same* epoch key, which is symmetric. A DH/KEM ratchet is asymmetric by
construction, so the two directions already have distinct chains and the split would be redundant state.

### D.3 `RatchetMessage` — the application message

The parent defines no application message at all: no ratchet header, no envelope, no AEAD associated
data. Normative here, carried as the payload of a `0x02` frame:

```
RatchetMessage (deterministic CBOR map, keys sorted per B.2)

  "ct"  bstr        AEAD ciphertext with the 16-byte Poly1305 tag appended
  "dh"  bstr(32)    sender's current X25519 ratchet public key
  "ek"  bstr(1568)  sender's current ML-KEM-1024 encapsulation key   } present iff this
  "kc"  bstr(1568)  ML-KEM ciphertext to the receiver's current ek   } message opens a
                                                                      } new sending chain
  "n"   uint        message index within the current sending chain
  "nc"  bstr(24)    XChaCha20-Poly1305 nonce (§5.1: 192-bit random)
  "pn"  uint        number of messages in the sender's previous sending chain
```

`"ek"` and `"kc"` are present **together or not at all**, and exactly on the first message of each new
sending chain — i.e. when `n == 0`. Their presence is what tells the receiver to perform a root step
(§D.2) before the chain step. A message with `n != 0` carrying either field is `ProtocolError::Malformed`,
as is `n == 0` carrying neither. This makes the ratchet-step signal a property of the parser rather than
of the state machine.

`"pn"` is what lets a receiver derive the message keys it skipped in the sender's previous chain before
ratcheting forward, exactly as in Signal.

**AEAD associated data.** The parent's `Aad` type (§8.3) was guarding an undefined value. Normative
preimage, and the only one:

```
AAD = canonical({
    "e":  uint         frame epoch,
    "h":  bstr         canonical(RatchetMessage without "ct"),
    "r":  bstr(32)     IdentityId of the recipient,
    "s":  bstr(32)     IdentityId of the sender,
    "v":  uint         PROTOCOL_VERSION,
})
```

This is strictly stronger than the Python binding (`double_ratchet.py:464-479`), which bound only the
`(epoch, index)` header and a caller-supplied opaque blob: binding both `IdentityId`s makes a ciphertext
non-transplantable between sessions, and binding the whole header (minus the ciphertext itself) makes
every ratchet field — including `dh`, `ek`, `kc` and the nonce — authenticated by the AEAD in addition to
the frame MAC. Because it is produced by `mlkb-codec`, it satisfies `Aad<'a>(&'a CanonicalBytes)` by
construction and the ad-hoc concatenation of audit L6 is unrepresentable.

### D.4 Skipped keys — fail closed, do not evict

Carried over from the Python implementation's post-audit behaviour (`double_ratchet.py:32-48`, `:377-390`),
which got this right and is the parent's §6.4 row 3:

- `MAX_SKIP_PER_CHAIN` bounds a single catch-up; `MAX_SKIPPED_KEYS_PER_SESSION` bounds the store.
- **Both bounds are checked before any key material is derived and before any AEAD is attempted.** The
  ordering is load-bearing: it is what stops a forged message from advancing state.
- On overflow the **new** message is refused (`ProtocolError::SkippedKeyLimit`). A cached key is **never**
  evicted — evicting one silently and permanently destroys an authentic delayed message.
- The bound is per authenticated **session**, which is inside an admitted peer, so a stranger cannot
  consume it (parent §6.4 row 3).
- Chains for `RETAINED_RECV_CHAINS` previous generations are retained for reordering; older skipped keys
  are pruned on each ratchet.

---

## E. Signatures

### E.1 `HybridSignature` — registry and exact lengths

Parent §3.6 leaves `version` and `suite` unassigned and does not constrain the length prefixes.

```
HybridSignature = u16(version) || u16(suite) || u16(len_ed) || sig_xeddsa || u16(len_ml) || sig_mldsa
```

- `version = 0x0200`. `suite = 0x0001`, meaning exactly **(XEd25519, ML-DSA-65)**. Any other value of
  either field is `ProtocolError::Malformed` **before any cryptographic work**.
- `len_ed` **must equal 64** and `len_ml` **must equal 3309** (§H, Q3). The prefixes are checked against
  the suite's fixed sizes, not trusted.
- Trailing bytes are rejected.
- Both legs verify or the signature is invalid (parent §3.6). `verify` returns
  `Result<(), Unauthenticated>` and has no variant that succeeds on one leg.

A one-value registry costs nothing and makes the no-downgrade claim a property of the parser.

### E.2 Signature context registry

Parent §3.6 defines the signed byte string but never the `ctx` values, which permits cross-type signature
substitution — a signed prekey lifted into a PQ-prekey slot. Closed set, same discipline as parent §4.4:

| `ctx` (exact ASCII) | Signs |
|---|---|
| `MLKEMBraid/ctx/spk/v2` | the X25519 signed prekey in `PrekeyBundleV2` |
| `MLKEMBraid/ctx/pqspk/v2` | the ML-KEM-1024 signed prekey (last-resort PQ contribution) |
| `MLKEMBraid/ctx/enrolment/v2` | `EnrolmentProof` (§F) |

Adding a context requires editing this table. The signed byte string is parent §3.6's, unchanged:

```
signed_msg = "MLKEMBraid/xeddsa/v2\x00" || u16(len(ctx)) || ctx || IdentityId || payload
```

**Label byte encoding, stated once for the whole project:** domain-separation labels are the literal ASCII
bytes shown, with **no terminator and no length prefix**. The `\x00` in the string above is part of that
literal and is retained deliberately — it is what preserves the Python framing whose disjointness from the
raw signing path the no-substitution argument depends on (`crypto/xeddsa.py:48`).

### E.3 ML-DSA-65 call shape — empirical

`ml-dsa 0.1.1`'s `Signer::sign` is **deterministic and hardcodes an empty context** (§H, Q3c). A context
string is only reachable through `ExpandedSigningKey`. Since §E.2 makes the context load-bearing:

- Sign with `sk.expanded_key().sign_deterministic(msg, ctx)`.
- Verify with `vk.verify_with_context(msg, ctx, sig)`, which returns **`bool`, not `Result`** — a
  dangerously ignorable return. `mlkb-crypto` wraps it so the only reachable form returns
  `Result<(), Unauthenticated>`, and the raw API is not re-exported.
- FIPS-204 **pre-hash (HashML-DSA) does not exist** in this crate. M1 uses pure ML-DSA-65 only; nothing in
  this specification requires pre-hash.

Private keys are stored as the **32-byte seed ξ** and expanded on load. Parent §9 item 5 made this
contingent on `[VERIFY]`; it is now **confirmed** (§H, Q3b): `SigningKey::<MlDsa65>::from_seed(&xi)` is
public, and the 32-byte seed is the crate's canonical private-key serialization.

### E.4 XEdDSA

Unchanged from parent §5.4: byte-for-byte compatible with the vendored Signal C on the existing KAT
vectors, and **no rejections Signal does not perform** are added inside `verify`. Confirmed implementable
from the public `curve25519-dalek 5.0.0` API (§H, Q4).

One trap, recorded because it is not obvious: `MontgomeryPoint([0; 32]).to_edwards(0)` returns `Some`, so
the Montgomery→Edwards conversion is **not** a validity filter. The torsion check must be done on the
Edwards side. This applies to §C.2's DH validation, not to `verify`.

---

## F. `EnrolmentProof` and `Voucher`

Parent §4.3 puts `EnrolmentProof` in every prekey bundle and §6.2 makes it the thing a responding client
checks to verify scarcity *locally* — it is the load-bearing element of the whole §6 resolution — but
neither defines it. Parent §10.3's `Voucher` is the same credential at the FFI boundary.

```
EnrolmentProof (deterministic CBOR map, keys sorted per B.2)

  "e"   uint        issuer epoch
  "k"   uint        issuer_key_id (u32)
  "na"  uint        not_after_ms (u64)
  "s"   bstr        HybridSignature
  "sj"  bstr(32)    subject: IdentityId
  "t"   uint        tier (u8)
  "v"   uint        version == 0x0200
```

`"s"` signs `signed_msg` with `ctx = "MLKEMBraid/ctx/enrolment/v2"` and
`payload = canonical(EnrolmentProof without "s")` (the omission rule is §B.3).

- Issuer public keys ship as a **pinned set in the client binary**, selected by `issuer_key_id`. There is
  no fetch, so there is no substitution surface.
- Verification is a **pure function** with no I/O, so it lives in `mlkb-policy` and is reachable from
  `mlkb-protocol` without giving the protocol crate a clock, an RNG, or a store (parent §11 gate 6).
  Expiry is checked by the caller, which owns the clock.
- `Voucher` at the FFI boundary (parent §10.3) **is** this structure, serialized. It is explicitly not a
  bare enum: parent §10.3 already warns that an enum with no signature is not scarcity.
- In M1 the issuer is the existing attestation subsystem (parent §6.2); `tier` distinguishes
  attestation-backed from rate-limit-backed enrolment. M2's blind-signed variant replaces `"sj"` with a
  nullifier commitment and is out of scope here.

---

## G. Type-level and crate resolutions

### G.1 Where the secret types live — a deviation, stated

Parent §7 gives `mlkb-secrets` "every secret byte", while parent §4.1 requires that `derive_sk` be the
**only** constructor of `RootKey` and that `KemSharedSecret` have **no public constructor**.

**Those two cannot both hold across a crate boundary.** Rust has no mechanism to grant exactly one
*other* crate privileged construction — a `pub` constructor is reachable by everyone, and a private one
by nobody outside the defining crate. A sealed token does not help, because the token itself would need
the same privilege.

**Resolution.** The *invariant* outranks the *file layout*, because the invariant is what the threat model
depends on:

- `mlkb-secrets` owns the **containers**: `Secret32` (a `Zeroizing<[u8; 32]>` with constant-time equality,
  a redacting `Debug`, and no `Deref` to the raw bytes), and is still the only crate importing `zeroize`
  and `subtle` for that purpose.
- `mlkb-crypto` owns the **typed keys** built on those containers — `KemSharedSecret`, `RootKey`,
  `ChainKey`, `MessageKey`, `FrameKey` — with private fields and no public constructors, because that is
  the crate where `derive_sk`, `encapsulate`/`decapsulate` and `ChainKey::step` live. Construction is
  private to the crate that mints them, which is exactly parent §4.1's requirement.

This is a deviation from parent §7's table and is listed as such in §J. The choke-point property it was
protecting is preserved: there is still exactly one place each key type can come into existence.

### G.2 `Nonce192` — the RNG cannot live in `mlkb-protocol`

Parent §5.1 mandates a random 192-bit nonce per seal; parent §8.3 gives `MessageKey::seal(self, pt, aad)`
with no RNG parameter; parent §11 gate 6 forbids `mlkb-protocol` from depending on an RNG. All three
cannot hold.

**Resolution:** the nonce is injected, not generated.

```rust
pub fn seal(self, nonce: Nonce192, pt: &[u8], aad: Aad<'_>) -> Ciphertext;
```

`Nonce192([u8; 24])` has no public constructor and is obtainable only from
`Nonce192::random(&mut impl CryptoRng)`. The RNG is supplied at the `mlkb-session` boundary;
`mlkb-testkit` supplies a deterministic one for KATs and fuzzing. `mlkb-protocol` stays sans-io, the
one-shot consuming-`self` property of parent §8.3 is untouched, and the nonce travels in the ratchet
header (`"nc"`, §D.3).

### G.3 `Aad`, `CanonicalBytes`, `Plan`

- `CanonicalBytes` — a newtype over `[u8]` constructible **only** by `mlkb_codec::encode_canonical`.
- `Aad<'a>(&'a CanonicalBytes)` — a transparent borrow. Parent §8.3's rejection of a raw-slice `seal`
  stands: `Aad` exists precisely to make ad-hoc concatenation unrepresentable, and §D.3 now defines the
  one value it carries.
- `Plan` — a private enum in `mlkb-protocol` with no public constructor and no public fields, produced
  only by `classify` and consumed only by `apply` (parent §8.1).

The borrow conflict between parent §8.1's `classify(&self)` and parent §8.2's consuming
`ChainKey::step(self)` is resolved by having `classify` work on a **clone** of the relevant chain key —
`ChainKey` is `Clone`, documented as "clone only to plan; the original is consumed by `apply` or dropped".
The one-shot property that matters is `MessageKey`'s, which is unaffected.

### G.4 no-`std` subtree

`mlkb-wire` and `mlkb-crypto` are **`no_std + alloc`**, like the crates that depend on them. Every
dependency in the no-`std` subtree is declared `default-features = false`. Parent §11 gate 6's
cross-compile covers the whole subtree, not just its root:

```
cargo check --target thumbv7em-none-eabi \
  -p mlkb-secrets -p mlkb-bounded -p mlkb-codec -p mlkb-wire -p mlkb-crypto -p mlkb-protocol
```

Confirmed feasible: `ml-kem 0.3.2` and `ml-dsa 0.1.1` are both `#![no_std]` and were compiled for
`thumbv7em-none-eabi` with `default-features = false` during Phase 0 (§H, Q10b).

The parent's caveat stands verbatim and must not be overstated: this proves no-`std`; it does **not**
prove absence of global mutable state.

### G.5 At-rest encryption vs. SQLCipher

Parent §5.1 mandates the ChaCha family at rest; parent §9 mandates SQLCipher, which is AES-256-CBC +
HMAC-SHA512.

**Resolution: both, layered.** SQLCipher remains as container-level defence in depth. Every secret blob —
ratchet state, identity private keys, the ML-DSA seed ξ — is sealed with XChaCha20-Poly1305 under
`K_store` **before** it is bound into a SQL statement. A SQLCipher key compromise alone therefore yields
no key material. Parent §5.1's constant-time rationale applies to the message and ratchet paths, where it
is load-bearing; the container cipher is not on that path.

---

## H. Phase 0 results — the API cheat sheet

Every line below was **compiled and executed** against the pinned versions on rustc 1.96, not read from
documentation. This discharges parent §11.4 for items 1, 2, 3 and 5 (item 4, `blind-rsa-signatures`, is
M2-only and remains open). **Gate verdict: PASS, with four corrections that are now normative above.**

| # | Question | Answer |
|---|---|---|
| 1 | ML-KEM crate | `ml-kem 0.3.2`. `MlKem1024`, `EncapsulationKey<MlKem1024>`, `DecapsulationKey<MlKem1024>`, `SharedKey = Array<u8,U32>` |
| | sizes | ek **1568**, ct **1568**, ss **32**, dk **64** (the FIPS-203 `(d,z)` seed — *not* 3168; the expanded form is deprecated) |
| | from wire | `EncapsulationKey::<MlKem1024>::new(&Array<u8,U1568>) -> Result<_, InvalidKey>`; validates the 12-bit coefficient bound |
| | ⚠ | validation is the modulus check **only** — the trailing 32-byte `rho` is not range-checked. Decoding ≠ key confirmation |
| 2 | deterministic encaps | `encapsulate_deterministic(&self, m: &B32)` — **public**, works with `default-features = false` |
| | K-PKE `u`/`v` | **absent.** `mod pke` is private; `EncryptionKey::encrypt` and the `u`/`v` vectors are `pub(crate)`; `r` is derived as `(K,r) = G(m ‖ H(ek))` and cannot be injected. **A future Braid split requires forking `ml-kem`** — exactly the risk parent §2 deferred |
| 3 | ML-DSA crate | `ml-dsa 0.1.1`. vk **1952**, sig **3309**, seed **32** |
| | seed keygen | **confirmed.** `SigningKey::<MlDsa65>::from_seed(&Seed)`; the 32-byte seed is canonical. Parent §9 item 5's plan holds |
| | context / mode | `Signer::sign` is deterministic with a **hardcoded empty context**; context and hedging live on `ExpandedSigningKey` (§E.3) |
| | pre-hash | **absent.** No HashML-DSA. Not required by this spec |
| 4 | curve25519-dalek | `5.0.0`. `Scalar::from_canonical_bytes([u8;32]) -> CtOption<Scalar>` (owned array); `MontgomeryPoint::to_edwards(u8) -> Option<EdwardsPoint>` (plain `Option`). XEdDSA hand-roll confirmed implementable from the public API |
| 5 | x25519-dalek | `3.0.0`. **`StaticSecret` requires `features = ["static_secrets"]`** — not default. **Does not reject low-order keys** → §C.2 |
| 6 | AEAD | `chacha20poly1305 0.11.0`. `XChaCha20Poly1305`, nonce **24**, tag **16**. Detached in-place API available for the ratchet path |
| 7 | HKDF/HMAC | `hkdf 0.13` + `sha2 0.11`. **RFC 5869 TC1 reproduced byte-for-byte.** `expand_multi_info` avoids a concat buffer |
| 8 | CBOR | `ciborium 0.2.2` **cannot** produce deterministic encoding → §B.1. Removed from the dependency graph |
| 9 | zeroize / subtle | `Zeroizing<[u8;32]>`, `derive(Zeroize, ZeroizeOnDrop)` (needs `features = ["derive"]`), `ConstantTimeEq` for `[u8; N]` and `[u8]` — all confirmed |
| 10 | size | Linked binary exercising ML-KEM-1024 + ML-DSA-65 + X25519 + HKDF + XChaCha: **+255 KB** over a `println` baseline (+196 KB `.text`), stripped, x86-64. Treat as an order-of-magnitude figure; parent §10.6 still requires per-ABI measurement |
| 10b | no-`std` | Both `ml-kem` and `ml-dsa` are `#![no_std]`; whole subtree compiled for `thumbv7em-none-eabi` with `default-features = false` |
| — | RNG | **`rand_core 0.10` unifies the whole stack.** One `&mut R: CryptoRng` drives ml-kem, ml-dsa, x25519-dalek and nonce generation |

---

## I. Normative constants

One home, so the CI gates that reference them are testable.

| Constant | Value | Where it binds |
|---|---|---|
| `PROTOCOL_VERSION` | `0x0200` | every top-level struct |
| `FRAME_HEADER_LEN` | `15` | §A.1 |
| `MAX_FRAME_PAYLOAD` | `65536` | §A.1 rule 2 |
| `MAX_SKIP_PER_CHAIN` | `1000` | §D.4 (matches `double_ratchet.py:80`) |
| `MAX_SKIPPED_KEYS_PER_SESSION` | `2000` | §D.4 |
| `RETAINED_RECV_CHAINS` | `1` | §D.4 (matches `double_ratchet.py:85`) |
| `REPLAY_WINDOW_BITS` | `64` | §C.4 |
| `SEND_EPOCH_LEASE` | `64` | parent §5.2 lease-ahead: one `fsync` per 64 messages |
| `UNKNOWN_POOL_CAPACITY` | `64` | parent §6.6 serverless Unknown pool |
| `UNKNOWN_ENTRY_TTL_MS` | `60_000` | parent §6.6 |
| `OPK_LOW_WATER` / `OPK_REPLENISH_TO` | `20` / `100` | parent §6.5 item 3 |
| `MAILBOX_PER_SENDER` | `64` messages / `1 MiB` | parent §6.4 row 5 |
| `RATE_LIMIT_BURST` / `RATE_LIMIT_REFILL` | `60` / `1 per second` | parent §6.4 row 6 |
| `BUNDLE_MAX_AGE_MS` | `604_800_000` (7 days) | `PrekeyBundleV2.expires_at_ms` |
| ML-KEM-1024 | ek `1568`, ct `1568`, ss `32`, seed `64` | §H |
| ML-DSA-65 | vk `1952`, sig `3309`, seed `32` | §H |
| XChaCha20-Poly1305 | key `32`, nonce `24`, tag `16` | §H |

---

## I.2 The complete M1 label registry

Parent §4.4 claims to be "the complete set of HKDF labels" and is not — five sections need labels absent
from it (§J row 9). This table is the closed set for M1. **Adding a label requires editing this table**,
and no crate may spell one of these byte strings outside `mlkb-crypto`'s `labels` module.

Every entry is the literal ASCII bytes shown: no terminator, no length prefix (§E.2).

| Label | Used for | Source |
|---|---|---|
| `MLKEMBraid/pqxdh/v2` | `SK` derivation `info` prefix | parent §4.1 |
| `MLKEMBraid/pqxdh/confirm/v2` | `k_cf`, the confirmation-tag key | parent §4.2 |
| `MLKEMBraid/frame/i2r/v2` | `K_frame_i2r` | parent §4.4 |
| `MLKEMBraid/frame/r2i/v2` | `K_frame_r2i` | parent §4.4 |
| `MLKEMBraid/sid/v2` | `session_id` | parent §4.4 |
| `MLKEMBraid/erasure-chunk/v2` | `K_chunk` — **M2+ only; no M1 derivation path exists** | parent §4.4 |
| `MLKEMBraid/ratchet/root/v2` | the hybrid ratchet root step | §D.2 |
| **`MLKEMBraid/store/v2`** | **`K_store`, the at-rest value-sealing key** | **§G.5 — the literal was previously unspelled anywhere; a second implementation could not reproduce it. Fixed here.** |
| `MLKEMBraid/frame/v2` | frame MAC preimage prefix (HMAC, not HKDF) | parent §3.3 |
| `MLKEMBraid/xeddsa/v2\x00` | signed-byte-string domain tag (the `\x00` is part of the literal) | parent §3.6, §E.2 |
| `MLKEMBraid/ctx/spk/v2` | signature context: X25519 signed prekey | §E.2 |
| `MLKEMBraid/ctx/pqspk/v2` | signature context: ML-KEM signed prekey | §E.2 |
| `MLKEMBraid/ctx/enrolment/v2` | signature context: `EnrolmentProof` | §E.2, §F |
| `0x01` / `0x02` | chain step — **HMAC message bytes, not HKDF labels** | §D.2 |

## I.3 The RNG boundary is load-bearing

Recorded here because it is a cross-crate obligation that no single crate can enforce, and the crate that
must honour it does not exist yet.

`Nonce192` can only be minted by `Nonce192::random(&mut impl CryptoRng)`, and every type-level route to
duplicating one is closed (no `Clone`, no `Copy`, no `from_bytes`, no `From<[u8; 24]>`, no conversion from
`WireNonce`). But `CryptoRng` is a **safe marker trait**: safe code can implement it with a lie, and a
constant-output RNG yields repeated nonces. Under XChaCha20-Poly1305 that is keystream reuse plus
Poly1305 one-time-key recovery — on the message path *and* on the at-rest path that protects the ML-DSA
seed ξ and the identity private keys.

The key half of the defence cannot help here: M1 §G.3 requires `ChainKey: Clone` for the classify/apply
split, so `ck.clone().step()` and `ck.step()` yield two byte-identical `MessageKey`s by construction.

**Therefore:** `mlkb-session` supplies the RNG at exactly one boundary, and that boundary must draw from
the platform CSPRNG. It is the sole remaining defence against nonce reuse. `mlkb-testkit`'s deterministic
RNG exists for KATs and fuzzing and **must never be reachable from a production constructor** — this is
the same structural requirement as parent §7's note that `mlkb-testkit` is a dev-dependency, and the same
defect class as `client/anonymous_transport.py:30-35`, which shipped hardcoded development keys in an
importable production class.

## J. Complete list of deviations from the parent spec

Nothing above changes the parent silently. Every disagreement, in one place:

| # | Parent says | This document says | Why |
|---|---|---|---|
| 1 | §3.2 deterministic CBOR is the canonical encoding for everything | The **frame envelope is fixed-layout**; CBOR governs payloads only (§A.1) | The parent's own §3.3 MAC input is a fixed-layout concatenation; under CBOR the preimage and the wire bytes differ |
| 2 | §5.3 canonical CBOR via `ciborium` + own profile | **Own encoder; `ciborium` removed entirely** (§B.1) | Compiled proof it cannot sort keys, cannot reject floats, and accepts indefinite lengths |
| 3 | §3.4 `device_id` | `to_device_id` (§C.3) | §6.3 needs the *responder's* device, computable from the message alone |
| 4 | §3.4 `InitialMessageV2` field set | adds `pqspk_id: u32` (§C.3) | Otherwise a responder with rotating PQ prekeys cannot select the decapsulation key |
| 5 | §5.2 "Standard Double Ratchet" | **Hybrid DH + ML-KEM ratchet, fully specified** (§D) | Deferring the Braid leaves M1 with no asymmetric ratchet input at all; a classical-only one fails the PQ requirement |
| 6 | §8.3 `seal(self, pt, aad)` | `seal(self, nonce, pt, aad)` (§G.2) | A random nonce cannot be generated inside a crate that gate 6 forbids an RNG |
| 7 | §7 `mlkb-secrets` owns every secret byte | Containers in `mlkb-secrets`, **typed keys in `mlkb-crypto`** (§G.1) | The "no public constructor" invariant cannot cross a crate boundary in Rust; the invariant outranks the layout |
| 8 | §6.3 reject if `seq <= last_seq - 64` | reject if `seq + 64 <= last_seq` (§C.4) | The parent's form underflows for every freshly admitted peer |
| 9 | §4.4 "the complete set of HKDF labels" | Complete **for M1**, extended with §D.2, §E.2 and `K_store` | The parent's claim was false — five sections needed labels absent from the table |
| 10 | §9 SQLCipher, §5.1 ChaCha at rest | **Both, layered** (§G.5) | SQLCipher is AES-CBC; value-level XChaCha sealing means a container-key compromise yields no key material |
| 11 | §5.4 / §3.6 (no change) | unchanged, plus the `to_edwards` non-filter trap recorded (§E.4) | Empirical: `MontgomeryPoint([0;32]).to_edwards(0)` returns `Some` |
| 12 | §9 item 5 seed storage `[VERIFY]` | **Confirmed** (§E.3, §H) | `SigningKey::from_seed` is public and the seed is canonical |

### Still open, unchanged from the parent

The parent's §12 open questions 2, 3 and 4 are **not** resolved here — they need a human decision, not a
specification:

2. No migration path from v1. Confirmed acceptable?
3. Who builds and operates the M2 voucher issuer?
4. Is the deferred Braid SCKA split still a product requirement, given M1 delivers PQ security without it?

§D.1 sharpens question 4 with a fact the parent did not have: the Braid split now **provably requires
forking `ml-kem`**, because the K-PKE internals it needs are `pub(crate)` and the encapsulation randomness
cannot be injected independently of `m` (§H, Q2). Its benefit over M1 is bandwidth, not security.
