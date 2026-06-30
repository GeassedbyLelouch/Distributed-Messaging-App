# ML-KEM Braid Chat — Abstract Protocol Specification

This is the **authoritative, byte-exact** abstraction of the protocol as implemented
in the Python reference (`ml_kem_braid/`). It is the single source of truth for the
formal models in [`formal/`](../formal/) and the Rust re-implementation in
[`docs/RUST_REWRITE.md`](RUST_REWRITE.md). Every KDF label, salt, and message field
below is copied verbatim from the code; where a model needs a byte-exact detail not
restated here, the cited source file is normative.

Notation: `‖` = concatenation; `HKDF(ikm, salt, info, L)` = HKDF-SHA256 → `L` bytes;
`HMAC(k, m)` = HMAC-SHA256; `i8(n)` = `n` as 8-byte big-endian; `0x00^32` / `0xff^32`
= 32 repeated bytes. Roles: **A** = session initiator (`Role.ALICE`), **B** =
responder (`Role.BOB`).

---

## 0. Layers and composition

```
   PQXDH handshake  ──►  SK (32 B)  ──►  seeds the ML-KEM Braid SCKA authenticator
        (one-shot)                       AND the Double Ratchet root key
                                              │
   ML-KEM Braid SCKA  ──► per-epoch keys k_e ─┤ (asymmetric/"DH" ratchet input)
        (continuous)                           ▼
                                          Double Ratchet ──► per-message keys mk
                                                                  │
                                                                  ▼
                                                          AES-256-GCM payload
   Sesame relay: opaque envelopes over HTTP/WS; minimal metadata; token-auth sender.
```

Security goals (all layers): PQ + classical confidentiality, mutual authentication,
**forward secrecy** (per message), **post-compromise security** (heals once fresh
SCKA entropy flows), replay resistance, unknown-key-share (UKS) resistance, and
**hybrid security** — safe if *either* X25519 or ML-KEM is unbroken.

Threat model: Dolev-Yao network attacker (full control of the relay/network) plus a
**state-compromise oracle** the attacker may query at chosen times (needed to state
FS/PCS). The relay server is **untrusted** (honest-but-curious at best): it sees only
public bundles + opaque ciphertexts + minimal metadata, never private keys or
plaintext.

---

## 1. PQXDH initial handshake  (`ml_kem_braid/pqxdh/pqxdh.py`)

### Long-term / ephemeral keys
- Identity: `IK_sign` = Ed25519 keypair, `IK_dh` = X25519 keypair. (Deviation from
  Signal: a dedicated Ed25519 signing key instead of XEdDSA; `IK_dh` is bound to
  `IK_sign` by a signature — see below.)
- Signed prekey `SPK` = X25519, signed by `IK_sign`.
- PQ prekey `PQSPK` = **ML-KEM-1024** encapsulation key, signed by `IK_sign`.
- One-time prekeys `OPK` = X25519 (consumed on use).
- Ephemeral `EK_A` = X25519 (initiator, fresh per handshake).

### Prekey bundle (published by B; all signatures by `IK_sign_B`)
`ik_sign_pub, ik_dh_pub, ik_dh_sig = Sign(IK_sign, ik_dh_pub), spk_pub, spk_sig,
pqspk_pub, pqspk_sig, [opk_pub]`. The initiator verifies **every** signature before use.

### Key derivation
```
DH1 = X25519(IK_dh_A, SPK_B)
DH2 = X25519(EK_A,   IK_dh_B)
DH3 = X25519(EK_A,   SPK_B)
DH4 = X25519(EK_A,   OPK_B)            # omitted iff no one-time prekey
SS  = ML-KEM-1024.Encaps(PQSPK_B) → (ss, kem_ct)
SK  = HKDF( ikm  = 0xff^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss,
            salt = 0x00^32,
            info = "MLKEMBraid_PQXDH_CURVE25519_SHA-256_ML-KEM-1024" ‖ IK_sign_A ‖ IK_sign_B,
            L = 32 )
```
- The `info` field **binds both identity signing keys** → UKS / identity-misbinding
  resistance. (Added after an adversarial review; `test_security_fixes.py`.)
- `0xff^32` is the X3DH/PQXDH curve domain-separation prefix `F`.

### Initial message (A→B, public)
`ik_sign_pub_A, ik_dh_pub_A, ik_dh_sig_A, ek_pub_A, spk_id, pqspk_id, kem_ct, [opk_id]`.
Responder **verifies `ik_dh_sig_A`** (binds A's X25519 key to A's Ed25519 identity)
before any DH, then recomputes the same `SK` and **deletes the used `OPK`** (replay of
the initial message then fails with `KeyError`).

### Properties to verify
Secrecy of `SK`; mutual implicit authentication; UKS resistance (identity binding);
OPK single-use ⇒ replay resistance; hybrid (secure if X25519 *or* ML-KEM holds);
KCI resistance.

---

## 2. ML-KEM Braid SCKA  (`ml_kem_braid/core/ml_kem.py`, `protocol/states.py`, `core/{kdf,authenticator}.py`)

A Sparse Continuous Key Agreement producing a fresh shared key per **epoch**. `SK`
seeds the ratcheted authenticator at epoch 1.

### Incremental ML-KEM (the novel KEM interface)
A FIPS-203 encapsulation key is `ek = Encode₁₂(t̂) ‖ ρ` (`384k+32` B). Map:
`ek_seed = ρ` (32 B), `ek_vector = Encode₁₂(t̂)` (`384k` B),
`hek = SHA3-256(ek)`. Header = `ek_seed ‖ hek` (64 B).
- `Encaps1(ek_seed, hek; m) → (es, ct1, ss)` computes the **u-component** `ct1`
  (`= Compress_du(Aᵀ·ŷ + e1)`) and `ss`/`K` from header + random `m` **only**
  (`(K, r) = G(m ‖ hek)`, matrix `Â` expanded from `ρ`).
- `Encaps2(es, ek_seed, ek_vector) → ct2` computes the **v-component** once
  `t̂` (= `ek_vector`) is known.
- `Decaps(dk, ct1 ‖ ct2)` = standard FIPS-203 decaps with implicit rejection.

**Key lemma (novel, see [EasyCrypt scaffold](../formal/easycrypt/)):** for the same
`m`, `ct1 ‖ ct2` equals the standard ML-KEM ciphertext **byte-for-byte** (proven
empirically by `test_kem.py::test_split_equals_reference_monolithic` across 512/768/
1024). Hence IND-CCA transfers by a trivial reduction, and revealing `ct1` before
`ct2` leaks nothing not already implied by the public final ciphertext.

### KDFs (`core/kdf.py`); `PROTOCOL_INFO = "MLKEMBraid_MLKEM768_HMAC-SHA256"`
```
KDF_OK(ss, e)        = HKDF(ikm=ss,  salt=0x00^32, info=PROTOCOL_INFO ‖ ":SCKA Key" ‖ i8(e),            L=32)   → epoch key k_e
KDF_AUTH(root, k, e) = HKDF(ikm=k,   salt=root,    info=PROTOCOL_INFO ‖ ":Authenticator Update" ‖ i8(e), L=64)  → (root', mac_key)
```

### Ratcheted authenticator (`core/authenticator.py`)
- `Init(e, key)`: `root ← 0x00^32`; then `Update(e, key)`.
- `Update(e, key)`: `(root, mac_key) ← KDF_AUTH(root, key, e)`.
- `MacHdr = HMAC(mac_key, PROTOCOL_INFO ‖ ":ekheader"  ‖ i8(e) ‖ header)`
- `MacCt  = HMAC(mac_key, PROTOCOL_INFO ‖ ":ciphertext" ‖ i8(e) ‖ ct1‖ct2)`
- **Transactional** `update_and_verify_ciphertext`: derive candidate `(root', mac')`,
  verify `MacCt` under `mac'`, and commit **only on success** — a forged ciphertext
  cannot advance/corrupt authenticator state. Verification failure ⇒ session halts.

### State machine
11 states (5 "transmit-EK / receive-CT", 5 "transmit-CT / receive-EK", + start),
driven by `Send`/`Receive` returning `(msg, sending_epoch, output_key?)` /
`(receiving_epoch, output_key?)`. Messages: `{epoch, type ∈ {None,Hdr,Ek,EkCt1Ack,
Ct1Ack,Ct1,Ct2}, data?}`. Large objects (header, ek_vector, ct1, ct2) are
**erasure-coded** (systematic Reed-Solomon over GF(2⁸)) into a chunk stream; any
`k`-of-`(k+p)` chunks reconstruct. `sending_epoch = epoch − 1`.

### Properties to verify
Agreement (both parties derive identical `k_e` per epoch); secrecy of each `k_e`;
authentication (MAC); FS across epochs; PCS (fresh ML-KEM entropy per epoch heals a
compromise); **state-machine correctness** — at most one key per epoch, no deadlock,
eventual progress (← TLA+ territory, §A).

---

## 3. Double Ratchet over the SCKA  (`ml_kem_braid/core/double_ratchet.py`)

Layers per-message keys on the shared per-epoch keys `k_e`. Because `k_e` is
**shared**, the two directions are split by domain separation so the parties never
derive the same sending chain (which would reuse keys).

```
KDF_RK(rk, k_e) = HKDF(ikm=k_e, salt=rk, info="MLKEMBraid-DR-root", L=64) → (rk', seed)
CK_{A→B} = HKDF(ikm=seed, salt=0x00^32, info="A->B", L=32)
CK_{B→A} = HKDF(ikm=seed, salt=0x00^32, info="B->A", L=32)
KDF_CK(ck) : mk = HMAC(ck, 0x01) ;  ck' = HMAC(ck, 0x02)
```
- `rk` initialised from PQXDH `SK`. On a new epoch key: `rk, seed ← KDF_RK(rk, k_e)`;
  set `ck_send/ck_recv` by role (A: send=`A→B`, recv=`B→A`; B: opposite); reset
  message counters; advance current epoch.
- Encrypt: `ck_send, mk ← KDF_CK(ck_send)`; `ct = AEAD(mk, pt, AD)`; header =
  `{epoch, index}`; index++.
- Decrypt: select `mk` by header — skipped-key cache (out-of-order), else chain-walk
  from `n_recv` caching intermediate keys (bounded by **`MAX_SKIP = 1000`**), else
  raise for future/past/consumed. **Commit-after-AEAD** (transactional) and
  **verify-before-evict** on the cache (a forged ciphertext for a cached slot must not
  consume the key).
- AEAD associated data: `AD = sender:dev "->" recipient:dev  ‖  "hdr:" ‖ i8(epoch) ‖ i8(index)`
  (directional identity binding + header binding; see `_chat_ad`, `_header_bytes`).

### Properties to verify
Per-message secrecy; FS (used `mk` and superseded `ck` are unrecoverable from current
state); PCS (inherited via `KDF_RK` from the SCKA); out-of-order correctness;
`MAX_SKIP` bound (no unbounded allocation); tamper ⇒ no state corruption, no forged
delivery; directional separation ⇒ no cross-direction key reuse.

---

## 4. Sesame relay  (`ml_kem_braid/sesame/*`, `server/app.py`)

Accounts keyed by **username only** (minimal metadata: username, device id,
registration id, timestamps, public bundles). Username pinned to `IK_sign` on first
registration (TOFU) via a possession proof `Sign(IK_sign, "MLKEMBraid-register:{username}:{registration_id}")`
verified server-side. Sender identity on every relay path is derived from the
device's **bearer token**, never the request body. Envelopes (`pqxdh_init | braid |
chat`) are opaque to the server. One-time prekeys consumed on bundle fetch.

### Properties to verify (mostly system-level)
Username↔identity binding (no hijack without the key); sender authenticity (no
spoofing); mailbox isolation; the server learns nothing beyond metadata + ciphertext.

## 5. Decentralized anonymous delivery

Decentralized anonymous mode replaces the single relay assumption with federated
home relays and client-owned state. Identity keys, PQXDH secrets, Braid and
Double-Ratchet state, contact logs, and delivery policy remain on the client; relays
publish public material and move opaque envelopes.

### Signed public records
Each account/device publishes a `SignedRecord` containing the current relay locator,
device id, identity signing key, signed prekeys, PQ prekeys, capabilities, expiry,
and monotonic record version. The record body is signed by the device identity key.
Clients reject records with invalid signatures, expired timestamps, stale versions,
or identity-key mismatches against an existing contact binding.

Contact request and accept messages are also signed. The request signature binds the
requester identity, target identity, selected `SignedRecord` version, fresh nonce,
and timestamp. The accept signature binds both identities, the accepted request id,
the responder's selected prekey material, and its own nonce/timestamp. These
signatures give the transcript a stable identity binding before PQXDH begins.

### Anonymous transport and rendezvous
Anonymous delivery uses mandatory 3-hop routing for all client traffic in this mode:
client -> entry relay -> middle relay -> destination home relay. Each hop sees only
its adjacent peers and an opaque envelope. Relay envelopes carry only routing data
needed for the next hop plus ciphertext payloads (`contact_request | contact_accept |
pqxdh_init | braid | chat`).

Direct P2P is disabled unless the path is relay-only and discloses no endpoint IP
addresses. Interactive streams therefore use relay-only rendezvous: both peers attach
to relay streams under rendezvous ids, and relays forward encrypted stream frames
without revealing either peer's network address to the other peer.

### OPK leases and replay prevention
One-time prekeys are reserved before use with an `OPK lease`. Lease state transitions
are:

```
available -> leased -> consumed
available -> leased -> expired
```

Only leased keys can be consumed by the matching contact/PQXDH transcript, and a
lease expires if the transcript is not completed before its deadline. Relays reject
duplicate request ids, stale `SignedRecord` versions, reused nonces, expired
timestamps, and attempts to consume an already consumed or expired lease. Clients
cache accepted transcript ids and record versions so replayed contact requests,
accepts, and initial PQXDH messages do not create new sessions or advance state.

---

## A. Verification target matrix (which tool proves what)

| Layer / property | Verifpal | Tamarin | TLA+/Apalache | CryptoVerif/EasyCrypt |
|---|---|---|---|---|
| PQXDH secrecy/auth/UKS | ✓ (first pass) | ✓ | – | ✓ (computational, hybrid) |
| SCKA agreement / no-deadlock | – | partial | **✓** | – |
| SCKA key secrecy + FS/PCS | partial | **✓** | – | ✓ |
| Double Ratchet FS/PCS/order | partial | **✓** | – | ✓ (Squirrel/CryptoVerif) |
| KEM split = IND-CCA(ML-KEM) | – | – | – | **✓ (EasyCrypt)** |
| Constant-time / side channels | – | – | – | ct-verif/Jasmin (out of model) |

Out of scope for these models (must be addressed separately): timing/side channels
(kyber-py is **not** constant-time), RNG quality, the model-to-code gap (closed only
by verified implementations — libcrux/HACL\*, DY\*/hax), and deniability/metadata
privacy unless explicitly modeled.
