# ML-KEM Braid — Post-Quantum Chat Scaffold

**Required Tools**

`uv`, `python3`... etc.

**Installing dependencies with `uv`**

```bash
# switch to this branch
uv sync # sync dependencies from pyproject.toml
uv venv # this creates a .venv virtual environment directory to use very easily with `uv`
source .venv/bin/activate # Linux/Mac
# OR
source .venv/Scripts/Activate.ps1
# Good to go!
```

This implementation follow the Signal Protocol specification very closely with a few caveats such as the zero knowledge proof's involved with there storage system. I don't see why that would be inherently useful in this case over other mechanisms already tested. Note that for "formal" claude/codex proofs are not correct, but they also aren't *incorrect* per-say... In other words, I just haven't done the due dilligence yet and for a project this size and the amount of cryptographic functionality being implemented, it may take a while... 

A **real** (FIPS-203) Python implementation of Signal's [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/)
Sparse Continuous Key Agreement (SCKA), seeded by a [PQXDH](https://signal.org/docs/specifications/pqxdh/)
handshake and wrapped in a [Sesame](https://signal.org/docs/specifications/sesame/)-style
account/device/mailbox model, with a FastAPI key-distribution and relay server, both
HTTP polling and WebSocket push transports, a chat client library, and an end-to-end
testnet.

No cryptography is implemented from scratch. ML-KEM comes from `kyber-py` (FIPS-203
reference implementation), X25519/Ed25519/HKDF/AES-GCM from `cryptography`, and
Reed-Solomon erasure coding from `reedsolo`. I had to use `kyber-py` in this case over something like `liboqs` because of the KEM split fidelity/PQXDH functionality used for key agreement, ratcheted authentication, erasure recovery, etc.

> **Research/educational caveat.** The protocol math (KEM split fidelity, PQXDH
> agreement, ratcheted authentication, erasure recovery, the Double Ratchet) is
> real and tested. The deployment layer now supports a persistent SQLite store, TLS
> serving with self-signed-cert pinning and optional mutual TLS, and a Signal-style
> Double Ratchet over the SCKA keys — but still lacks rate limiting/DoS protection
> and has had no third-party security audit. Not for production use without one.

---

## Table of Contents

1. [What's real — feature table](#1-whats-real--feature-table)
2. [Why kyber-py, not liboqs](#2-why-kyber-py-not-liboqs)
3. [Architecture](#3-architecture)
4. [Protocol walkthroughs](#4-protocol-walkthroughs)
   - 4a. [PQXDH initial handshake](#4a-pqxdh-initial-handshake)
   - 4b. [ML-KEM Braid SCKA](#4b-ml-kem-braid-scka)
   - 4c. [Sesame account/device/mailbox model](#4c-sesame-accountdevicemailbox-model)
   - 4d. [End-to-end message flow](#4d-end-to-end-message-flow)
5. [Transports](#5-transports)
6. [Setup and usage](#6-setup-and-usage)
7. [HTTP/WS API reference](#7-httpws-api-reference)
8. [Security model](#8-security-model)
9. [Testing](#9-testing)
10. [References](#10-references)

---

## 1. What's real — feature table

| Layer | Implementation |
|-------|----------------|
| ML-KEM incremental KEM | `kyber-py` K-PKE internals split into `Encaps1` (ct1 from 64-byte header alone) / `Encaps2` (ct2 from ek_vector). `ct1‖ct2` equals the exact FIPS-203 ciphertext — verified against the reference monolithic `encaps` in `test_kem.py::test_split_equals_reference_monolithic`. |
| SCKA state machine | 11-state Braid machine (see [states.py](ml_kem_braid/protocol/states.py)); ratcheted HMAC-SHA256 authenticator with transactional verify-before-commit; HKDF-SHA256 `KDF_OK`/`KDF_AUTH`; per-epoch keys with forward secrecy and post-compromise security. |
| PQXDH handshake | X25519 ×4 DH + ML-KEM-1024 KEM → 32-byte `SK` via HKDF (`F‖DH1‖DH2‖DH3‖DH4‖SS`, info=`PQXDH_INFO‖IK_A‖IK_B`). Signed prekey bundles (Ed25519). Identity-binding signature on the initiator's DH key (`ik_dh_sig`). One-time prekey consumed on use; replay raises `KeyError`. |
| Erasure coding | Interleaved systematic Reed-Solomon over GF(2⁸) (`reedsolo`); recovers any k-of-(k+p) chunks including out-of-order delivery (verified with real chunk loss in tests). |
| Payload encryption | AES-256-GCM (`cryptography` AESGCM) under agreed per-epoch keys, with associated-data binding: `sender:dev->recipient:dev#epoch`. |
| Sesame store | Thread-safe in-memory account/device/mailbox store; username pinned to Ed25519 identity key on first registration; minimal metadata (no phone numbers, real names, or contact graphs). |
| Decentralized anonymous mode | Signed client-owned public records, OPK leases, federated relay forwarding, relay-only rendezvous, and mandatory 3-hop anonymous circuit transport. Direct P2P endpoints are rejected in anonymity mode. |
| Server | FastAPI relay: authenticated registration (Ed25519 `proof_sig`), prekey distribution with one-time-prekey consumption, opaque-envelope mailbox, WebSocket push channel. Sender identity always resolved from the bearer token, never the request body. |
| Transports | `HttpTransport` (polling) and `WebSocketTransport` (push), both satisfying a `Transport` typing.Protocol. At-least-once delivery via `_deliver_and_push`. |

---

## 2. Why kyber-py, not liboqs

The defining optimisation in Signal's ML-KEM Braid spec is splitting ML-KEM
encapsulation into two phases:

- **Phase 1 (`Encaps1`)**: produce the shared secret `K` and `ct1` (the `u`-vector
  ciphertext component) from only the 64-byte header (`ek_seed ‖ hek`). This is
  possible because `ct1 = Compress_du(A_hat^T · y_hat + e1)` — the matrix `A_hat`
  is expanded entirely from `rho = ek_seed`, and the randomness vector is derived via
  the FO transform from `m` and `hek = SHA3-256(ek)`.
- **Phase 2 (`Encaps2`)**: produce `ct2` (the `v`-polynomial component) once the
  full `ek_vector = Encode_12(t_hat)` arrives.

`liboqs` and `pycryptodome` expose only a monolithic `encaps()` and provide no access
to the intermediate lattice objects (`y_hat`, `e2`, etc.). Calling them cannot
implement the split.

`kyber-py` (a pure-Python FIPS-203 reference implementation) exposes the K-PKE
primitives directly:
- `_generate_matrix_from_seed(rho)` — expands the NTT-domain matrix from `ek_seed`
- `_G(m ‖ hek)` — the FO G-function yielding `(K, r)`
- `_generate_error_vector` / `_generate_polynomial` — CBD sampler
- `M.decode_vector(ek_vector, k, 12, is_ntt=True)` — deserialise `t_hat`

`Encaps1` performs the first half of `_k_pke_encrypt` (the `u`-component), stashing
`y_hat` and `e2` in an `EncapsulationSecret` object (never serialised or transmitted).
`Encaps2` completes the second half once `ek_vector` is available. Concatenated,
`ct1 ‖ ct2` is identical to what the monolithic `encaps` would have produced for the
same randomness — proven in tests.

See [`ml_kem_braid/core/ml_kem.py`](ml_kem_braid/core/ml_kem.py) for the full
implementation.

---

## 3. Architecture

```
ml_kem_braid/
├── core/
│   ├── ml_kem.py         Real FIPS-203 ML-KEM: keygen, Encaps1, Encaps2, decaps.
│   ├── kdf.py            HKDF-SHA256: KDF_AUTH (authenticator ratchet), KDF_OK (epoch keys).
│   ├── authenticator.py  Ratcheted HMAC-SHA256 authenticator; update_and_verify_ciphertext.
│   ├── aead.py           AES-256-GCM encrypt/decrypt (nonce ‖ ct ‖ tag).
│   ├── double_ratchet.py Double Ratchet over SCKA epoch keys (per-message keys, FS, skip cache).
│   └── provider.py       Research crypto-provider wrapper (HKDF-SHA256, AES-GCM, OS randomness).
├── decentralized/
│   ├── records.py        Canonical SignedRecord signing, verification, and contact-event state.
│   ├── descriptors.py    Username, relay, and contact-event record body helpers.
│   ├── opk.py            OPK lease state machine: available -> leased -> consumed/expired.
│   ├── vault.py          In-memory client-owned identity/session/contact-log vault.
│   ├── services.py       Signed-record registry, opaque mailboxes, federated relay forwarding.
│   ├── circuits.py       3-hop circuit frames, AES-GCM onion layers, fixed-size padding.
│   └── rendezvous.py     Relay-only anonymous stream rendezvous with no peer addresses.
├── encoding/
│   └── erasure.py        Systematic Reed-Solomon encoder/decoder (reedsolo, GF(2⁸)).
├── protocol/
│   ├── messages.py       Message wire format: epoch (8B) ‖ type (1B) ‖ [len ‖ data].
│   ├── states.py         11-state SCKA state machine (abstract State, concrete classes).
│   └── braid.py          MLKEMBraid (Role.ALICE/BOB) + run_exchange driver.
├── pqxdh/
│   └── pqxdh.py          PQXDH: create_identity, create_prekey_bundle,
│                          initiator_handshake, responder_handshake.
├── sesame/
│   ├── base.py           StoreBackend ABC (interface shared by both backends).
│   ├── store.py          SesameStore: in-memory Account/Device/Envelope/mailbox.
│   └── sqlite_store.py   SqliteStore: durable backend (atomic OTK consume + mailbox drain).
├── server/
│   ├── app.py            FastAPI: registration, key distribution, mailbox, /ws endpoint.
│   └── decentralized_routes.py  Feature-gated signed-record and circuit-frame API.
├── client/
│   ├── transport.py      Transport protocol + HttpTransport + WebSocketTransport.
│   ├── anonymous_transport.py  3-hop anonymous circuit transport wrapper.
│   ├── vault_client.py   Minimal client wrapper for vault-owned identity state.
│   └── client.py         BraidChatClient: register, start_session, poll, send_chat.
├── testnet/
│   └── demo.py           In-process end-to-end testnet (no listening socket required).
├── transport/
│   └── http_client.py    BraidHttpClient, BraidServer, InMemoryTransport (raw-message transports).
├── tls.py                Self-signed cert generation, fingerprint pinning, server/client
│                          SSL contexts (mTLS), generate_dev_certs.
├── wire.py               JSON wire serialisation: b64 helpers, bundle/message
│                          encode-decode, registration_challenge.
└── __init__.py           Top-level re-exports: MLKEMBraid, Role, run_exchange.

tests/
├── test_anonymous_circuits.py
├── test_anonymous_transport.py
├── test_kem.py
├── test_braid_protocol.py
├── test_pqxdh.py
├── test_erasure.py
├── test_braid.py
├── test_server_testnet.py
├── test_security_fixes.py
├── test_websocket_transport.py
├── test_integration_scenarios.py
├── test_store_backends.py        (in-memory + SQLite parity, persistence)
├── test_tls.py                   (cert gen, pinning, mTLS, enforcement middleware)
├── test_decentralized_*.py       (signed records, services, docs, integration)
├── test_federated_relays.py
├── test_opk_leases.py
├── test_rendezvous.py
└── test_double_ratchet.py        (per-message keys, out-of-order, tamper, MAX_SKIP)
```

### Package responsibilities

| Package | Responsibility |
|---------|---------------|
| `core` | Pure cryptographic primitives — no I/O, no state. |
| `encoding` | Erasure coding for reliable delivery of large objects over chunk streams. |
| `protocol` | Full SCKA state machine and message format; `run_exchange` driver. |
| `pqxdh` | Initial handshake producing the 32-byte `SK` that seeds the Braid. |
| `sesame` | Minimal server-side metadata store; never touches private keys or plaintext. |
| `decentralized` | Signed records, OPK leases, client vaults, anonymous circuits, federated relay forwarding, and relay-only rendezvous. |
| `server` | HTTP + WebSocket relay server. |
| `client` | High-level chat client, HTTP/WS transports, anonymous circuit transport, and vault-backed identity wrapper. |
| `testnet` | Self-contained in-process demonstration requiring no server socket. |

### Decentralized anonymous mode

Decentralized anonymous mode lets clients choose federated home relays while keeping
identity, PQXDH, Braid, Double-Ratchet, and contact-log state client-owned. Public
directory material is published as signed public records, and PQXDH one-time prekeys
are reserved with OPK leases so contact establishment does not depend on a single
central key server.

In anonymity mode, client traffic uses mandatory 3-hop anonymous transport through
opaque envelopes. Direct P2P is disabled; peer rendezvous is relay-only rendezvous
over streams that do not disclose either peer's endpoint IP address to the other
peer. Relays route and store ciphertext envelopes, but do not learn private keys,
plaintext, contact logs, or peer network locations.

---

## 4. Protocol walkthroughs

### 4a. PQXDH initial handshake

```
Bob (responder) publishes to server:
  PreKeyBundle {
    ik_sign_pub,  ik_dh_pub,  ik_dh_sig   (Ed25519 sig over ik_dh_pub)
    spk_pub,      spk_sig                   (signed X25519 prekey)
    pqspk_pub,    pqspk_sig                 (signed ML-KEM-1024 prekey)
    opk_pub,      opk_id                    (one-time X25519 prekey, optional)
  }

Alice (initiator) fetches Bob's bundle and runs:

  1. Verify bundle signatures (Ed25519 on ik_dh_pub, spk_pub, pqspk_pub)

  2. Generate ephemeral key:  EK_A <- X25519.keygen()

  3. Four X25519 DH computations:
       DH1 = DH(IK_A_dh,  SPK_B)
       DH2 = DH(EK_A,     IK_B_dh)
       DH3 = DH(EK_A,     SPK_B)
       DH4 = DH(EK_A,     OPK_B)   (omitted if no one-time prekey)

  4. Post-quantum KEM:
       SS, kem_ct = ML-KEM-1024.Encaps(pqspk_pub)

  5. Key derivation (identity-bound):
       IKM  = F || DH1 || DH2 || DH3 [|| DH4] || SS
       info = PQXDH_INFO || IK_A_sign_pub || IK_B_sign_pub
       SK   = HKDF-SHA256(IKM, salt=0x00*32, info, length=32)

  6. Send InitialMessage to Bob:
       { ik_sign_pub, ik_dh_pub, ik_dh_sig, ek_pub, spk_id, pqspk_id, kem_ct, opk_id }

Bob (responder) on receiving InitialMessage:

  1. Verify initiator identity binding:
       Ed25519.Verify(msg.ik_sign_pub, msg.ik_dh_sig, msg.ik_dh_pub)

  2. Mirror the four DHs (roles reversed):
       DH1 = DH(SPK_B_priv, IK_A_dh)
       DH2 = DH(IK_B_priv,  EK_A)
       DH3 = DH(SPK_B_priv, EK_A)
       DH4 = DH(OPK_B_priv, EK_A)   (omitted if opk_id is None)

  3. SS = ML-KEM-1024.Decaps(pqspk_dk, kem_ct)

  4. SK = HKDF-SHA256(F || DH1..4 || SS, salt, info)  [same formula as Alice]

  5. Consume OPK: del secrets.opk_priv[opk_id]   (replay raises KeyError)

  => SK is now shared; both sides seed MLKEMBraid with it.
```

**Constants:**
- `PQXDH_INFO = b"MLKEMBraid_PQXDH_CURVE25519_SHA-256_ML-KEM-1024"`
- `F = 0xff * 32` (X25519 domain-separation prefix, X3DH convention)
- `ik_dh_sig` binds the X25519 DH identity key to the Ed25519 signing identity on
  both sides, defeating identity-misbinding attacks.

### 4b. ML-KEM Braid SCKA

The Braid SCKA runs as a full-duplex bidirectional protocol over a chunk stream.
Alice starts in `KeysUnsampled` (encapsulation-key transmitter); Bob starts in
`NoHeaderReceived` (ciphertext transmitter). Roles switch after each complete epoch.

**Key sizes (ML-KEM-768, the default):**

| Object | Size |
|--------|------|
| `ek_seed` (rho) | 32 B |
| `hek` = SHA3-256(ek) | 32 B |
| **header** = `ek_seed ‖ hek` | **64 B** |
| `ek_vector` = Encode_12(t_hat) | 1152 B (768), 1536 B (1024), 768 B (512) |
| `ct1` | 960 B (768) |
| `ct2` | 128 B (768) |
| Authenticator MAC | 32 B |

**ASCII state-machine (one epoch, ML-KEM-768):**

```
Alice (ALICE role)                          Bob (BOB role)
─────────────────                           ────────────────
[KeysUnsampled]
  keygen() -> dk, ek_seed, ek_vector, hek
  header  = ek_seed || hek  (64 B)
  mac     = HMAC(mac_key, "ekheader" || epoch || header)
  Send HDR chunks  ──────────────────────────>  [NoHeaderReceived]
                                                 collect HDR chunks
                                                 verify header MAC
                                               [HeaderReceived]
                                                 Encaps1(ek_seed, hek)
                                                   -> encaps_secret, ct1, ss_b
                                                 ss_b = KDF_OK(ss_b, epoch)
                                                 auth.update(epoch, ss_b)
                   <──────────────────────────  Send CT1 chunks  [Ct1Sampled]
[KeysSampled / HeaderSent]
  collect CT1 chunks
Send EK_CT1_ACK chunks (ek_vector)  ──────>  collect EK_CT1_ACK chunks
                                               [EkReceivedCt1Sampled]
                                                 Encaps2(encaps_secret, ek_seed, ek_vector)
                                                   -> ct2
                                                 mac_ct = HMAC(mac_key, "ciphertext" || epoch || ct1||ct2)
                   <──────────────────────────  Send CT2 (ct2 || mac_ct) chunks [Ct2Sampled]
[EkSentCt1Received / Ct1Received]
  collect CT2 chunks
  ct2 = payload[:ct2_size]
  mac = payload[ct2_size:]
  ss_a = ML-KEM.Decaps(dk, ct1 || ct2)
  ss_a = KDF_OK(ss_a, epoch)
  update_and_verify_ciphertext(epoch, ss_a, ct1||ct2, mac)
    => verify mac with candidate key BEFORE committing ratchet
  output_key = (epoch, ss_a)           output_key = (epoch, ss_b)
  assert ss_a == ss_b                  (same key agreed)
[NoHeaderReceived]                      [KeysUnsampled]  (roles swap)
  epoch += 1                            epoch += 1
```

**Transactional authenticator ratchet (`update_and_verify_ciphertext`):**
The decapsulator receives a ciphertext of unknown authenticity. It must not commit
the ratchet before verifying the MAC, since a forged ciphertext would permanently
corrupt the authenticator chain. `update_and_verify_ciphertext` computes the
candidate `(root_key, mac_key)`, verifies the ciphertext MAC against the candidate
key, and only then commits the new state. On failure, the authenticator is left
unchanged and the session must halt.

**Per-epoch key derivation:**
```
ss_raw = ML-KEM.Decaps(dk, ct1 || ct2)          # or .Encaps1 output
epoch_key = KDF_OK(ss_raw, epoch)
  = HKDF-SHA256(ikm=ss_raw, salt=0x00*32,
                info=PROTOCOL_INFO || ":SCKA Key" || epoch_as_8_bytes)
```

**Erasure-coded chunk stream:**
Each logical Braid object (header, ek_vector, ct1, ct2) is split into `k` systematic
data chunks plus `p = min(k, 255-k)` parity chunks using Reed-Solomon over GF(2⁸).
Any `k` of the `k+p` chunks reconstruct the original. On the happy path the receiver
assembles all `k` data chunks and never invokes RS decoding.

### 4c. Sesame account/device/mailbox model

```
SesameStore
├── Account (username → identity_key)
│   └── Device (device_id, registration_id, bundle, auth_token)
│       ├── one_time_prekeys: {opk_id → opk_pub}
│       └── Mailbox: deque[Envelope]
└── Envelope (envelope_id, sender, recipient, kind, body, created_at)
```

- Username is pinned to the Ed25519 `identity_key` on first registration.
  Subsequent registrations must present the same key (enforced in
  `SesameStore.register_device`), preventing mailbox hijacking.
- Server assigns `device_id` sequentially; existing devices are never overwritten.
- Minimal metadata: no phone numbers, email addresses, real names, or contact graphs.
- The store is thread-safe (`threading.RLock`). Swapping in a database requires
  reimplementing `SesameStore` — the interface is the same.

### 4d. End-to-end message flow

```
1. Register
   Alice.register()
     -> create_identity()          (Ed25519 + X25519 keypairs)
     -> create_prekey_bundle()     (SPK, PQSPK, OPKs, signatures)
     -> proof_sig = sign(registration_challenge(username, reg_id))
     -> POST /register {username, reg_id, bundle, proof_sig, one_time_prekeys}
        server verifies proof_sig against bundle.ik_sign_pub
     <- {device_id, auth_token}

2. Fetch Bob's bundle
   Alice.start_session("bob")
     -> GET /keys/bob              (list device ids)
     -> GET /keys/bob/1            (fetch bundle; server consumes one-time prekey)

3. PQXDH handshake
   sk_a, init_msg = initiator_handshake(alice.identity, bob_bundle)
   POST /messages {kind="pqxdh_init", body=init_msg, ...}   (Bearer alice_token)

4. Bob receives and responds
   Bob.poll()  ->  GET /messages (Bearer bob_token)
   _handle_pqxdh_init():  sk_b = responder_handshake(bob.identity, secrets, init_msg)
                           BraidSession(role=BOB, braid=MLKEMBraid(BOB, sk_b))

5. Braid key agreement
   run_until_agreed(alice, bob, session):
     each round: bob.poll() ; bob.pump_session() ; alice.pump_session() ; alice.poll()
     pump_session():  msg, _, key = braid.send()
                      POST /messages {kind="braid", body=msg}
     poll() -> _handle_braid(): braid.receive(msg)
   Both sides record epoch_key[epoch] when output_key is emitted.

6. Encrypted chat (via the Double Ratchet, keyed by the SCKA epoch keys)
   Alice.send_chat(session, "Hello")
     header, blob = session.ratchet.encrypt(plaintext, ad="alice:1->bob:1")
       # ratchet derives a fresh per-message key: mk = HMAC(ck_send, 0x01)
       # header = {epoch, index}; AEAD binds header+ad
     POST /messages {kind="chat", body={header:{epoch,index}, ciphertext=b64(blob)}}

   Bob.poll() -> _handle_chat():
     plaintext = session.ratchet.decrypt(header, blob, ad="alice:1->bob:1")
       # selects mk by header (skip cache / chain walk); commits state only on AEAD success
     inbox.append(("alice", 1, header.epoch, plaintext))
```

The testnet wires all of this in-process (no socket required) using FastAPI's
`TestClient` ASGI transport. Run it with `uv run braid-testnet`.

---

## 5. Transports

The client uses any object satisfying the `Transport` `typing.Protocol`:

```python
class Transport(Protocol):
    def register(self, payload: dict) -> dict: ...
    def list_devices(self, username: str) -> List[dict]: ...
    def get_bundle(self, username: str, device_id: int) -> dict: ...
    def send(self, payload: dict, token: str) -> dict: ...
    def fetch(self, token: str, drain: bool = True) -> List[dict]: ...
```

### HttpTransport (HTTP polling)

`HttpTransport` wraps an `httpx.Client` and maps each method to the corresponding
REST endpoint. The client polls `GET /messages` to drain its mailbox.

### WebSocketTransport (WebSocket push)

`WebSocketTransport` wraps a live WebSocket session. The three key-exchange methods
(`register`, `list_devices`, `get_bundle`) delegate to an inner `HttpTransport`
because they are strictly request/response. `send` writes an
`{"action": "send", ...}` frame; `fetch` drains an internal inbox buffer.

The transport is **passive**: it never calls `receive_json()` internally. The caller
controls when frames are pulled from the wire via `receive_one()`. This avoids
deadlocks in synchronous test environments.

### Delivery semantics and the HTTP/WS mailbox split

When a recipient has at least one live `/ws` connection, the server pushes envelopes
in real time via `_deliver_and_push()`. An envelope is stored in the persistent
mailbox **only when no live socket successfully accepted it** (e.g., the socket died
between the connectivity check and the actual send), guaranteeing at-least-once
delivery.

On `/ws` connect, the server flushes the device's queued mailbox to the socket so
no envelopes are missed during the gap between HTTP polling and WS connect.

**Choose one transport per device:** a client polling `GET /messages` while holding
an open `/ws` connection is harmless but WS-delivered envelopes will not re-appear
in polling responses. For real-time chat, open a `/ws` connection. For background
polling, use `GET /messages`.

---

## 6. Setup and usage

### Install

```bash
uv sync --extra dev
```

### Run the testnet (in-process, no server required)

```bash
uv run python -m ml_kem_braid.testnet.demo
# or, using the installed script:
uv run braid-testnet
```

This registers Alice and Bob, runs PQXDH, agrees an ML-KEM Braid epoch key on both
sides, and round-trips an AES-256-GCM chat message — all in-process via FastAPI's
ASGI test transport. Expected output:

```
[register] alice -> device 1, bob -> device 1
[pqxdh] alice established SK with bob device 1
[braid] agreed epoch 1: alice=… bob=… match=True
[chat] alice sent: 'Hello over post-quantum Braid!'
[chat] bob received: 'Hello over post-quantum Braid!'
RESULT: SUCCESS (epoch keys match=True, message roundtrip=True)
```

### Run the server

```bash
uv run braid-server       # uvicorn on 127.0.0.1:8000; GET /health, GET /docs
```

### Library quick start — Braid SCKA

```python
import os
from ml_kem_braid import MLKEMBraid, Role, run_exchange

# seed from a real PQXDH handshake; use os.urandom(32) only for testing
secret = os.urandom(32)
alice = MLKEMBraid(Role.ALICE, secret)
bob   = MLKEMBraid(Role.BOB,   secret)

for epoch, a_key, b_key in run_exchange(alice, bob, target_epochs=3):
    assert a_key == b_key                    # identical 32-byte post-quantum keys
    print(f"epoch {epoch}: {a_key.hex()[:16]}...")
```

`run_exchange` runs a synchronous in-memory simulation over a reliable in-order
channel. In a networked setting, call `braid.send()` and `braid.receive(msg)` per
round instead.

### Library quick start — PQXDH

```python
from ml_kem_braid.pqxdh import (
    create_identity,
    create_prekey_bundle,
    initiator_handshake,
    responder_handshake,
)

bob_identity = create_identity()
bundle, secrets = create_prekey_bundle(bob_identity, num_one_time=4)
# Bob publishes `bundle` to the server.

alice_identity = create_identity()
sk_a, init_msg = initiator_handshake(alice_identity, bundle)
# Alice sends `init_msg` to Bob.

sk_b = responder_handshake(bob_identity, secrets, init_msg)
assert sk_a == sk_b    # 32-byte shared secret agreed
```

### Client + transport example

```python
import httpx
from ml_kem_braid.client.client import BraidChatClient, HttpTransport, run_until_agreed

base = httpx.Client(base_url="http://127.0.0.1:8000")
alice = BraidChatClient(HttpTransport(base), "alice")
bob   = BraidChatClient(HttpTransport(base), "bob")

alice.register()
bob.register()

session = alice.start_session("bob")
run_until_agreed(alice, bob, session, target_epochs=1)

alice.send_chat(session, "Hello, post-quantum world!")
bob.poll()
print(bob.inbox[-1])   # ('alice', 1, 1, 'Hello, post-quantum world!')
```

---

## 7. HTTP/WS API reference

All REST endpoints accept and return JSON. Authenticated endpoints require
`Authorization: Bearer <auth_token>` (obtained from `POST /register`).

| Method | Path | Auth | Request body | Response |
|--------|------|------|--------------|----------|
| `GET` | `/health` | None | — | `{"status": "ok"}` |
| `POST` | `/register` | None | `RegisterRequest` | `RegisterResponse` |
| `GET` | `/keys/{username}` | None | — | `List[DeviceInfo]` |
| `GET` | `/keys/{username}/{device_id}` | None | — | `{username, device_id, bundle}` |
| `POST` | `/messages` | Bearer | `SendMessageRequest` | `{status, envelope_id}` |
| `GET` | `/messages` | Bearer | `?drain=true` | `List[EnvelopeModel]` |
| `WS` | `/ws?token=<token>` | Query token | JSON frames | JSON frames |

### Request / response shapes

**`RegisterRequest`**
```json
{
  "username": "alice",
  "registration_id": 1,
  "bundle": { "ik_sign_pub": "<b64>", "ik_dh_pub": "<b64>", "ik_dh_sig": "<b64>",
              "spk_id": 1, "spk_pub": "<b64>", "spk_sig": "<b64>",
              "pqspk_id": 1, "pqspk_pub": "<b64>", "pqspk_sig": "<b64>" },
  "proof_sig": "<b64>",           /* Ed25519 sig over registration_challenge(username, reg_id) */
  "one_time_prekeys": { "1": "<b64>", "2": "<b64>" }
}
```

**`RegisterResponse`**
```json
{ "username": "alice", "device_id": 1, "auth_token": "<urlsafe-base64>" }
```

**`SendMessageRequest`** (`POST /messages`)
```json
{
  "recipient_username": "bob",
  "recipient_device_id": 1,
  "kind": "pqxdh_init",           /* one of: pqxdh_init | braid | chat */
  "body": { ... }                 /* opaque; server never inspects it */
}
```

**Sender identity** is derived from the bearer token server-side. The `body` field
is opaque to the relay — the server never reads or modifies it.

**`EnvelopeModel`** (returned by `GET /messages` and pushed via `/ws`)
```json
{
  "envelope_id": "env-42",
  "sender_username": "alice",
  "sender_device_id": 1,
  "recipient_username": "bob",
  "recipient_device_id": 1,
  "kind": "braid",
  "body": { ... },
  "created_at": 1719400000.0
}
```

**`GET /keys/{username}/{device_id}`** — consumes one one-time prekey from the
device's prekey pool (Sesame/PQXDH one-time-prekey semantics). When the pool is
empty, `opk_id` and `opk_pub` are `null` in the response.

### WebSocket (`/ws?token=<token>`)

Authentication is via the `?token=` query parameter (same bearer token as the REST
endpoints). A bad token closes the connection with code 1008 (Policy Violation).

On connect, any envelopes queued in the device's mailbox are flushed to the socket.

**Inbound frame (client → server):**
```json
{
  "action": "send",
  "recipient_username": "bob",
  "recipient_device_id": 1,
  "kind": "chat",
  "body": { "header": { "epoch": 1, "index": 0 }, "ciphertext": "<b64>" }
}
```

**Outbound frames (server → client):**
```json
{ "type": "envelope", "envelope": { /* EnvelopeModel */ } }
{ "type": "ack",      "envelope_id": "env-42" }
{ "type": "error",    "detail": "unknown recipient device" }
```

Sender identity is always resolved from the connection's authentication token — it
is impossible for the client to forge the sender field in a frame body.

---

## 8. Security model

### Properties provided

| Property | Mechanism |
|----------|-----------|
| **Post-quantum confidentiality** | ML-KEM-1024 in PQXDH; ML-KEM-768 (default, or 512/1024) in Braid SCKA. KEM security under Module-LWE per FIPS 203. |
| **Forward secrecy** | Ephemeral PQXDH keys and per-epoch Braid keys are not retained after use; past epoch keys cannot be recovered from current state. |
| **Post-compromise security** | Braid SCKA ratchets fresh ML-KEM entropy into every epoch; compromise of one epoch does not expose subsequent epochs once fresh randomness is contributed. |
| **Authenticated handshake** | PQXDH bundle signatures (Ed25519) and `ik_dh_sig` binding — both the responder's prekey bundle and the initiator's DH key are signed by the respective Ed25519 identity keys. `SK` binds both identity public keys via the HKDF `info` field, defeating unknown-key-share attacks. |
| **Identity-pinned usernames** | Username is pinned to an Ed25519 identity key on first registration. Subsequent registrations must prove possession of the same key (`proof_sig` verified server-side). |
| **Token-authenticated relay** | Server derives sender identity from the bearer token, never from the request body. Envelopes cannot be spoofed. |
| **OPK replay prevention** | One-time prekeys are deleted on use (`del secrets.opk_priv[opk_id]`); a replayed `InitialMessage` with a consumed OPK raises `KeyError`. |
| **Transactional authenticator ratchet** | `update_and_verify_ciphertext` verifies the ciphertext MAC under the candidate (not yet committed) key before advancing the ratchet chain, preventing forged ciphertexts from corrupting long-term authenticator state. |
| **Per-message forward secrecy** | A Signal-style **Double Ratchet** ([core/double_ratchet.py](ml_kem_braid/core/double_ratchet.py)) layers symmetric sending/receiving chains over the SCKA per-epoch keys: every message gets a fresh key (`mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`) that is used once and dropped, with directional `A→B`/`B→A` chains, out-of-order/skipped-message handling (bounded by `MAX_SKIP`), and transactional decrypt (a forged ciphertext never advances or corrupts ratchet state). |
| **Transport security (optional)** | TLS serving via uvicorn (`BRAID_TLS_CERT`/`BRAID_TLS_KEY`); an enforcement middleware (off by default) that rejects plaintext with HTTP 426 and sets HSTS; libsignal-style **self-signed certificate pinning** on the client (trusts exactly one out-of-band cert, not the system CA store) and optional **mutual TLS**. See [tls.py](ml_kem_braid/tls.py). |
| **Durable storage (optional)** | A `StoreBackend` abstraction with an in-memory default and a persistent **SQLite** backend ([sqlite_store.py](ml_kem_braid/sesame/sqlite_store.py)) — atomic one-time-prekey consumption and mailbox drain — selected via `BRAID_STORE_PATH`. |
| **Minimal server-side metadata** | Username, device id, registration id, timestamps, and public prekey bundles only. No phone numbers, email addresses, real names, or contact graphs. The server never sees private keys or plaintext. |

### Not provided / out of scope

- **No rate limiting, DoS protection, or spam filtering.**
- **No formal audit.** This is a research/educational implementation. The protocol
  math is real and tested; it has not been reviewed by a third-party cryptographer
  or received a security audit.
- **No XEdDSA.** Signal's PQXDH spec uses XEdDSA to derive a signing key from the
  same Montgomery DH key. To avoid hand-rolling XEdDSA, this implementation uses a
  separate Ed25519 key for signing and binds the X25519 DH key to it via `ik_dh_sig`.
  This is a documented deviation.

### Adversarial review findings and fixes

An adversarial multi-agent review of a prior version identified several issues.
The following were fixed and have regression tests in `test_security_fixes.py`:

1. **Identity binding** — `ik_dh_sig` (Ed25519 signature over the initiator's X25519
   DH key) added to `InitialMessage`; responder verifies it.
2. **Both identity keys bound into SK** — `info = PQXDH_INFO || IK_A || IK_B`
   in the HKDF, defeating unknown-key-share attacks.
3. **OPK replay** — one-time prekeys are consumed on use.
4. **Transactional ratchet** — `update_and_verify_ciphertext` added to
   `Authenticator`.
5. **Authenticated registration** — `proof_sig` field and server-side Ed25519
   verification added to `POST /register`.
6. **Token-derived sender** — sender resolved from bearer token on all paths
   (POST /messages and WS send).

---

## 9. Testing

```bash
uv run pytest -q
```

**446 tests pass** (as of the latest verification run).

### Test modules

| Module | What it covers |
|--------|---------------|
| `test_kem.py` | Key-generation sizes; incremental Encaps1/Encaps2 matching decaps; **`test_split_equals_reference_monolithic`** proves `ct1‖ct2` equals the FIPS-203 reference ciphertext for all three ML-KEM variants (512/768/1024); implicit rejection on tampered ciphertext. |
| `test_braid_protocol.py` | Full ML-KEM Braid SCKA: `run_exchange` asserting identical per-epoch keys across all three ML-KEM variants for multiple epochs; initial state checks; forged-ciphertext MAC rejection mid-session. |
| `test_pqxdh.py` | PQXDH handshake agreement (with and without OPK); bundle signature verification; AEAD encrypt/decrypt round-trip; bundle and initial-message wire serialisation round-trips. |
| `test_erasure.py` | Reed-Solomon lossless round-trips for multiple payload sizes; genuine loss recovery (any k of k+p chunks, including parity-only subsets); out-of-order delivery. |
| `test_braid.py` | Component tests: KDF determinism, HMAC key rotation, authenticator ratchet (init/update/verify, forged-MAC rejection); message serialisation round-trips (`HDR`, `EK`, `CT1`, `CT2`, `NONE`); wire transport helpers. |
| `test_server_testnet.py` | FastAPI server endpoints: `/health`, `POST /register`, `GET /keys`, `GET/POST /messages`; full end-to-end testnet via `run_testnet()`; multi-device registration; authenticated registration proof rejection. |
| `test_decentralized_records.py` | Canonical `SignedRecord` signing/verification, strict wire parsing, replay/order checks, and signed contact request/accept/deny/cancel state derivation. |
| `test_decentralized_descriptors.py` | Username, relay, and contact-event descriptor body serialization and immutability. |
| `test_opk_leases.py` | OPK lease state transitions, expiry, duplicate-add rejection, replay prevention, and immutable OPK public material. |
| `test_crypto_provider.py` | Research crypto-provider HKDF/AES-GCM round-trip, nonce validation, AD failure, and randomness-size checks. |
| `test_decentralized_services.py` | Verified signed-record registry, username uniqueness/body validation, opaque mailbox semantics, feature-gated FastAPI `/v1/records` routes. |
| `test_anonymous_circuits.py` | 3-hop AES-GCM circuit layering, circuit-bound nonces, wrong-key/order failures, AD tamper rejection, and fixed-size padding. |
| `test_anonymous_transport.py` | Mandatory entry/middle/exit route validation, direct-P2P disablement, padded encrypted frame sending, circuit-frame API metadata rejection, queue isolation/drain behavior. |
| `test_federated_relays.py` | Federated relay peer registration and opaque cross-relay mailbox forwarding with mutation isolation. |
| `test_rendezvous.py` | Relay-only rendezvous streams, two-stream limit, no peer addresses, no sender echo, stream immovability, deterministic unknown-stream errors. |
| `test_client_vault.py` | Client-owned identity/session/contact vault behavior plus `VaultBackedClient` identity persistence. |
| `test_decentralized_integration.py` | Cross-relay opaque message preservation and existing E2EE chat with decentralized routes enabled. |
| `test_decentralized_docs.py` | Documentation and decentralized formal-model scaffold presence checks. |
| `test_security_fixes.py` | Regression tests for all 9 adversarial-review findings: initiator identity binding rejection, IK-misbinding rejection, OPK replay rejection, transactional ratchet, authenticated registration, token-derived sender, session-reset defence, multi-party key isolation. |
| `test_websocket_transport.py` | `/ws` rejects bad tokens (close 1008); WS-to-WS push with token-derived sender; HTTP-to-WS push; mailbox flush on connect; `Transport` protocol conformance; `WebSocketTransport.fetch()` via `push()`; `BraidChatClient` over WS send + HTTP poll. |
| `test_integration_scenarios.py` | Session lifecycle (state-machine progression, epoch-1 convention); multi-epoch agreement (5 epochs, keys match and are distinct); many chat messages (≥10, alternating direction); bidirectional chat; multi-device user (mailbox isolation); transport parity; robustness (duplicate chunk tolerance, wrong-epoch chat dropped gracefully). |
| `test_store_backends.py` | Behavioral parity of `SesameStore` (in-memory) and `SqliteStore` run as one parametrized suite; identity-key pinning, OPK consumption, mailbox isolation; SQLite persistence across reopen; `created_at` stability vs `last_seen`. |
| `test_tls.py` | Self-signed x509 generation (CN/SAN/self-signed/validity); fingerprint pinning that **rejects a mismatched cert** (socketpair handshake + live uvicorn round-trip); server/client SSL contexts; mTLS context + missing-CA guard; enforcement middleware (426 on plaintext, HSTS, `/health` exempt, off by default). |
| `test_double_ratchet.py` | A/B round-trip (exact plaintext both directions); distinct per-message keys; out-of-order and dropped-message handling via the skip cache; **forged message does not evict a cached key**; multi-epoch; tamper rejection without state corruption; `MAX_SKIP` bound. |

The canonical fidelity proof is:
```
tests/test_kem.py::test_split_equals_reference_monolithic[ML-KEM-512]
tests/test_kem.py::test_split_equals_reference_monolithic[ML-KEM-768]
tests/test_kem.py::test_split_equals_reference_monolithic[ML-KEM-1024]
```
These force the same 32-byte message `m` through both the Braid split and
`kyber-py`'s own `_encaps_internal`, then assert `ct1 ‖ ct2 == ref_c`. A
divergence here would mean the split is not real ML-KEM.

---

## 10. References

- [ML-KEM Braid specification](https://signal.org/docs/specifications/mlkembraid/) — Signal
- [PQXDH specification](https://signal.org/docs/specifications/pqxdh/) — Signal
- [Sesame specification](https://signal.org/docs/specifications/sesame/) — Signal
- [NIST FIPS 203 (ML-KEM)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) — NIST

---

## License

MIT — research and educational use.
