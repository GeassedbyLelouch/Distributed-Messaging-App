# PROJECT_STATE.md — Python Reference Implementation Snapshot

> **Purpose:** Accurate snapshot of the current Python codebase for a reader
> (or a future Rust rewrite team) who needs to know exactly what exists, what
> quality claims are defensible, and what remains to be done.
>
> **Date recorded:** 2026-06-29  
> **Test suite verdict (uv run pytest -q):** **446 passed, 3 warnings, 20.04 s**  
> **No test failures; warnings are deprecation notices in third-party libraries,
> not in ml\_kem\_braid code.**

---

## 1. Module map of `ml_kem_braid/`

Each sub-package is listed with its file(s) and a one-line description of what
the code actually does (not what it says it intends to do).

### 1.1 `core/` — cryptographic primitives

| File | What it does |
|------|--------------|
| [`core/ml_kem.py`](../ml_kem_braid/core/ml_kem.py) | Wraps `kyber-py` to expose the Braid-specific **incremental encapsulation** interface: `keygen()` → `KeyPair`; `encaps1(ek_seed, hek)` → `(EncapsulationSecret, ct1, ss)`; `encaps2(secret, ek_seed, ek_vector)` → `ct2`; `decaps(dk, ct1, ct2)` → `ss`. All three ML-KEM security levels (512/768/1024) supported via `MLKEMVariant`. |
| [`core/kdf.py`](../ml_kem_braid/core/kdf.py) | Hand-rolled HKDF-SHA256 (extract + expand per RFC 5869). `KDF` class exposes `kdf_ok(ss, epoch)` and `kdf_auth(root, key, epoch)` with the exact info strings `PROTOCOL_INFO + ":SCKA Key" + i8(epoch)` and `PROTOCOL_INFO + ":Authenticator Update" + i8(epoch)`. Default `PROTOCOL_INFO = "MLKEMBraid_MLKEM768_HMAC-SHA256"`. |
| [`core/authenticator.py`](../ml_kem_braid/core/authenticator.py) | Ratcheted HMAC-SHA256 authenticator. `init(e, key)` sets `root = 0x00^32` then calls `update`. `update(e, key)` derives `(root', mac_key)` via `kdf_auth`. `mac_header` / `mac_ciphertext` compute `HMAC(mac_key, PROTOCOL_INFO + label + i8(e) + data)`. **`update_and_verify_ciphertext`** is transactional: derives candidate keys, verifies the ciphertext MAC under the candidate, and only commits state on success — a forged ciphertext cannot corrupt the ratchet. |
| [`core/aead.py`](../ml_kem_braid/core/aead.py) | AES-256-GCM (via `cryptography` library). `aead_encrypt(key, pt, ad)` → `nonce ‖ ct ‖ tag`; `aead_decrypt` → `pt` or raises `InvalidTag`. Fresh 96-bit random nonce per message. No hand-rolled crypto. |
| [`core/double_ratchet.py`](../ml_kem_braid/core/double_ratchet.py) | Signal-style Double Ratchet layered over the SCKA epoch keys. `ratchet_epoch(e, k_e)` advances the root key via `KDF_RK(rk, k_e) = HKDF(ikm=k_e, salt=rk, info=b"MLKEMBraid-DR-root", 64)` and splits the chain seed into directional chains (`"A->B"` / `"B->A"`). `encrypt` / `decrypt` use Signal's `KDF_CK`: `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`. Out-of-order messages buffered in `_skipped[(epoch, index)]` up to `MAX_SKIP = 1000`. **Verify-before-evict**: on both the skipped-key path and the chain-walk path, AEAD verification precedes any state mutation. |
| [`core/provider.py`](../ml_kem_braid/core/provider.py) | Research/development crypto-provider wrapper exposing OS randomness, HKDF-SHA256 via `cryptography`, and AES-GCM encrypt/decrypt with 96-bit nonce validation. This is an abstraction seam for later FIPS/verified primitive providers, not a production certification claim. |

### 1.2 `encoding/` — erasure coding

| File | What it does |
|------|--------------|
| [`encoding/erasure.py`](../ml_kem_braid/encoding/erasure.py) | Systematic Reed-Solomon erasure code over GF(2⁸) via `reedsolo`. `Encoder(message)` streams data chunks `0..k-1` then parity chunks `k..k+p-1`. `Decoder.new(size)` accepts any `k`-of-`(k+p)` chunks (in any order) and reconstructs the message. Column-wise RS encoding across chunk bytes. GF(2⁸) bounds total symbols to ≤255 (sufficient: ML-KEM-1024 `ct1` is the largest object at 1408 B → 44 data chunks). Spec recommends GF(2¹⁶); this is a real trade-off, documented in the module. |

### 1.3 `protocol/` — Braid SCKA state machine

| File | What it does |
|------|--------------|
| [`protocol/messages.py`](../ml_kem_braid/protocol/messages.py) | `MessageType` enum (`NONE=0, HDR=1, EK=2, EK_CT1_ACK=3, CT1_ACK=4, CT1=5, CT2=6`). `Message` dataclass with `(epoch: int, type: MessageType, data?: bytes)`. Binary wire format: `[epoch: 8B big-endian][type: 1B][data_len: 2B big-endian][data]`. Factory helpers `msg_none/msg_header/msg_ek/msg_ek_ct1_ack/msg_ct1/msg_ct2`. |
| [`protocol/states.py`](../ml_kem_braid/protocol/states.py) | 11-state abstract state machine. Two groups: EK-transmit side (`KeysUnsampled → KeysSampled → HeaderSent → Ct1Received → EkSentCt1Received`) and CT-transmit side (`NoHeaderReceived → HeaderReceived → Ct1Sampled → EkReceivedCt1Sampled ↔ Ct1Acknowledged → Ct2Sampled`). Each state holds the minimum private data needed for its phase (e.g. `EkSentCt1Received` holds `dk, ct1, ct2_decoder`). `EkSentCt1Received.receive` calls `auth.update_and_verify_ciphertext` transactionally and emits `(epoch, k_e)` on success. `HeaderReceived.send` calls `encaps1` and emits a key on the CT-transmit side. |
| [`protocol/braid.py`](../ml_kem_braid/protocol/braid.py) | `MLKEMBraid` dataclass orchestrating the state machine. `send()` → `(Message, sending_epoch, OutputKey)`; `receive(msg)` → `(receiving_epoch, OutputKey)`. Epoch counter incremented on transitions to `NoHeaderReceived` (with a key) or `KeysUnsampled` (from `Ct2Sampled`). `run_exchange(alice, bob, target_epochs)` helper drives a synchronous in-process exchange for tests. |

### 1.4 `pqxdh/` — PQXDH initial handshake

| File | What it does |
|------|--------------|
| [`pqxdh/pqxdh.py`](../ml_kem_braid/pqxdh/pqxdh.py) | Implements the Signal PQXDH key agreement. Identity = Ed25519 signing key + X25519 DH key (intentional deviation from XEdDSA: documented in module). `create_prekey_bundle` generates signed SPK (X25519), signed PQSPK (ML-KEM-1024), and OPKs. `initiator_handshake`: verifies all bundle signatures, computes DH1–DH4 + ML-KEM encapsulation, derives `SK = HKDF(F ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss, salt=0x00^32, info=PQXDH_INFO ‖ IK_A ‖ IK_B, L=32)`. `responder_handshake`: verifies initiator `ik_dh_sig`, recomputes `SK`, **deletes the OPK** (single-use). |

### 1.5 `sesame/` — relay store

| File | What it does |
|------|--------------|
| [`sesame/base.py`](../ml_kem_braid/sesame/base.py) | Abstract base class `StoreBackend` defining the six-method interface: `register_device`, `get_account`, `list_devices`, `get_device`, `device_for_token`, `take_prekey_bundle`, `deliver`, `fetch_mailbox`, `pending_count`. |
| [`sesame/store.py`](../ml_kem_braid/sesame/store.py) | Thread-safe in-memory implementation `SesameStore`. Accounts pinned to `identity_key` on first registration (`PermissionError` on key mismatch). OPKs consumed atomically via `take_prekey_bundle`. Mailbox is a `deque`. Auth tokens are `secrets.token_urlsafe(24)`. |
| [`sesame/sqlite_store.py`](../ml_kem_braid/sesame/sqlite_store.py) | Durable `SqliteStore` implementing `StoreBackend`. WAL journal mode. `take_prekey_bundle` and `fetch_mailbox` (with drain) are wrapped in explicit `BEGIN` / `COMMIT` / `ROLLBACK` transactions. Schema: `accounts`, `devices`, `one_time_prekeys`, `mailbox`. |

### 1.6 `server/` — FastAPI relay

| File | What it does |
|------|--------------|
| [`server/app.py`](../ml_kem_braid/server/app.py) | FastAPI application with endpoints: `POST /register` (verifies Ed25519 possession proof over `registration_challenge(username, reg_id)`), `GET /keys/{username}`, `GET /keys/{username}/{device_id}` (atomically consumes one OPK), `POST /messages` (auth-token-derived sender identity), `GET /messages` (drain mailbox), `WS /ws?token=` (real-time push). `_TLSEnforcementMiddleware` (enabled via `enforce_tls=True`) rejects plaintext HTTP with 426 and adds HSTS. Sender identity on every path is derived from the bearer token — never the request body. WebSocket on-connect flushes the persistent mailbox so no envelopes are lost. `BRAID_STORE_PATH` env var selects SQLite; `BRAID_TLS_CERT/KEY/CLIENT_CA` enable TLS/mTLS. |
| [`server/decentralized_routes.py`](../ml_kem_braid/server/decentralized_routes.py) | Feature-gated decentralized API included by `create_app(enable_decentralized=True)`: `POST/GET /v1/records` for signed username records and `POST/GET /v1/circuits/{circuit_id}/frames` for opaque anonymous circuit frames. The circuit endpoint recursively rejects identity/auth metadata and drains per-circuit queues. |

### 1.7 `client/` — chat client

| File | What it does |
|------|--------------|
| [`client/transport.py`](../ml_kem_braid/client/transport.py) | `Transport` typing.Protocol (five methods: `register`, `list_devices`, `get_bundle`, `send`, `fetch`). `HttpTransport` (thin `httpx.Client` wrapper). `WebSocketTransport` (delegates REST to HTTP, uses WS for `send`/`fetch`; passive design: never blocks on `receive_json` internally). `tls_http_client` factory builds an `httpx.Client` with cert-pinned SSL context. |
| [`client/client.py`](../ml_kem_braid/client/client.py) | `BraidChatClient` drives the full lifecycle: `register()` → `start_session(peer)` → `pump_session()` → `send_chat()` / `poll()`. `BraidSession` holds `braid: MLKEMBraid` + `ratchet: DoubleRatchet`; `record_key` advances both. `send_chat` uses Double Ratchet `encrypt` with AD `"{sender}:{dev}->{recipient}:{dev}"`. `poll` dispatches `pqxdh_init` / `braid` / `chat` envelopes; malformed/forged envelopes are dropped individually (logged to `client.dropped`), the rest of the batch continues. `run_until_agreed` helper drives two in-process clients. |
| [`client/anonymous_transport.py`](../ml_kem_braid/client/anonymous_transport.py) | Anonymous-mode client wrapper that requires the role route `entry -> middle -> exit`, rejects any direct peer endpoint, pads payloads to 1024 bytes, wraps them in 3-hop AES-GCM circuit frames, and delegates to a `CircuitGateway`. Current keys are explicitly development-only placeholders pending negotiated per-hop keys. |
| [`client/vault_client.py`](../ml_kem_braid/client/vault_client.py) | Minimal wrapper that persists identity secrets into an `InMemoryClientVault` under the client's username. |

### 1.8 `decentralized/` — anonymous decentralized delivery primitives

| File | What it does |
|------|--------------|
| [`decentralized/canonical.py`](../ml_kem_braid/decentralized/canonical.py) | Deterministic canonical JSON and SHA-256 helpers used by signed records. Rejects non-finite JSON numbers. |
| [`decentralized/records.py`](../ml_kem_braid/decentralized/records.py) | Immutable canonical `SignedRecord` model, Ed25519 signing/verification, strict wire parsing, and signed contact request/accept/deny/cancel log derivation with replay/order guards. |
| [`decentralized/descriptors.py`](../ml_kem_braid/decentralized/descriptors.py) | Dataclasses for username records, relay descriptors, and contact-event bodies. |
| [`decentralized/opk.py`](../ml_kem_braid/decentralized/opk.py) | OPK lease store with `available -> leased -> consumed` / `expired` transitions, lease expiry checks, duplicate-add rejection, and immutable OPK public material. |
| [`decentralized/vault.py`](../ml_kem_braid/decentralized/vault.py) | In-memory client-owned vault for identity secrets, session state, and per-conversation signed contact logs with defensive copies. |
| [`decentralized/services.py`](../ml_kem_braid/decentralized/services.py) | Verified signed-record registry, username uniqueness/body validation, opaque mailbox delivery/fetch, and minimal `FederatedRelay` forwarding to remote home relays. |
| [`decentralized/circuits.py`](../ml_kem_braid/decentralized/circuits.py) | Circuit frame dataclasses, 3-hop AES-GCM onion layering with circuit-bound deterministic nonces, AD binding, and fixed-size payload padding/unpadding. |
| [`decentralized/rendezvous.py`](../ml_kem_braid/decentralized/rendezvous.py) | Relay-only two-stream rendezvous primitive that forwards opaque bytes between streams and never stores or returns peer network addresses. |

### 1.9 `testnet/` — end-to-end demo

| File | What it does |
|------|--------------|
| [`testnet/demo.py`](../ml_kem_braid/testnet/demo.py) | `run_testnet()` boots the FastAPI app in-process (no socket), registers Alice and Bob, runs PQXDH, pumps the Braid SCKA to agreement, sends a real AES-256-GCM-encrypted chat message, and verifies decryption. Can be run as `uv run braid-testnet`. Returns a `TestnetResult` dataclass used by `test_server_testnet.py`. |

### 1.10 `transport/` — low-level HTTP/WS utilities

| File | What it does |
|------|--------------|
| [`transport/http_client.py`](../ml_kem_braid/transport/http_client.py) | `BraidHttpClient` (async + sync httpx wrapper around the Braid message wire format). `InMemoryTransport` (two-queue in-process transport for unit tests). `serialize_for_wire` / `deserialize_from_wire` (thin wrappers over `Message.to_bytes()` / `from_bytes()`). This module predates `client/transport.py`; the latter is what `BraidChatClient` actually uses. |

### 1.11 Top-level modules

| File | What it does |
|------|--------------|
| [`wire.py`](../ml_kem_braid/wire.py) | JSON serialisation helpers shared by client and server: `b64e/b64d`, `registration_challenge`, `bundle_to_dict/from_dict`, `initial_message_to_dict/from_dict`, `braid_message_to_dict/from_dict`. |
| [`tls.py`](../ml_kem_braid/tls.py) | Self-signed EC P-256 certificate generation (`generate_self_signed_cert`), cert fingerprinting (`cert_fingerprint`), server SSL context builder (supports mTLS), client SSL context builder (libsignal-style cert pinning — replaces system CA store with a single pinned cert), `generate_dev_certs` convenience function for testnet. Key files written mode `0o600`. |

---

## 2. Reference-quality vs. scaffold

### 2.1 Reference-quality (real crypto, real protocol logic)

**FIPS-203 ML-KEM via `kyber-py`**  
`ml_kem_braid/core/ml_kem.py` does not implement any lattice arithmetic from
scratch. Every operation — matrix expansion, CBD sampling, NTT, compression,
encoding, the FO transform, and implicit rejection — is performed by
`kyber_py`'s own primitives. The Braid module only reorders the standard
`encaps` computation into two phases. The fidelity test (§3 below) proves
byte-for-byte identity with the library's own monolithic ciphertext.

**PQXDH handshake**  
Ed25519 signing, X25519 DH, ML-KEM-1024 encapsulation, HKDF-SHA256 — all via
the `cryptography` library. Bundle signature verification is complete (three
`Ed25519PublicKey.verify` calls). OPK single-use enforcement (KeyError on
replay). Identity binding in the KDF `info` field (both signing keys concatenated).

**Real Reed-Solomon erasure coding**  
`reedsolo` library, GF(2⁸). Column-wise systematic RS. Lossless roundtrip and
genuine loss recovery are both tested with real chunk drops.

**AES-256-GCM**  
`cryptography.hazmat.primitives.ciphers.aead.AESGCM` — no hand-rolled crypto.
Fresh random 96-bit nonce per message.

**FastAPI relay with HTTP + WebSocket transports**  
Full FastAPI app with Pydantic request/response models, Bearer token auth,
real WebSocket push, TLS middleware (426 enforcement + HSTS headers).

**SQLite store with transactional atomicity**  
`take_prekey_bundle` and `fetch_mailbox` use explicit transactions; the
in-memory store uses `threading.RLock`.

**TLS with cert pinning and mTLS**  
`tls.py` implements the libsignal-style trust model (bypass CA store, pin one
self-signed cert). Server SSL context supports mTLS via client CA verification.

### 2.2 Scaffold / not production-hardened

- **`kyber-py` is a pure-Python reference implementation and is not
  constant-time.** Timing side channels are possible. This is explicitly called
  out in the PROTOCOL_SPEC and the module's own docstring. For production use
  the Rust rewrite must use a constant-time ML-KEM implementation (e.g. libcrux,
  HACL\*, or pqcrypto-kyber via libpqcrypto). See §5.

- **Hand-rolled HKDF in `core/kdf.py`.** Uses `hmac.new` (from stdlib) which
  is not constant-time against the `key` argument on all platforms. For
  production, use `cryptography.hazmat.primitives.kdf.hkdf.HKDF`.

- **No third-party audit.** The implementation has undergone one internal
  adversarial review (see §4) but no independent security audit.

- **No rate limiting or DoS protection.** The FastAPI server has no request
  rate limiting, mailbox size cap, or connection-count limits. These are
  necessary before public deployment.

- **In-memory store is the default.** `SesameStore` loses all data on process
  restart. `SqliteStore` persists but has no migration mechanism for schema
  changes.

- **`BraidServer` class in `transport/http_client.py`** is a stub with no
  actual network listener; it is not used by any production path.

- **Envelope `envelope_id` is a simple counter** (`env-1`, `env-2`, …) rather
  than a UUID. Replayable across server restarts if the counter resets.

- **Client session persistence is still development-only.** `InMemoryClientVault`
  stores identity, session, and contact-log material for tests and local flows,
  but production still needs an encrypted durable vault plus explicit
  `DoubleRatchet` / `MLKEMBraid` state migration and recovery semantics.

---

## 3. Test suite

**Total: 446 passed** (as of `uv run pytest -q` on 2026-06-29).

To run: `uv run pytest` (from the project root). Requires the dev dependencies
(`uv sync`; `pyproject.toml` lists `pytest>=8.0.0`).

### 3.1 Per-module breakdown

| Test file | Count | Description |
|-----------|------:|-------------|
| [`tests/test_store_backends.py`](../tests/test_store_backends.py) | 94 | Parametrized (`memory` / `sqlite`) behavioural tests for both store backends: registration, identity-key pinning, OPK consumption, mailbox deliver/fetch/drain, pending count, SQLite persistence across reopen. |
| [`tests/test_tls.py`](../tests/test_tls.py) | 33 | Certificate generation (parseable, correct CN/SANs, self-signed), fingerprinting (stable, changes on cert change), SSL context construction (plain TLS + mTLS), `generate_dev_certs` file creation, key-file permission `0o600`, TLS enforcement middleware (426 on plain HTTP, HSTS header, `/health` exempt), live uvicorn TLS round-trip with correct and wrong pin. |
| [`tests/test_double_ratchet.py`](../tests/test_double_ratchet.py) | 33 | A↔B round-trip, per-message key distinctness, out-of-order (indices 2,0,1), dropped message (cached then pruned), multi-epoch (≥3 epochs), tamper rejection (modified ct + wrong AD), `MAX_SKIP` refusal, full integration (two `BraidChatClient`s over a test server, exact plaintext round-trip). |
| [`tests/test_anonymous_circuits.py`](../tests/test_anonymous_circuits.py) | 27 | 3-hop circuit frame layering, circuit-bound nonce derivation, wrong-order/key/tag failures, AD tamper rejection, duplicate/missing hop validation, and fixed-size padding. |
| [`tests/test_anonymous_transport.py`](../tests/test_anonymous_transport.py) | 26 | Anonymous transport route validation, direct-P2P disablement, padded encrypted frame sending, sequence no-reuse, circuit IDs, gateway propagation, and circuit-frame API metadata rejection/drain behavior. |
| [`tests/test_decentralized_services.py`](../tests/test_decentralized_services.py) | 25 | Verified signed-record registry, username uniqueness/body validation, opaque mailbox semantics, decentralized record routes, route gating, and error mappings. |
| [`tests/test_integration_scenarios.py`](../tests/test_integration_scenarios.py) | 23 | Session lifecycle, multi-epoch (5 epochs, keys match and are distinct), ≥10 chat messages alternating direction, bidirectional chat, multi-device user (mailbox isolation), transport parity (`HttpTransport` + WS send), robustness (duplicate chunk, wrong-epoch chat dropped gracefully). |
| [`tests/test_contacts_api.py`](../tests/test_contacts_api.py) | 19 | Username lookup and contact request/accept/deny/delete API behavior, including confirmation/denial flow and UI-compatible registration paths. |
| [`tests/test_decentralized_records.py`](../tests/test_decentralized_records.py) | 18 | Canonical signed-record verification, strict wire parsing, immutable bodies, and signed contact event state derivation with malformed/replay handling. |
| [`tests/test_usernames.py`](../tests/test_usernames.py) | 18 | Username validation, normalization, hash/display behavior, and duplicate/case-sensitive uniqueness constraints. |
| [`tests/test_braid.py`](../tests/test_braid.py) | 15 | KDF output lengths and domain separation, authenticator init/update/verify/clone, MAC failure rejection, message type `has_payload`, wire serialisation round-trip, transport `InMemoryTransport`/`serialize_for_wire`/`deserialize_from_wire`. |
| [`tests/test_erasure.py`](../tests/test_erasure.py) | 13 | Lossless roundtrip (7 sizes: 64–1408 B), genuine loss recovery (4 sizes, up to `parity_chunks` drops in random order), encoder iteration, chunk index boundaries. |
| [`tests/test_security_fixes.py`](../tests/test_security_fixes.py) | 11 | Security regression tests for the 9-finding adversarial review (see §4). |
| [`tests/test_rendezvous.py`](../tests/test_rendezvous.py) | 11 | Relay-only rendezvous stream pairing, no peer addresses, stream immovability, no sender echo, two-stream limit, memoryview copying, and deterministic unknown-stream errors. |
| [`tests/test_kem.py`](../tests/test_kem.py) | 10 | Key size validation for all three variants, `encaps1/encaps2/decaps` round-trip, **`test_split_equals_reference_monolithic`** (canonical fidelity test — see §3.2), implicit rejection on tampered ciphertext, `hek_for` consistency, deterministic keygen. |
| [`tests/test_client_vault.py`](../tests/test_client_vault.py) | 9 | In-memory vault identity/session/contact-log behavior, malformed contact-record rejection, bytes-only identity inputs, and `VaultBackedClient` persistence. |
| [`tests/test_federated_relays.py`](../tests/test_federated_relays.py) | 9 | Federated relay forwarding, unknown relay handling, mutation isolation, duplicate peer replacement, self-peering, and invalid peer/envelope behavior. |
| [`tests/test_opk_leases.py`](../tests/test_opk_leases.py) | 9 | OPK lease double-lease prevention, expiry, invalid TTLs, duplicate-add no-reset behavior, consumption replay prevention, and immutable bytes validation. |
| [`tests/test_websocket_transport.py`](../tests/test_websocket_transport.py) | 8 | WS token rejection (close 1008), WS-to-WS push (sender from token), HTTP-to-WS push, mailbox flush on connect, `Transport` protocol isinstance check, `WebSocketTransport.fetch()`, WS send + HTTP poll round-trip. |
| [`tests/test_braid_protocol.py`](../tests/test_braid_protocol.py) | 7 | Initial states, key agreement across all three ML-KEM variants (parametrized), multi-epoch agreement, mismatched preshared secret, forged ciphertext MAC halts session. |
| [`tests/test_server_testnet.py`](../tests/test_server_testnet.py) | 6 | FastAPI health endpoint, register + bundle fetch, SQLite backend end-to-end, `run_testnet` demo (chat round-trip), invalid auth rejection, unknown recipient rejection. |
| [`tests/test_pqxdh.py`](../tests/test_pqxdh.py) | 6 | Full handshake with OPK, handshake without OPK, bundle signature verification (tampered SPK, tampered PQSPK), AEAD encrypt/decrypt using derived `SK`, wire roundtrip (bundle/initial-message dict serialisation). |
| [`tests/test_crypto_provider.py`](../tests/test_crypto_provider.py) | 6 | Research provider HKDF/AES-GCM round-trip, nonce-shape validation, AD authentication failure, random-size behavior, and invalid length checks. |
| [`tests/test_decentralized_descriptors.py`](../tests/test_decentralized_descriptors.py) | 5 | Username, relay, and contact-event descriptor serialization and immutable endpoint storage. |
| [`tests/test_decentralized_docs.py`](../tests/test_decentralized_docs.py) | 3 | README/protocol documentation assertions and decentralized formal-model scaffold presence checks. |
| [`tests/test_decentralized_integration.py`](../tests/test_decentralized_integration.py) | 2 | Cross-relay opaque envelope preservation and existing E2EE chat with decentralized routes enabled. |

### 3.2 Canonical fidelity test

`tests/test_kem.py::test_split_equals_reference_monolithic[ML-KEM-{512,768,1024}]`

For each variant, generates a `kyber-py` keypair, calls `encaps1(ek_seed, hek, m=fixed_m)` and `encaps2(es, ek_seed, ek_vector)`, then calls `kyber-py`'s own `_encaps_internal(ek, m)` with the same `m` and asserts:

```python
assert ct1 + ct2 == ref_c   # byte-for-byte identity
assert ss == ref_K           # shared secret matches
assert ref.decaps(dk, ct1 + ct2) == ss  # standard decaps recovers it
```

This is the key lemma for the IND-CCA reduction claimed in the protocol spec: the Braid incremental ciphertext is identical to the standard FIPS-203 ciphertext, so breaking Braid's KEM requires breaking ML-KEM. The formal EasyCrypt proof of this lemma is a TODO (see `formal/easycrypt/`).

---

## 4. Security hardening history

The implementation underwent a structured adversarial review that produced 9
findings. All 9 were addressed. Regression tests for each live in
[`tests/test_security_fixes.py`](../tests/test_security_fixes.py).

### 4.1 Finding #1/#2 — PQXDH identity binding (UKS resistance)

**Finding:** The initial implementation derived `SK` from DH outputs + the KEM
shared secret alone. A man-in-the-middle could substitute its own identity
without detection (unknown-key-share attack).

**Fix:** Both parties' Ed25519 signing-key public bytes are concatenated into the
HKDF `info` field:
```
info = PQXDH_INFO + ik_sign_A + ik_sign_B
```
This binds the derived secret to the specific pair of identities.

**Tests:** `test_responder_rejects_unbound_initiator_dh_key`,
`test_sk_bound_to_identities`.

### 4.2 Finding #3 — OPK single-use / replay prevention

**Finding:** One-time prekeys were not deleted on use, allowing a replayed
`InitialMessage` to re-derive the same `SK`.

**Fix:** `responder_handshake` calls `del secrets.opk_priv[message.opk_id]`
after use. A second call with the same `opk_id` raises `KeyError`.

**Test:** `test_one_time_prekey_consumed_blocks_replay`.

### 4.3 Finding #4 — Transactional authenticator ratchet

**Finding:** The authenticator's `update` method mutated state before verifying
the ciphertext MAC. A forged ciphertext whose decapsulation succeeded (returning
a garbage shared secret) would corrupt the authenticator's long-term root key.

**Fix:** `update_and_verify_ciphertext` derives candidate `(root', mac_key)`,
verifies the MAC under the candidate, and only commits state on success. A
failed verification leaves the authenticator untouched and halts the session.

**Test:** `test_failed_ciphertext_mac_does_not_mutate_authenticator`.

### 4.4 Finding #5 — Erasure decoder robustness

**Finding:** The erasure decoder accepted chunks without bounds checking, so an
attacker sending a chunk with `index >= total_chunks` could insert data into the
wrong position.

**Fix:** `Decoder.add_chunk` silently drops chunks with `index >= total_chunks`
or wrong `len(chunk.data)`.

**Test:** `test_erasure_rejects_too_many_chunks`.

### 4.5 Finding #6 — Authenticated server registration

**Finding:** Any client could register any username without proving it held the
corresponding identity key, enabling username hijacking.

**Fix:** `POST /register` now requires `proof_sig`: an Ed25519 signature over
`registration_challenge(username, registration_id) =
b"MLKEMBraid-register:{username}:{registration_id}"`. The server verifies this
against `bundle.ik_sign_pub` before storing the device.

**Test:** `test_registration_requires_valid_proof`.

### 4.6 Finding #7 — Username pinning to identity key (TOFU)

**Finding:** A second registration for an existing username could supply a
different identity key, hijacking the mailbox.

**Fix:** `SesameStore.register_device` and `SqliteStore.register_device` check
the stored `identity_key` on subsequent registrations and raise `PermissionError`
on mismatch. The server maps this to HTTP 403.

**Test:** `test_username_pinned_to_identity_key`.

### 4.7 Finding #8 — Token-derived sender identity

**Finding:** The `POST /messages` endpoint originally accepted `sender_username`
and `sender_device_id` from the request body, allowing any authenticated device
to spoof any other device as the envelope sender.

**Fix:** Sender identity is resolved exclusively from the bearer token
(`auth_device` dependency). The request body `SendMessageRequest` has no sender
fields. The WebSocket handler does the same (sender = connection token, not frame
body).

**Tests:** `test_messages_endpoint_requires_auth`,
`test_sender_derived_from_token_not_body`.

### 4.8 Finding #9 — Resilient batch processing in `poll()`

**Finding:** A single malformed or forged envelope in a mailbox batch would
raise an exception and silently discard the remaining valid envelopes.

**Fix:** `BraidChatClient.poll()` wraps each envelope's dispatch in a
`try/except`; a failed envelope is appended to `client.dropped` and processing
continues with the next envelope.

**Test:** `test_poll_drops_bad_envelope_keeps_batch`.

### 4.9 Additional per-feature hardening (post-review)

The following properties were added or strengthened during development:

| Property | Where | Notes |
|----------|-------|-------|
| **Verify-before-evict ratchet** | `core/double_ratchet.py` `decrypt` | Skipped-key cache: AEAD verification precedes `del self._skipped[key]`. Chain-walk path: all state updates deferred until after AEAD succeeds. Prevents a forged ciphertext from consuming a cached key or advancing the chain. |
| **WS at-least-once delivery** | `server/app.py` `_deliver_and_push` | If no live WebSocket socket successfully receives an envelope, it is written to the persistent mailbox. Prevents silent loss on transient socket failure. |
| **Registration ID upper bound** | `server/app.py` `RegisterRequest` | `Field(ge=0, lt=2**31)` on `registration_id` to prevent integer overflow edge cases. **Test:** `test_registration_id_upper_bound`. |
| **Directional AD binding in Double Ratchet** | `core/double_ratchet.py` `_header_bytes` | `full_ad = associated_data + b"hdr:" + i8(epoch) + i8(index)`. The header is bound into the AEAD additional data, preventing ct/header separation or replay across message positions. |
| **`ik_dh_sig` verification on both sides** | `pqxdh/pqxdh.py` | Initiator: `bundle.verify()` checks all three signatures (`ik_dh_sig`, `spk_sig`, `pqspk_sig`). Responder: verifies initiator's `ik_dh_sig` before computing any DH. Prevents an attacker from substituting a forged DH key while keeping the authentic Ed25519 identity. |
| **TLS enforcement middleware** | `server/app.py` | `enforce_tls=True` adds `_TLSEnforcementMiddleware`; `/health` exempt so load-balancer probes work. HSTS `max-age=63072000; includeSubDomains` on every response. |

---

## 5. Known limitations / not for production

1. **`kyber-py` is not constant-time.** The pure-Python lattice operations in
   `kyber-py` (NTT, compression, CBD sampling) are not constant-time with
   respect to secret values. Timing side channels against the KEM are a real
   concern on shared hardware. Do not use this implementation where an attacker
   can measure CPU timing. The Rust rewrite must use a constant-time backend
   (libcrux, HACL\*, or a pqcrypto binding to liboqs/pqclean with documented
   CT guarantees).

2. **Hand-rolled HKDF.** `core/kdf.py` re-implements HKDF-SHA256 from scratch
   using `hmac.new`. While the logic is correct and tested, NIST recommends
   using a validated implementation. The `cryptography` library's `HKDF` class
   is already a dependency and should replace this in any hardened deployment.

3. **No third-party security audit.** The codebase has been through one internal
   adversarial review (§4). An independent audit by a specialist firm is required
   before any production use, especially of the PQXDH and Double Ratchet layers.

4. **No rate limiting or DoS protection.** The FastAPI server accepts unbounded
   mailbox envelopes, unlimited registration attempts, and unlimited WebSocket
   connections. A real deployment needs per-IP rate limiting, mailbox size caps,
   and connection-count limits.

5. **In-memory default store.** `SesameStore` (the default) is ephemeral.
   `SqliteStore` persists but has no schema-migration mechanism; any schema
   change requires manual database recreation.

6. **No key rotation for long-term identities.** `IdentityKeyPair` has no
   rotation mechanism. Compromised signing or DH keys require re-registration
   (which the server currently blocks via identity-key pinning, so the user
   would need manual intervention).

7. **GF(2⁸) Reed-Solomon bound.** The protocol spec recommends GF(2¹⁶)
   erasure coding. The `reedsolo` implementation uses GF(2⁸), limiting total
   chunks to ≤255 per object. For ML-KEM-1024 this is sufficient (largest
   object: `ct1` = 1408 B → 44 data chunks with ~44 parity → 88 total, well
   under 255), but any future extension that increases chunk sizes would hit this
   limit.

8. **Envelope IDs are sequential counters.** `env-1`, `env-2`, etc. — not UUIDs.
   Counter resets on server restart, enabling potential envelope-ID collisions
   in persistent stores.

9. **Formal proofs are scaffolds, not completed verification.** The repository
   contains Verifpal, Tamarin, TLA+, and EasyCrypt-style artifacts under
   `formal/` and `ml_kem_braid/codex-proofs/`, including decentralized
   `SignedRecord` contact-event and OPK-lease scaffolds. They document proof
   obligations and model structure, but the prover toolchains were not installed
   locally and no formal verification result is claimed.

10. **Client state persistence is still incomplete.** `InMemoryClientVault` and
   `VaultBackedClient` demonstrate client-owned identity/session/contact-log
   state, but production needs an encrypted durable vault and migration path for
   Braid/Double-Ratchet state.

11. **`pq-vpn-braid/` Rust folder.** The repository contains a `pq-vpn-braid/`
    Rust subtree scoped to VPN-level packet forwarding. This is **not** a
    reimplementation of the chat protocol above and is slated for removal (see
    `docs/RUST_REWRITE.md`). Do not confuse it with the planned Rust rewrite of
    `ml_kem_braid/`.

---

## 6. Role of this Python repo as oracle for the Rust rewrite

The Python implementation is designed to serve as the **reference oracle** for
the Rust rewrite in the following ways:

### 6.1 Test vector generation

Every deterministic operation in the Python code accepts explicit seeds/inputs
and produces reproducible outputs:

- `MLKEM.keygen(seed=bytes(64))` — deterministic FIPS-203 key derivation.
- `MLKEM.encaps1(ek_seed, hek, m=fixed_bytes)` + `encaps2` — reproducible
  `ct1`, `ct2`, `ss` for a given `m` and key.
- `KDF.kdf_ok(ss, epoch)` and `kdf_auth(root, key, epoch)` — deterministic
  HKDF with known inputs.
- `aead_encrypt(key, pt, ad)` — deterministic with a fixed nonce (the nonce
  is currently random; to generate test vectors, pass a patched version with a
  fixed 12-byte nonce).
- `DoubleRatchet.ratchet_epoch(e, k_e)` followed by `encrypt` — deterministic
  chain steps (nonce is random; same caveat as AEAD).

**TODO (human):** Write a `scripts/gen_test_vectors.py` script that serialises
known-input / known-output pairs from each primitive to a JSON file that the
Rust test suite can load and assert against. This is the primary tool for
detecting protocol-level divergences between Python and Rust.

### 6.2 Differential testing

The Python server (`create_app(SesameStore())`) can be run alongside the Rust
server in a differential harness:

1. Both servers register the same Alice and Bob (using the same identity keys
   and prekey bundles derived from fixed seeds).
2. The Python client executes a full PQXDH → Braid → chat sequence against the
   Python server.
3. The Rust client replays the same transcript against the Rust server.
4. Compare intermediate values (epoch keys, ratchet chain keys, AEAD outputs)
   at each step.

**TODO (human):** Design and implement the differential harness. The
`run_testnet()` function and `run_exchange()` are good entry points for this.

### 6.3 KDF label / format oracle

The PROTOCOL_SPEC.md and the Python code together define byte-exact wire
formats, KDF info strings, and message field layouts. The Rust implementation
must produce identical bytes for:

- The `registration_challenge` (`b"MLKEMBraid-register:{username}:{reg_id}"`),
  verified by the server in `POST /register`.
- Braid `Message` binary wire format (epoch 8B big-endian + type 1B +
  data\_len 2B big-endian + data).
- HKDF info strings: `PROTOCOL_INFO + ":SCKA Key" + epoch.to_bytes(8, "big")`,
  etc.
- Double Ratchet info: `b"MLKEMBraid-DR-root"`, `b"A->B"`, `b"B->A"`.
- AEAD associated data: `b"{s_user}:{s_dev}->{r_user}:{r_dev}" + b"hdr:" + epoch_8B + index_8B`.

**TODO (human):** Cross-check every constant string in `core/kdf.py`,
`core/double_ratchet.py`, `pqxdh/pqxdh.py`, `wire.py`, and `server/app.py`
against the PROTOCOL_SPEC before starting Rust implementation. Any discrepancy
between spec, Python code, and Rust code will silently produce different keys.

### 6.4 What the Rust rewrite must NOT take from this repo

- The `transport/http_client.py` `BraidHttpClient` / `BraidServer` classes
  are not used by the reference client and are effectively dead code; they
  should not be ported.
- The `pq-vpn-braid/` Rust folder is VPN-scoped, not chat-scoped; discard it.
- The hand-rolled HKDF in `core/kdf.py` should be replaced by a constant-time,
  audited crate (e.g. `hkdf` + `sha2` from the RustCrypto project).
- `kyber-py` internals (`_encaps_internal`, `_G`, `_H`, etc.) are implementation
  details of the reference; the Rust rewrite should call a stable ML-KEM API
  (e.g. `ml-kem` crate from RustCrypto, or `pqcrypto-kyber`).

---

## 7. Open TODOs a human must finish

The following items are explicitly **not** complete and require human judgment or
significant implementation work:

1. **Test vector generation script** (`scripts/gen_test_vectors.py`). Needs
   deterministic seeds wired into every primitive; format TBD (JSON with hex
   bytes is conventional).

2. **Differential testing harness.** Design the Python–Rust co-execution
   framework. Decision needed: out-of-process (pipe/socket) vs. shared file
   vectors.

3. **Formal verification scaffolds.** `formal/easycrypt/` KEM split lemma,
   `formal/tamarin/` PQXDH + Double Ratchet models, `formal/tla+/` SCKA
   state-machine liveness. All are stubs per `PROTOCOL_SPEC.md §A`; a human
   must drive each tool to completion.

4. **Replace hand-rolled HKDF** with `cryptography.hazmat.primitives.kdf.hkdf.HKDF`
   for the hardened Python variant (or document explicitly that the hand-rolled
   version is only for the reference/oracle role).

5. **Session serialisation / persistence.** `DoubleRatchet` and `MLKEMBraid`
   state must be serialisable for the Rust rewrite (and for production Python
   use). Format TBD; must handle secret zeroisation on write.

6. **Key-material zeroisation.** Python does not guarantee memory zeroisation
   after GC; this is acceptable for the reference oracle but the Rust rewrite
   must `zeroize` all key material on drop.

7. **Rate limiting and mailbox size caps** in `server/app.py`.

8. **Sequential `envelope_id` counter.** Replace with `uuid.uuid4()` or a
   CSPRNG-derived identifier that survives server restarts without collision.

9. **GF(2¹⁶) erasure coding.** If the spec's recommendation is to be followed,
   `encoding/erasure.py` must be updated to a GF(2¹⁶) RS codec (currently no
   Python library with a production-quality GF(2¹⁶) RS is in common use;
   this may require a Rust extension or a custom implementation).

10. **OPK replenishment protocol.** The server notifies clients when OPK count
    is low (not yet implemented). Clients should upload fresh OPKs periodically.
    Without this the server will eventually serve bundles without OPKs, losing
    one-time prekey forward secrecy.
