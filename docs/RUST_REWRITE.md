# Rust Re-Implementation Plan — Replacing `pq-vpn-braid/`

> **Status: SCAFFOLD / PLAN.** This is a human-reviewed design document, not a
> completed implementation. Nothing here has been built, compiled, or verified.
> Every "verified-crypto" claim refers to *upstream* libraries' verification status,
> **not** to this project's code, which is unwritten. Search this file for `TODO`,
> `OPEN QUESTION`, and `RISK` markers for the work a human must still do.

This document specifies the plan to **delete the VPN-scoped Rust experiment
`pq-vpn-braid/`** (a WireGuard-style tunnel prototype) and replace it with a
**broad-scope, multi-platform Rust re-implementation of the ML-KEM Braid *chat*
protocol** — the same protocol implemented by the Python reference under
`ml_kem_braid/` and abstracted in [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md).

Targets: **iOS, Android (all mobile), a server/API, Linux desktop, Windows
desktop** (and macOS as a near-free byproduct of the iOS/desktop toolchains).

The normative source of truth for *what* must be re-implemented (KDF labels, salts,
DH assignments, wire fields, the four layers) is [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md).
Where a byte-exact detail is not restated there, the cited Python source file under
`ml_kem_braid/` is normative.

---

## 0. Status of `pq-vpn-braid/` (what is reused vs. discarded)

> **Observation (✓ VERIFIED, 2026-06-27):** at the time of writing, the directory
> `pq-vpn-braid/` **does not exist on disk** in this repository (`ls` returns
> "No such file or directory"). The task brief describes it as a "VPN-scoped Rust
> experiment ... currently a WireGuard-style tunnel prototype" to be replaced. This
> plan therefore treats it as either (a) not yet committed, (b) living on another
> branch, or (c) already removed. **TODO (human):** confirm where `pq-vpn-braid/`
> actually lives before deleting anything; if it is on a branch, port any reusable
> pieces per the table below, then remove it.

| Concern in (presumed) `pq-vpn-braid/` | Disposition | Rationale |
|---|---|---|
| WireGuard/tunnel transport, TUN device, packet routing | **DISCARD** | Out of scope. The new target is an E2EE *chat* protocol over HTTP/WS relay, not an IP tunnel. |
| Any datagram/Noise-style framing tied to the VPN | **DISCARD** | Replaced by the Sesame relay envelope model (§4 of spec). |
| Cargo workspace skeleton, CI config, `rustfmt`/`clippy` setup, `deny.toml` | **REUSE if present** | Tooling is protocol-agnostic; salvage to save setup time. |
| Any `libcrux`/`ml-kem`/RustCrypto wiring already done | **REUSE if present** | Crypto crate selection is directly relevant (see §3). |
| X25519/Ed25519/HKDF helper code | **REUSE cautiously** | Only if it already uses the crates in §3 and is constant-time; otherwise rewrite. |

If `pq-vpn-braid/` cannot be found, treat this as a **greenfield** Rust workspace
created at repo path `rust/` (proposed; see OPEN QUESTION below).

> **OPEN QUESTION (human):** new workspace root path. Options: (a) reuse the name
> `pq-vpn-braid/` (confusing — it is no longer a VPN); (b) `rust/`; (c) `braid-rs/`.
> This document assumes **`rust/`** as the workspace root. Pick one and rename.

---

## 1. Rationale & scope

### 1.1 Why rewrite in Rust at all

The Python reference (`ml_kem_braid/`) is an excellent **executable specification and
test oracle**, but it is unsuitable as a production client/server for three reasons,
all already acknowledged in `PROTOCOL_SPEC.md` §A ("Out of scope"):

1. **Not constant-time.** `PROTOCOL_SPEC.md` explicitly notes "kyber-py is **not**
   constant-time" and lists "timing/side channels" as out of model. A real client
   handling long-term identity keys on a possibly-hostile device (mobile) needs
   constant-time KEM, X25519, AEAD, and constant-time MAC/tag comparison. This is the
   single biggest correctness gap the Rust rewrite closes.
2. **No path to mobile.** Python does not ship to iOS/Android as a first-class E2EE
   crypto core. The industry-standard answer is exactly the **libsignal** model:
   one memory-safe Rust core, exposed to Swift and Kotlin via generated bindings.
3. **The model-to-code gap.** `PROTOCOL_SPEC.md` §A says this gap "is closed only by
   verified implementations — libcrux/HACL\*, DY\*/hax." A Rust core lets us (a) link
   the **formally verified** `libcrux-ml-kem` for the KEM primitive and (b) submit
   `braid-core` itself to **hax** (Rust → F\*/Coq) — tying into
   [`FORMAL_VERIFICATION.md`](FORMAL_VERIFICATION.md) (see §5).

### 1.2 Scope of the rewrite

**In scope** (full re-implementation, byte-exact to the spec):

- **Layer 1 — PQXDH handshake** (`PROTOCOL_SPEC.md` §1; ref `ml_kem_braid/pqxdh/pqxdh.py`):
  Ed25519 identity + X25519 identity/SPK/OPK, ML-KEM-1024 PQ prekey, the four DHs
  + KEM `ss`, and the exact `SK` HKDF (`ikm = 0xff^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss`,
  `salt = 0x00^32`, `info = "MLKEMBraid_PQXDH_CURVE25519_SHA-256_ML-KEM-1024" ‖
  IK_sign_A ‖ IK_sign_B`, `L = 32`). All bundle/initial-message signature
  verification.
- **Layer 2 — Incremental ML-KEM Braid SCKA** (§2; ref `core/ml_kem.py`,
  `protocol/states.py`, `protocol/braid.py`, `core/kdf.py`, `core/authenticator.py`):
  the split `Encaps1`/`Encaps2`/`Decaps` interface, the 11-state machine, the
  ratcheted transactional authenticator, and Reed–Solomon erasure coding of large
  objects.
- **Layer 3 — Double Ratchet** (§3; ref `core/double_ratchet.py`): `KDF_RK`,
  directional `CK_{A→B}`/`CK_{B→A}`, `KDF_CK`, skipped-key cache with `MAX_SKIP = 1000`,
  commit-after-AEAD, and the exact `AD` construction.
- **Layer 4 — Sesame relay** (§4; ref `sesame/store.py`, `sesame/sqlite_store.py`,
  `server/app.py`): username-only accounts, TOFU identity pinning with the possession
  proof `Sign(IK_sign, "MLKEMBraid-register:{username}:{registration_id}")`,
  bearer-token sender identity, opaque envelopes (`pqxdh_init | braid | chat`),
  one-time prekey consumption on bundle fetch.
- **Wire formats** (ref `ml_kem_braid/wire.py`): the JSON/dict ↔ struct mappings for
  prekey bundles, initial messages, and braid messages, plus base64 framing.

**Out of scope** (explicitly, matching the spec's non-goals): IP tunneling/VPN,
group/multi-device sender-keys beyond what the Python ref does, push-notification
infrastructure, and a polished end-user GUI (we ship *reference* desktop/mobile shells
to prove the bindings work, not a shippable product).

---

## 2. Cargo workspace architecture

Proposed layout under the workspace root (`rust/`):

```
rust/
├── Cargo.toml                  # [workspace] virtual manifest; pins toolchain via rust-toolchain.toml
├── rust-toolchain.toml         # channel = "stable"; components = clippy, rustfmt
├── deny.toml                   # cargo-deny: license + advisory + ban policy (no `ring` vs RustCrypto conflicts)
│
├── crates/
│   ├── braid-core/             # ← the heart. no_std-friendly, NO I/O, NO async, NO platform deps
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── pqxdh/          # Layer 1: keys, bundle, initial msg, SK derivation
│   │   │   ├── kem/            # Layer 2a: incremental ML-KEM split (Encaps1/Encaps2/Decaps)
│   │   │   ├── scka/          # Layer 2b: 11-state machine + ratcheted authenticator + KDFs
│   │   │   ├── ratchet/       # Layer 3: Double Ratchet, skipped-key cache
│   │   │   ├── erasure/       # systematic Reed–Solomon chunking of large objects
│   │   │   ├── kdf.rs         # HKDF-SHA256 / HMAC-SHA256 wrappers w/ exact labels & salts
│   │   │   ├── wire/          # serde (de)serialization mirroring ml_kem_braid/wire.py
│   │   │   └── error.rs
│   │   └── tests/             # KAT + cross-impl vectors (see §6)
│   │
│   ├── braid-ffi/              # UniFFI crate: thin, panic-safe wrapper over braid-core
│   │   ├── src/lib.rs         # #[uniffi::export] surface; opaque handles for sessions
│   │   ├── braid.udl          # (or proc-macro mode) the FFI interface definition
│   │   └── uniffi-bindgen.rs  # binary target to generate Swift/Kotlin/Python bindings
│   │
│   ├── braid-server/           # axum + tokio relay (the Sesame server). Binary crate.
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── routes/        # register, fetch-bundle, send-envelope, WS mailbox
│   │   │   ├── store/         # sqlx: SQLite (dev) | Postgres (prod) behind a trait
│   │   │   ├── auth.rs        # bearer-token → device identity; TOFU pin verification
│   │   │   └── ws.rs          # tokio-tungstenite mailbox delivery
│   │   └── migrations/        # sqlx migrations (accounts, devices, prekeys, mailboxes)
│   │
│   └── braid-cli/              # optional headless reference client (test harness / oracle parity)
│
├── apps/
│   ├── desktop-tauri/          # Tauri 2.x shell (Linux + Windows + macOS) over braid-core
│   │   └── src-tauri/         #   Rust side calls braid-core directly (no FFI needed)
│   └── desktop-egui/           # OPTIONAL pure-Rust native shell (egui/iced) — fallback to Tauri
│
└── bindings/
    ├── swift/                  # generated Swift + XCFramework packaging (iOS/macOS)
    │   ├── BraidCore.xcframework/
    │   └── Package.swift      # Swift Package Manager manifest wrapping the XCFramework
    └── android/                # generated Kotlin + AAR (cargo-ndk build of braid-ffi)
        └── braid/             # Gradle module with .so per ABI + Kotlin bindings
```

### 2.1 Crate responsibilities & boundaries

| Crate | `no_std`? | async? | Depends on | Exposes |
|---|---|---|---|---|
| `braid-core` | **yes** (with `alloc`; `std` feature for tests) | no | crypto crates only (§3) | pure protocol state machines + (de)serialization |
| `braid-ffi` | no (`std`) | no | `braid-core`, `uniffi` | C-ABI / UniFFI surface for Swift & Kotlin |
| `braid-server` | no (`std`) | **yes** (tokio) | `braid-core`, axum, sqlx, tokio-tungstenite | HTTP+WS relay binary |
| `braid-cli` | no | optional | `braid-core` | headless client for parity testing |
| `apps/desktop-*` | no | yes (UI loop) | `braid-core` directly | desktop shell |

**Design rule (critical):** `braid-core` must be *pure*: no clock, no RNG ambient
access (RNG is passed in via a trait so tests can inject KAT seeds — mirroring the
Python `keygen(seed=...)` path used by `test_kem.py`), no networking, no `tokio`, no
`uniffi`. This keeps it (a) `no_std`-friendly for the smallest mobile footprint and
(b) a clean **hax** verification target (§5). All I/O, async, and platform glue live
in the outer crates.

> **TODO (human):** decide the RNG abstraction. Recommended: accept
> `impl rand_core::CryptoRng + RngCore` at each randomized entry point, and provide a
> `DeterministicRng` test impl seeded from KAT vectors so Rust output can be compared
> byte-for-byte against the Python reference (§6).

---

## 3. Dependency choices (the verified-crypto angle)

Primitive selection prioritizes, in order: **(1) formal verification / memory-safe
provenance, (2) constant-time guarantees, (3) maintenance & audit history,
(4) `no_std` support.** This is precisely where the Rust rewrite is *stronger* than the
Python reference (which uses non-constant-time `kyber-py`).

| Primitive | Spec requirement | Primary crate | Notes / trade-offs |
|---|---|---|---|
| **ML-KEM (512/768/1024)** | FIPS-203; **incremental split** (§2) | **`libcrux-ml-kem`** | **Formally verified** (hax/F\*), constant-time, `no_std`. **PROBLEM:** exposes only monolithic `encaps`/`decaps`, not the project's `Encaps1`/`Encaps2` split. See §3.1. |
| ML-KEM (fallback) | same | `ml-kem` (RustCrypto) | Pure-Rust, RustCrypto-audited, easier to fork for the split, but **not formally verified**; verify constant-time claims. |
| ML-KEM (last resort) | same | `oqs` (liboqs bindings) | C dependency, FFI surface, harder to ship to mobile / `no_std`. Avoid unless others fail. |
| X25519 | DH1–DH4 (§1) | `x25519-dalek` (v2) | Constant-time, widely audited; pair with `curve25519-dalek`. |
| Ed25519 | identity signatures, prekey sigs, TOFU proof | `ed25519-dalek` (v2) | Constant-time; enable `zeroize` feature on signing keys. |
| HKDF-SHA256 | `SK`, `KDF_OK`, `KDF_AUTH`, `KDF_RK` | `hkdf` + `sha2` (RustCrypto) | Must reproduce exact `ikm/salt/info/L` from spec §1–§3. |
| HMAC-SHA256 | `MacHdr`, `MacCt`, `KDF_CK` | `hmac` + `sha2` | `KDF_CK`: `mk = HMAC(ck,0x01)`, `ck' = HMAC(ck,0x02)`. |
| SHA3-256 | `hek = SHA3-256(ek)`; ML-KEM internals | `sha3` (RustCrypto) | Used for the incremental-KEM header (`ek_seed ‖ hek`). |
| AES-256-GCM | Double Ratchet payload AEAD (§3) | `aes-gcm` (RustCrypto) | Constant-time on AES-NI targets; on mobile ARM use the `aes` crate's hardware backend. Consider `chacha20poly1305` as a software-constant-time fallback for non-AES hardware — **OPEN QUESTION:** spec mandates AES-256-GCM; keep AES to stay byte-exact. |
| Reed–Solomon erasure | chunking of header/ek_vector/ct1/ct2 (§2) | **`reed-solomon-simd`** (or `reed-solomon-erasure`) | Must match the Python systematic RS over GF(2⁸); verify the *byte-exact* chunk layout against `ml_kem_braid/encoding/`. SIMD variant is faster; `-erasure` is simpler/more portable. |
| Secret zeroization | all private keys, chain keys, message keys | `zeroize` (+ `ZeroizeOnDrop` derive) | Wrap `EncapsulationSecret`, `dk`, `rk`, `ck`, `mk`, identity keys. The Python ref does **not** zeroize — this is a Rust improvement. |
| Constant-time compare | MAC/tag verification, TOFU checks | `subtle` (`ConstantTimeEq`) | Replace any `==` on secrets/MACs/tags. |
| (De)serialization | wire formats (`wire.py`) | `serde` + `serde_json` (+ optional `bincode`/`postcard` for compact mobile) | JSON to match the Python relay; binary codec optional for size. |
| RNG | keygen, ephemerals, KEM `m` | `rand_core` trait (injected) | Production: `OsRng` from `rand`. Tests: deterministic KAT seed (§2.1). |

> **RISK (high):** the AES-GCM backend's constant-timeness depends on the target
> having AES hardware. On older Android ARM devices without ARMv8 Crypto Extensions,
> the software AES path may be variable-time. **TODO (human):** audit per-ABI; document
> the threat; consider gating to hardware-AES devices or accepting the documented risk.

### 3.1 The incremental ML-KEM split — the hard dependency problem

`PROTOCOL_SPEC.md` §2 defines a **novel** KEM interface that no off-the-shelf crate
exposes:

- `Encaps1(ek_seed, hek; m) → (es, ct1, ss)` — computes the **u-component** `ct1` and
  the shared secret `K` from the header (`ek_seed ‖ hek`) + random `m` *only*
  (`(K,r) = G(m ‖ hek)`, `Â` expanded from `ρ = ek_seed`).
- `Encaps2(es, ek_seed, ek_vector) → ct2` — computes the **v-component** once `t̂`
  (`= ek_vector`) is known.
- `Decaps(dk, ct1 ‖ ct2)` — standard FIPS-203 decaps with implicit rejection.

The **key lemma** (`PROTOCOL_SPEC.md` §2; `test_kem.py::test_split_equals_reference_monolithic`)
is that `ct1 ‖ ct2` equals the standard ML-KEM ciphertext **byte-for-byte**. This is
what makes IND-CCA transfer trivially.

**Implementation strategy (in priority order):**

1. **Preferred:** use `libcrux-ml-kem` for the verified *internal* building blocks
   (NTT, sampling `Â` from `ρ`, `Compress_du`/`Compress_dv`, the FO transform `G`/`J`)
   and assemble the `Encaps1`/`Encaps2` split *on top of* them — keeping as much of the
   verified core in the critical path as possible. **RISK:** libcrux may not expose
   these internals as public API; this may require a vendored fork or upstream patch.
2. **Fallback:** fork `ml-kem` (RustCrypto), which is pure Rust and more hackable, to
   split `encaps` into the two halves. Lose the formal-verification provenance for the
   KEM but gain control. Compensate with the EasyCrypt proof (spec §A) + the byte-exact
   differential test against Python (§6) + hax on the split assembly (§5).
3. **Last resort:** call into the Python `kyber_py`-equivalent logic only as an *oracle*
   for tests, never in the Rust product.

> **TODO (human, the single most important task):** decide the split implementation
> path (1 vs 2). Then prove — by the same byte-exact equality test as `test_kem.py` —
> that the Rust `ct1 ‖ ct2` equals the monolithic FIPS-203 ciphertext for all three
> parameter sets (512/768/1024) **and** equals the Python reference's split output. Do
> not claim "verified" until both equalities hold on real vectors.

---

## 4. Platform strategy

The **libsignal model**: *one* Rust core (`braid-core`), exposed everywhere.

```
                         ┌────────────────────────┐
                         │      braid-core         │  (pure, no_std, hax-target)
                         └───────────┬────────────┘
              ┌──────────────────────┼───────────────────────────┐
              │                      │                            │
        braid-ffi (UniFFI)     braid-server (axum)         apps/desktop-*
        │            │              binary + container      (Tauri / egui)
   ┌────┴───┐   ┌────┴────┐
   Swift     Kotlin
 (iOS/macOS) (Android)
 XCFramework  AAR + .so
   via SPM    via cargo-ndk
```

### 4.1 Mobile — UniFFI → Swift + Kotlin (libsignal model)

- **One** `braid-ffi` crate annotated with **UniFFI** (`#[uniffi::export]` proc-macro
  mode, or `braid.udl`). UniFFI generates idiomatic **Swift** and **Kotlin** bindings
  plus the C-ABI shim — the same mechanism Mozilla and the Matrix Rust SDK use.
- **iOS:** build `braid-ffi` for `aarch64-apple-ios` (+ `aarch64-apple-ios-sim`,
  `x86_64-apple-ios` for simulators), package as an **XCFramework**, wrap in a **Swift
  Package** (`Package.swift`). App code calls generated Swift.
- **Android:** build per-ABI `.so` with **`cargo-ndk`** (`arm64-v8a`, `armeabi-v7a`,
  `x86_64`), generate **Kotlin** bindings, package as an **AAR** consumed via Gradle;
  the `.so` is loaded over **JNI** (UniFFI generates the JNI glue).
- **FFI surface design:** expose *opaque session handles*, not raw key material. Keep
  the surface small: `register`, `build_bundle`, `start_session` (PQXDH),
  `scka_send`/`scka_receive`, `encrypt`/`decrypt`, `serialize_state`/`load_state`.
  Secrets never cross the FFI boundary as plain bytes.

> **TODO (human):** UniFFI does not support every Rust type. Audit `braid-core`'s
> public types for FFI-compatibility (no generics/lifetimes across the boundary; map
> errors to a UniFFI `[Error] enum`; represent byte blobs as `Vec<u8>`/`bytes`).

### 4.2 Desktop — Tauri (primary) or native (fallback)

- **Primary: Tauri 2.x** for **Linux + Windows + macOS** from one codebase. The Rust
  side (`src-tauri`) calls `braid-core` **directly** (no FFI needed — it is the same
  language), exposing commands to a web-tech frontend. Smallest binaries, system
  webview, good cross-platform story.
- **Fallback / alternative: native pure-Rust** `egui` or `iced` shell (`apps/desktop-egui`)
  over the same `braid-core` — no webview, single static binary, simplest CI. Useful if
  Tauri's webview dependencies are a problem on a target.
- Both desktop shells link `braid-core` as a normal crate; **no UniFFI on desktop**.

### 4.3 Server — standalone binary + container

- `braid-server` is a standalone **tokio**/**axum** binary. HTTP for register /
  fetch-bundle / send-envelope; **WebSocket** (tokio-tungstenite) for mailbox push.
  Persistence via **sqlx** behind a `Store` trait: **SQLite** for dev (mirrors
  `sesame/sqlite_store.py`), **Postgres** for production. Ship a `Dockerfile`
  (multi-stage, `distroless`/`scratch` final image) + `docker-compose.yml`.

### 4.4 Target / toolchain matrix

| Platform | Rust target triple(s) | Build tool | Binding/Output | Tested in CI |
|---|---|---|---|---|
| **Linux desktop (x64)** | `x86_64-unknown-linux-gnu` | `cargo` / Tauri | binary / Tauri bundle (deb, AppImage) | ✓ (primary CI) |
| **Linux desktop (arm64)** | `aarch64-unknown-linux-gnu` | `cargo` (cross) | binary | TODO |
| **Windows desktop** | `x86_64-pc-windows-msvc` | `cargo` / Tauri | `.exe` / MSI/NSIS bundle | ✓ |
| **macOS desktop** | `aarch64-apple-darwin`, `x86_64-apple-darwin` | `cargo` / Tauri | `.app` / universal binary | ✓ (byproduct) |
| **iOS device** | `aarch64-apple-ios` | `cargo` + `xcodebuild` | XCFramework → SPM | TODO |
| **iOS simulator** | `aarch64-apple-ios-sim`, `x86_64-apple-ios` | `cargo` | XCFramework slice | TODO |
| **Android** | `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android` | `cargo-ndk` | AAR (.so per ABI) + Kotlin | TODO |
| **Server (Linux)** | `x86_64-unknown-linux-gnu` (+ `-musl` for static) | `cargo` + Docker | container image | ✓ |

> **RISK:** Apple targets require macOS CI runners + an Apple developer cert for
> signing the XCFramework. Android targets require the NDK in CI. Budget for both.

---

## 5. Formal-verification integration

This rewrite is the concrete realization of `PROTOCOL_SPEC.md` §A's note that the
model-to-code gap "is closed only by verified implementations — libcrux/HACL\*,
DY\*/hax." It ties directly into [`FORMAL_VERIFICATION.md`](FORMAL_VERIFICATION.md).

| FV asset | Tool | Applies to | Status |
|---|---|---|---|
| Verified ML-KEM primitive | **libcrux-ml-kem** (hax/F\*-verified upstream) | `braid-core::kem` internals | Upstream verified; **our split assembly is NOT** — see below |
| KEM-split == IND-CCA(ML-KEM) | **EasyCrypt** | the `Encaps1`/`Encaps2` lemma (spec §2) | scaffold in `formal/easycrypt/` (separate task) |
| `braid-core` Rust extraction | **hax** (Rust → F\*/Coq) | `pqxdh`, `scka`, `ratchet`, `kdf`, authenticator | **TODO — not started** |
| Protocol-level secrecy/auth/FS/PCS | Tamarin / Verifpal / CryptoVerif / TLA+ | the abstract protocol | separate `formal/` tasks (spec §A) |

**hax plan for `braid-core` (TODO, human):**

1. Keep `braid-core` in the **hax-supported Rust subset** (no trait objects in the hot
   path, bounded loops, no interior mutability in verified modules, explicit panics).
   This is *why* the "pure / no_std" design rule in §2.1 exists.
2. Extract the KDF/authenticator/ratchet modules to **F\*** via hax; prove the panic-
   freedom and the functional-correspondence lemmas (e.g. `KDF_AUTH` produces
   `(root', mac_key)` matching the spec; the transactional authenticator never commits
   on MAC failure).
3. Tie the EasyCrypt KEM-split lemma to the Rust split by showing the Rust `Encaps1`/
   `Encaps2` refine the EasyCrypt model (refinement, not re-proof).

> **Do NOT claim any of this is verified.** As of this document, **zero** hax
> extraction has been run. The only verified component is whatever `libcrux-ml-kem`
> ships upstream — and even that does **not** cover our incremental split, which sits
> *outside* libcrux's verified boundary. Mark every such claim `admit`/`sorry`/`TODO`
> until a human runs the tools.

---

## 6. Migration & parity — Python repo as the reference oracle

The Python `ml_kem_braid/` stays in the tree as the **golden reference oracle**. The
Rust port is correct **iff** it agrees with Python byte-for-byte on shared vectors.

### 6.1 Test-vector porting

Generate vectors *from Python* (deterministic seeds), commit them as JSON under
`rust/crates/braid-core/tests/vectors/`, and assert Rust reproduces them:

| Vector set | Source (Python) | Rust assertion |
|---|---|---|
| **KEM split KAT** | `test_kem.py::test_split_equals_reference_monolithic` | `Encaps1‖Encaps2 == monolithic FIPS-203 ct`, all of 512/768/1024, **byte-exact** |
| KEM split vs Python | new exporter from `core/ml_kem.py` (seeded `keygen`) | Rust `(es, ct1, ct2, ss)` == Python, same `m`/seed |
| **PQXDH `SK` agreement** | seeded run of `pqxdh/pqxdh.py` | Rust `SK` == Python `SK` for identical keys/ephemerals/OPK-present and OPK-absent |
| `info`/label bytes | `pqxdh.py`, `core/kdf.py` | exact `info`/`salt`/`ikm` byte strings (catch label typos early) |
| **Ratchet message keys** | seeded `core/double_ratchet.py` | Rust `mk[0..N]` per direction == Python; incl. out-of-order + `MAX_SKIP` cache |
| SCKA epoch keys `k_e` | seeded `protocol/braid.py` + `states.py` | identical `k_e` per epoch, both roles |
| Authenticator MACs | `core/authenticator.py` | `MacHdr`/`MacCt` byte-exact; transactional-reject behavior matches |
| Reed–Solomon chunks | `ml_kem_braid/encoding/` | chunk byte layout + any-`k`-of-`(k+p)` reconstruction identical |
| Wire (de)serialization | `wire.py` | round-trip JSON for bundle / initial msg / braid msg matches field-for-field |

### 6.2 Differential / cross-impl testing

- **Static KAT** (above): committed vectors, run in `cargo test` every CI build.
- **Live cross-impl** (`braid-cli` ↔ Python): a harness runs a **Rust client against
  the Python server** *and* a **Python client against `braid-server`**, plus a
  **Rust↔Python full session** (PQXDH → several SCKA epochs → ratchet messages,
  including out-of-order delivery), asserting decrypted plaintext + intermediate keys
  agree. This catches integration drift the static vectors miss.

> **TODO (human):** write the Python exporter scripts (deterministic seeds, JSON out)
> and the cross-impl harness. These do **not** modify `ml_kem_braid/` application code —
> they are new *test/tooling* scripts (allowed) that *import* the reference.

> **RISK:** JSON number/float handling, base64 variant (std vs urlsafe — see
> `wire.py::b64e`), and map key ordering can silently diverge. Pin the exact base64
> alphabet and a canonical JSON form; assert on raw bytes, not parsed objects.

---

## 7. Phased delivery plan

Order: **core + server first** (provable against the oracle, no platform toolchains),
**then desktop** (same-language, no FFI), **then mobile** (FFI + Apple/Android CI).

| Phase | Deliverable | Milestone / exit criterion | Key risks |
|---|---|---|---|
| **0. Bootstrap** | `rust/` workspace, `deny.toml`, CI (fmt/clippy/test), RNG trait, error types | `cargo test` green on empty scaffolding; locate/remove `pq-vpn-braid/` | mis-set workspace root (§0 OPEN QUESTION) |
| **1. Crypto primitives + KDFs** | `kdf.rs`, HKDF/HMAC/SHA3 wrappers, `zeroize`/`subtle` wiring | label/`info` byte vectors match Python exactly | label typos (catch via §6.1 vector) |
| **2. Incremental ML-KEM split** | `kem/` with `Encaps1`/`Encaps2`/`Decaps` | **KEM split KAT byte-exact** for 512/768/1024 AND == Python | §3.1 (libcrux internals access) — **highest risk** |
| **3. PQXDH** | `pqxdh/` handshake + bundle/initial-msg + signature verify | **`SK` agreement** vs Python (OPK present & absent) | DH1–DH4 assignment mistakes |
| **4. SCKA** | `scka/` 11-state machine + ratcheted authenticator + `erasure/` RS | epoch-key + authenticator-MAC + RS-chunk vectors match; no-deadlock smoke test | state-machine subtleties; RS byte layout |
| **5. Double Ratchet** | `ratchet/` + skipped-key cache (`MAX_SKIP=1000`) | message-key + out-of-order vectors match; commit-after-AEAD verified | directional CK separation; cache eviction order |
| **6. Server** | `braid-server` (axum+WS+sqlx SQLite/Postgres) + Docker | Python client ↔ Rust server full session passes (§6.2) | TOFU proof + bearer-token auth parity |
| **7. CLI + cross-impl harness** | `braid-cli`, Rust↔Python differential suite | all four cross-impl directions green | base64/JSON canonicalization (§6.2 RISK) |
| **8. Desktop** | Tauri shell (Linux/Win/macOS) [+ optional egui] over `braid-core` | manual E2E chat between two desktop instances via `braid-server` | Tauri webview deps per-OS |
| **9. Mobile** | `braid-ffi` (UniFFI) → Swift XCFramework + Android AAR; reference apps | iOS app ↔ Android app E2E chat via `braid-server` | Apple/Android CI, AES-GCM CT on ARM (§3 RISK) |
| **10. FV pass** | hax extraction of `braid-core`; tie to EasyCrypt/Tamarin | F\* extraction compiles; functional lemmas stated (some `admit`) | hax Rust-subset constraints (§5) |

**Suggested grouping for parallel work:** Phases 1–5 are sequential (each builds on
the previous and gates on its parity vector). Phase 6 (server) can start in parallel
with Phase 4 once the wire formats (Phase 1's `wire/`) stabilize. Phases 8 and 9 can
run in parallel once Phase 7 proves the core end-to-end.

---

## 8. Consolidated risk list

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | `libcrux-ml-kem` doesn't expose the internals needed for the `Encaps1`/`Encaps2` split | **High** | Vendor/fork libcrux or fall back to forking RustCrypto `ml-kem` (§3.1); upstream a PR |
| R2 | Rust split diverges from Python/FIPS-203 by even one byte | **High** | Byte-exact KAT gate before any further phase (§6.1); EasyCrypt lemma (spec §2) |
| R3 | Forking `ml-kem` loses formal-verification provenance for the KEM | Medium | Compensate with EasyCrypt + hax-on-split + differential tests; document the gap honestly |
| R4 | AES-256-GCM not constant-time on ARM without crypto extensions | Medium | Per-ABI audit; document threat; consider gating (§3 RISK) |
| R5 | UniFFI type incompatibilities force `braid-core` API contortions | Medium | Keep FFI surface tiny & opaque-handle-based; isolate FFI-shaped types in `braid-ffi` |
| R6 | KDF label / salt / `info` byte typos (silent crypto break) | Medium | Dedicated byte-string vectors copied verbatim from spec §1–§3 + Python |
| R7 | base64 alphabet / JSON canonicalization drift Rust↔Python | Medium | Pin alphabet (check `wire.py::b64e`), canonical JSON, assert on raw bytes |
| R8 | Reed–Solomon chunk layout differs from Python | Medium | Vector-match `encoding/`; pick the crate whose GF(2⁸)/systematic layout matches |
| R9 | Apple/Android CI cost & signing complexity | Medium | Defer to Phase 9; budget macOS runners + NDK; XCFramework + AAR automation |
| R10 | hax Rust-subset constraints conflict with idiomatic `braid-core` | Low–Med | Enforce the "pure, bounded, no-trait-object" rule from day one (§2.1, §5) |
| R11 | `pq-vpn-braid/` location unknown — risk of deleting/duplicating wrong thing | Low | §0 TODO: locate before acting; this plan assumes greenfield `rust/` |

---

## 9. How to install & run the toolchain (orientation for the human implementer)

> These are the tools the plan depends on. None are required to *read* this document;
> they are needed to *execute* the phases. Commands shown are the current idioms.

```bash
# Rust toolchain (stable) + components
rustup toolchain install stable
rustup component add clippy rustfmt

# Workspace hygiene
cargo install cargo-deny      # license/advisory/ban policy (deny.toml)
cargo deny check              # expect: no advisories, no banned/duplicate crypto crates

# Core build & parity tests (Phases 1–7)
cargo test -p braid-core      # expect: all KAT + parity vectors green (once written)

# Server (Phase 6)
cargo run -p braid-server     # axum on :PORT; SQLite by default (DATABASE_URL for Postgres)

# Mobile bindings (Phase 9)
cargo install cargo-ndk                    # Android: builds per-ABI .so
cargo ndk -t arm64-v8a -t x86_64 build --release -p braid-ffi
cargo run -p braid-ffi --bin uniffi-bindgen -- generate ...   # Swift + Kotlin bindings
rustup target add aarch64-apple-ios aarch64-apple-ios-sim     # iOS slices → XCFramework

# Desktop (Phase 8)
cargo install tauri-cli       # or: use apps/desktop-egui for pure-Rust native
cargo tauri build             # produces per-OS bundles

# Formal verification (Phase 10) — see FORMAL_VERIFICATION.md for exact install
# hax: Rust -> F*/Coq extraction of braid-core; libcrux ships its own F* proofs.
```

Expected outputs are noted per command above. **Until a human actually runs these and
the parity vectors pass, treat every correctness statement in this document as a
*goal*, not a fact.**

---

## 10. Summary of open TODOs (for the reviewer)

1. **Locate `pq-vpn-braid/`** (§0) — it is not on disk now; confirm before deleting.
2. **Pick the workspace root path** (`rust/` assumed) and the KEM-split crate strategy
   (libcrux internals vs. fork RustCrypto `ml-kem`) — §3.1, the highest-risk decision.
3. **Define the injected-RNG trait** + `DeterministicRng` for KAT parity — §2.1.
4. **Write the Python vector exporters + cross-impl harness** (new tooling, does not
   touch `ml_kem_braid/` app code) — §6.
5. **Run hax on `braid-core`** and tie to EasyCrypt/`FORMAL_VERIFICATION.md`; leave
   unproven obligations as explicit `admit`/`sorry` — §5.
6. **Audit AES-GCM constant-timeness per mobile ABI** — §3 R4.
7. **Pin base64 alphabet + canonical JSON** to kill Rust↔Python drift — §6.2 R7.

Nothing in this document has been compiled, run, or verified. It is a plan.
