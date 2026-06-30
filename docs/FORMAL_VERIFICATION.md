# Formal Verification Plan — ML-KEM Braid PQ E2EE Chat

> **Status: PLAN / SCAFFOLD.** This document is an *implementation plan* for the
> formal-verification effort, to be reviewed by a human and executed later.
> **Nothing in this repository is "verified" or "proven" yet.** Every claim that a
> property *holds* is a **proof obligation**, marked `TODO`, `admit`, or `sorry`
> below. The scaffolds under [`../formal/`](../formal/) are skeletons; they will not
> typecheck or close without the human work described here.
>
> The **single source of truth** for every KDF label, salt, DH assignment, and
> message field is [`PROTOCOL_SPEC.md`](PROTOCOL_SPEC.md). Where a model needs a
> byte-exact detail not restated there, the cited Python source file is normative.
> Any model that disagrees with the spec/code is **wrong** and must be fixed — a
> mismatched KDF label or swapped DH input is the primary failure mode of this kind
> of work.

---

## Table of contents

1. [Security goals and threat model](#1-security-goals-and-threat-model)
2. [Three levels of rigor](#2-three-levels-of-rigor)
3. [Property → tool matrix (per layer)](#3-property--tool-matrix-per-layer)
4. [The novel proof obligations](#4-the-novel-proof-obligations-not-free-from-prior-signal-analyses)
5. [Precedent to fork](#5-precedent-to-fork)
6. [Staged roadmap and effort](#6-staged-roadmap-and-rough-effort)
7. [CI / reproducibility](#7-ci--reproducibility)
8. [Explicit limits and out-of-scope](#8-explicit-limits--what-these-models-do-not-cover)
9. [Scaffold index](#9-scaffold-index-formal)

---

## 1. Security goals and threat model

Restated crisply from [`PROTOCOL_SPEC.md` §0](PROTOCOL_SPEC.md). The protocol is four
composed layers: a one-shot **PQXDH** handshake → 32-byte `SK`; a continuous
**ML-KEM Braid SCKA** producing per-epoch keys `k_e`; a **Double Ratchet** over the
SCKA producing per-message keys `mk`; and an untrusted **Sesame relay**.

### 1.1 Security goals (what we must prove)

| Goal | Informal statement | Primary layer(s) |
|---|---|---|
| **PQ + classical confidentiality** | Message plaintext is secret against a quantum adversary AND a classical adversary. | all |
| **Mutual authentication** | Each party is assured of the peer's identity (`IK_sign`); no impersonation. | PQXDH, SCKA (MAC), DR (AD binding) |
| **Forward secrecy (FS)** | Compromise of current state does **not** reveal *past* message keys. | DR (per-message), SCKA (per-epoch) |
| **Post-compromise security (PCS) / healing** | After a compromise, the session **heals** once fresh SCKA entropy (a new ML-KEM epoch) flows. | SCKA → DR via `KDF_RK` |
| **Replay resistance** | A replayed handshake / message is rejected (OPK single-use; DR index monotonicity; transactional MAC). | PQXDH, SCKA, DR |
| **Unknown-key-share (UKS) / identity-misbinding resistance** | A cannot be tricked into sharing a key it believes is with B but is actually with C. | PQXDH (`info` binds both `IK_sign`) |
| **Hybrid security** | The session is secure if **either** X25519 **or** ML-KEM-1024 is unbroken (not both required). | PQXDH ikm, SCKA epochs |
| **Directional key non-reuse** | The two directions never derive the same sending chain. | DR (`"A->B"` / `"B->A"` domain sep) |
| **State-machine correctness** | At most one key per epoch, no deadlock, eventual progress. | SCKA (11-state FSM) |
| **KCI resistance** | Compromise of A's long-term key does not let the attacker impersonate *others* to A. | PQXDH |
| **System-level (relay)** | Username↔identity binding, sender authenticity, mailbox isolation, server learns only metadata+ciphertext. | Sesame |

### 1.2 Threat model

- **Network: Dolev-Yao.** The attacker has *full* control of the relay and network:
  read, drop, reorder, inject, replay any message. The relay server itself is part of
  the attacker model (untrusted; honest-but-curious at best). It sees only public
  bundles, opaque ciphertexts, and minimal metadata (username, device id, registration
  id, timestamps) — never private keys or plaintext.
- **State-compromise oracle.** This is the *defining* element for stating FS and PCS.
  The adversary may, at chosen times, query an oracle that **reveals a party's current
  secret state** (long-term keys, ratchet/authenticator state, cached keys). FS/PCS are
  meaningless without it: FS = "a compromise at time `t` does not break messages from
  `t' < t`"; PCS = "a compromise at time `t` is healed for messages at `t'' > t + Δ`
  once a fresh ML-KEM epoch is injected". **Every symbolic and computational model
  below must expose this oracle explicitly** (Tamarin `Reveal` facts, CryptoVerif/
  Squirrel `corrupt` events, EasyCrypt adversary state-leak). A model that omits it
  *cannot* express the protocol's two headline guarantees.
- **Crypto assumptions (computational layer).** X25519 ⇒ Gap-DH/ODH; ML-KEM-1024 ⇒
  IND-CCA (MLWE); HKDF-SHA256 / HMAC-SHA256 ⇒ PRF/dual-PRF + random-oracle where
  needed; AES-256-GCM ⇒ IND-CCA / INT-CTXT AEAD; Ed25519 ⇒ EUF-CMA.
- **Out of the adversary's reach (assumed):** RNG is uniform; erasures/side channels
  are *not* modeled here (see [§8](#8-explicit-limits--what-these-models-do-not-cover)).

---

## 2. Three levels of rigor

Each level buys something different; none subsumes the others. We pursue all three.

| Level | Tools | Adversary model | What it **buys** | What it **cannot** catch |
|---|---|---|---|---|
| **Symbolic** | Verifpal, Tamarin, ProVerif | Dolev-Yao; perfect crypto (terms, no probabilities) | Fast, automatable, whole-protocol **logical-flaw** discovery: missing authentication, UKS, reflection/replay, key-confusion, reachability/deadlock. Great first net. | Probabilistic / number-theoretic gaps; "secure if X25519 *or* ML-KEM holds" is awkward (must model two failure branches); nothing about bit-security or reductions. |
| **Computational** | CryptoVerif, EasyCrypt, Squirrel | Probabilistic poly-time; game-based / sequence-of-games; concrete crypto assumptions | **Reduction-style** proofs in the standard/ROM model: secrecy with concrete advantage bounds, FS/PCS against the state oracle, **hybrid** ("either primitive suffices") stated as a real assumption, and the **KEM-split IND-CCA equivalence** ([§4.1](#41-incremental-ml-kem-split--ind-cca-equivalence)). | Implementation bugs; constant-time; the model-to-code gap. |
| **Verified implementation** | HACL\*, **libcrux-ml-kem** (formosa/libcrux), DY\*, **hax** | Machine-checked code-level proofs (F\*/Rust→F\*) | Closes the **model-to-code gap**: the *actual* ML-KEM bytes and (optionally) the Braid state machine are proved functionally correct & memory-safe, matching the spec. libcrux/HACL\* give a drop-in **constant-time, verified ML-KEM** to replace `kyber-py`. | Only as good as the spec it's proved against; does not by itself prove the *protocol* secure (that's the symbolic+computational layers). |

**Why all three:** symbolic finds design flaws cheaply and early; computational gives
quantitative confidence and handles the genuinely novel reductions; verified
implementation removes the "but does the code match the model?" objection and fixes
the constant-time gap that none of the others touch.

---

## 3. Property → tool matrix (per layer)

This refines [`PROTOCOL_SPEC.md` §A](PROTOCOL_SPEC.md). Scaffold files are cited by
relative path under [`../formal/`](../formal/).

### 3.1 PQXDH handshake (`ml_kem_braid/pqxdh/pqxdh.py`)

| Property | Symbolic | Computational | Scaffold |
|---|---|---|---|
| Secrecy of `SK` | Verifpal `confidentiality SK`; Tamarin `Secret(SK)` lemma | CryptoVerif `secrecy of SK` (fork BJKS PQXDH) | [`../formal/verifpal/pqxdh.vp`](../formal/verifpal/pqxdh.vp), [`../formal/tamarin/pqxdh.spthy`](../formal/tamarin/pqxdh.spthy) |
| Mutual implicit auth | Verifpal `authentication`; Tamarin injective-agreement | CryptoVerif `correspondence` | same |
| **UKS / identity binding** (`info` binds `IK_sign_A‖IK_sign_B`) | Tamarin agreement on *both* identities | CryptoVerif | `pqxdh.spthy` (TODO: model `info` string byte-exactly) |
| OPK single-use ⇒ replay resistance | Tamarin restriction: `OPK` consumed once | — | `pqxdh.spthy` |
| **Hybrid** (secure if X25519 **or** ML-KEM holds) | Tamarin: two lemmas, each corrupting one primitive | CryptoVerif: model both as independent assumptions, prove disjunction | `pqxdh.spthy` + CryptoVerif TODO |
| KCI resistance | Tamarin (reveal A's long-term, attacker still can't impersonate C) | CryptoVerif | `pqxdh.spthy` |

> **Byte-exact note (normative):** `SK = HKDF(ikm = 0xff^32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4 ‖ ss,
> salt = 0x00^32, info = "MLKEMBraid_PQXDH_CURVE25519_SHA-256_ML-KEM-1024" ‖ IK_sign_A ‖ IK_sign_B, L=32)`.
> DH assignments: `DH1=X25519(IK_dh_A, SPK_B)`, `DH2=X25519(EK_A, IK_dh_B)`,
> `DH3=X25519(EK_A, SPK_B)`, `DH4=X25519(EK_A, OPK_B)` (omitted iff no OPK). The
> models **must** match these exactly; do not paraphrase the `info` label.

### 3.2 ML-KEM Braid SCKA (`core/ml_kem.py`, `protocol/states.py`, `core/{kdf,authenticator}.py`)

| Property | Symbolic | Computational | State-machine | Scaffold |
|---|---|---|---|---|
| Agreement: both derive identical `k_e` per epoch | Tamarin equality lemma | CryptoVerif | — | [`../formal/tamarin/scka.spthy`](../formal/tamarin/scka.spthy) |
| Secrecy of each `k_e` | Verifpal (partial) | **CryptoVerif/Squirrel** | — | tamarin + computational TODO |
| Authentication (transactional MAC) | Tamarin (forged CT cannot advance state) | EasyCrypt (HMAC PRF) | — | `scka.spthy` |
| FS across epochs | — | **CryptoVerif/Squirrel** with reveal oracle | — | computational TODO |
| PCS / healing (fresh ML-KEM entropy per epoch) | Tamarin PCS lemma | **CryptoVerif/Squirrel** | — | `scka.spthy` |
| **State-machine: ≤1 key/epoch, no deadlock, progress** | — | — | **TLA+/Apalache** | [`../formal/tla/SckaStateMachine.tla`](../formal/tla/SckaStateMachine.tla) |

> **Byte-exact KDF labels (verified against `core/kdf.py`):**
> `PROTOCOL_INFO = "MLKEMBraid_MLKEM768_HMAC-SHA256"`.
> `KDF_OK(ss,e) = HKDF(ikm=ss, salt=0x00^32, info=PROTOCOL_INFO‖":SCKA Key"‖i8(e), L=32)`.
> `KDF_AUTH(root,k,e) = HKDF(ikm=k, salt=root, info=PROTOCOL_INFO‖":Authenticator Update"‖i8(e), L=64) → (root', mac_key)`.
> Authenticator: `Init` sets `root←0x00^32` then `Update`; `MacHdr/MacCt` labels
> `":ekheader"` / `":ciphertext"`. The **transactional** `update_and_verify_ciphertext`
> commits only on MAC success — model it as an atomic verify-then-commit so a forged
> ciphertext provably cannot corrupt authenticator state.

### 3.3 Double Ratchet over the SCKA (`core/double_ratchet.py`)

| Property | Symbolic | Computational | Scaffold |
|---|---|---|---|
| Per-message secrecy | Tamarin | **Squirrel/CryptoVerif** (fork ACD ratchet) | [`../formal/tamarin/double_ratchet.spthy`](../formal/tamarin/double_ratchet.spthy) |
| FS (used `mk`, superseded `ck` unrecoverable) | Tamarin reveal | Squirrel/CryptoVerif with state oracle | same |
| PCS (inherited via `KDF_RK` from SCKA) | Tamarin | Squirrel/CryptoVerif (**composition**, see [§4.3](#43-double-ratchet-over-scka-composition--directional-separation)) | same |
| Out-of-order / skipped-key correctness, `MAX_SKIP=1000` bound | TLA+ (bounded allocation) + Tamarin | — | [`../formal/tla/SckaStateMachine.tla`](../formal/tla/SckaStateMachine.tla) (extend) |
| Tamper ⇒ no state corruption (commit-after-AEAD, verify-before-evict) | Tamarin transactional model | EasyCrypt (AEAD INT-CTXT) | `double_ratchet.spthy` |
| **Directional separation** ⇒ no cross-direction key reuse | Tamarin: prove `CK_{A→B} ≠ CK_{B→A}` reachable-key disjointness | Squirrel | `double_ratchet.spthy` |

> **Byte-exact (normative, `core/double_ratchet.py`):**
> `KDF_RK(rk,k_e) = HKDF(ikm=k_e, salt=rk, info="MLKEMBraid-DR-root", L=64) → (rk', seed)`;
> `CK_{A→B} = HKDF(ikm=seed, salt=0x00^32, info="A->B", L=32)`;
> `CK_{B→A} = HKDF(ikm=seed, salt=0x00^32, info="B->A", L=32)`;
> `KDF_CK(ck): mk=HMAC(ck,0x01), ck'=HMAC(ck,0x02)`.
> `AD = "sender:dev->recipient:dev" ‖ "hdr:" ‖ i8(epoch) ‖ i8(index)`.

### 3.4 Incremental ML-KEM split (`core/ml_kem.py`; `tests/test_kem.py`)

| Property | Tool | Scaffold |
|---|---|---|
| **`Encaps1`‖`Encaps2` output = monolithic FIPS-203 ciphertext byte-for-byte** | EasyCrypt equivalence lemma (the empirical oracle is `test_kem.py::test_split_equals_reference_monolithic`) | [`../formal/easycrypt/`](../formal/easycrypt/) |
| **IND-CCA of the split interface = IND-CCA(ML-KEM)** | EasyCrypt reduction (fork formosa-mlkem / libcrux) | [`../formal/easycrypt/`](../formal/easycrypt/) |
| Revealing `ct1` before `ct2` leaks nothing beyond the public final ciphertext | EasyCrypt corollary of the equivalence | [`../formal/easycrypt/`](../formal/easycrypt/) |

### 3.5 Sesame relay (`sesame/*`, `server/app.py`) — mostly system-level

| Property | Tool | Note |
|---|---|---|
| Username↔`IK_sign` binding (TOFU + possession proof) | Tamarin (registration sub-model) | proof string `"MLKEMBraid-register:{username}:{registration_id}"` |
| Sender authenticity (token-derived, never request body) | Tamarin / manual argument | bearer-token = sender identity |
| Mailbox isolation, "server learns only metadata+ct" | manual / non-interference argument; **not** a crypto-game property | document assumptions |

---

## 4. The novel proof obligations (not free from prior Signal analyses)

Prior Signal / X3DH / Double-Ratchet analyses get us most of the *classical*
structure. The following are **genuinely new** and carry the real risk — they are the
heart of this effort and **none is currently discharged**.

### 4.1 Incremental ML-KEM split = IND-CCA equivalence

The Braid splits FIPS-203 encapsulation into `Encaps1` (u-component `ct1`, computed
from `ek_seed=ρ` and `hek` and random `m` only: `(K,r)=G(m‖hek)`) and `Encaps2`
(v-component `ct2`, once `ek_vector=Encode₁₂(t̂)` is known). **Claim:** for the same
`m`, `ct1‖ct2` equals the standard ML-KEM ciphertext *byte-for-byte*, so IND-CCA
transfers by a trivial reduction and early release of `ct1` leaks nothing.

- **Status:** supported *empirically* only — `tests/test_kem.py::test_split_equals_reference_monolithic`
  (512/768/1024). **This is an oracle, not a proof.**
- **Obligation:** EasyCrypt lemma `split_equals_monolithic` (functional equivalence of
  the split vs. reference encaps for all `m`), then the IND-CCA reduction. **TODO:
  `admit` both.** A human must (a) formalize the FIPS-203 encaps in EasyCrypt or reuse
  formosa-mlkem's spec, (b) prove the two procedures equivalent, (c) lift IND-CCA.

### 4.2 SCKA security — **the Braid is new; no published formal analysis exists**

The ML-KEM Braid SCKA (sparse CKA with per-epoch ML-KEM re-encapsulation, ratcheted
HMAC authenticator, 11-state FSM, erasure-coded large objects) is a **novel
construction**. There is **no prior peer-reviewed security proof to fork.** Its
agreement, per-epoch secrecy, FS, and PCS must be modeled and proved from scratch
(Tamarin for symbolic; CryptoVerif/Squirrel for computational; TLA+ for the FSM). This
is the single largest open obligation. **TODO:** define the CKA security game for this
specific construction; the transactional authenticator's "forgery cannot advance
state" must be a proved invariant, not an assumption.

### 4.3 Double-Ratchet-over-SCKA composition + directional separation

Standard Double Ratchet sits over an X3DH+DH ratchet. Here it sits over the **SCKA**:
the DH-ratchet input is the *shared* per-epoch `k_e`, not a fresh per-direction DH
output. Because `k_e` is shared, **both parties would otherwise derive the same sending
chain and reuse keys** — catastrophic. The protocol avoids this with directional
domain separation (`info="A->B"` vs `"B->A"`). **Obligations:**

1. **Composition theorem:** prove DR security *assuming* the SCKA delivers
   fresh, secret, agreed `k_e` — i.e., a clean modular reduction (SCKA security ⇒ DR
   security). Do not re-prove DR from scratch; reduce to it.
2. **Directional non-reuse:** prove the reachable sending-chain keys for A→B and B→A
   are disjoint (the domain separation is *load-bearing* for FS, not cosmetic).
   **TODO `sorry`.**

### 4.4 Hybrid PQ/classical binding

`SK` mixes `DH1..DH4` (X25519) **and** `ss` (ML-KEM) in one HKDF `ikm`. **Obligation:**
prove `SK` secret if **either** the X25519 branch **or** the ML-KEM branch is unbroken
(disjunction, not conjunction). Symbolically: two Tamarin lemmas, each granting the
adversary one primitive. Computationally: model X25519 and ML-KEM as independent
assumptions and prove secrecy under their *disjunction* (dual-PRF / KEM-combiner
argument). This is exactly the BJKS PQXDH hybrid result, but must be re-checked for our
*non-standard* `info` (binds both `IK_sign`) and our `0xff^32` prefix. **TODO.**

---

## 5. Precedent to fork

Do **not** start from a blank file. Fork these and adapt to our byte-exact spec.

| Precedent | What it gives | Reuse for |
|---|---|---|
| **Bhargavan, Jacomme, Kiefer, Schmidt — "Formal verification of the PQXDH protocol" (2024)** (ProVerif + CryptoVerif models of Signal's PQXDH) | Symbolic + computational PQXDH models incl. hybrid PQ/classical and the prekey/signature structure | §3.1, §4.4 — fork their `.spthy`/CryptoVerif and **edit DH assignments + `info` label** to match our spec |
| **Cohn-Gordon, Cremers, Dowling, Garratt, Stebila — Signal protocol analysis** | The reference symbolic framework for X3DH + ratchet, FS/PCS lemma shapes | §3.1, §3.3 lemma templates |
| **Alwen, Coretti, Dodis — "The Double Ratchet: Security Notions, Proofs, and Modularization" (2019)** | The clean *modular* security definition for the Double Ratchet (sub-protocol abstractions) | §4.3 — the composition theorem reduces to their DR notion |
| **formosa-mlkem / libcrux-ml-kem** (machine-checked, constant-time ML-KEM in Jasmin + F\*/Rust→hax) | A *verified, constant-time* ML-KEM spec & implementation, and an EasyCrypt/Jasmin IND-CCA proof to extend | §3.4, §4.1, §8 — base the split equivalence on their FIPS-203 spec; replace `kyber-py` with libcrux for constant-time |

---

## 6. Staged roadmap and rough effort

Effort is **engineer-weeks for someone fluent in the tool**; ranges reflect the novel
obligations. Stages are roughly ordered by cost/benefit (cheap flaw-finding first).

| Stage | Goal | Tool | Output | Rough effort |
|---|---|---|---|---|
| **S0** | Stand up scaffolds, pin tool versions, wire CI (lint-only first) | all | `formal/` skeletons run in CI | 0.5–1 wk |
| **S1** | First symbolic pass: PQXDH secrecy/auth/UKS sanity | **Verifpal** ([`../formal/verifpal/pqxdh.vp`](../formal/verifpal/pqxdh.vp)) | quick flaw net; catches gross design bugs | 1 wk |
| **S2** | Full symbolic: PQXDH + SCKA + DR, FS/PCS via reveal, hybrid (2 lemmas), replay/UKS/KCI | **Tamarin** ([`../formal/tamarin/*.spthy`](../formal/tamarin/)) | injective-agreement + secrecy + FS/PCS lemmas | 3–6 wk |
| **S3** | Computational PQXDH: secrecy + hybrid disjunction + KCI | **ProVerif/CryptoVerif** (fork BJKS) | concrete-advantage secrecy proof | 3–5 wk |
| **S4** | **KEM-split lemma:** functional equivalence + IND-CCA transfer | **EasyCrypt** ([`../formal/easycrypt/`](../formal/easycrypt/), fork formosa-mlkem) | `split_equals_monolithic`, IND-CCA corollary | 4–8 wk (novel) |
| **S5** | SCKA state machine: ≤1 key/epoch, no deadlock, progress, `MAX_SKIP` bound | **TLA+/Apalache** ([`../formal/tla/SckaStateMachine.tla`](../formal/tla/SckaStateMachine.tla)) | model-checked invariants + liveness | 2–4 wk |
| **S6** | Computational SCKA + DR composition + directional separation | **CryptoVerif/Squirrel** (fork ACD) | composition theorem, FS/PCS, no key reuse | 6–10 wk (novel) |
| **S7** | **Verified implementation:** replace `kyber-py` with **libcrux-ml-kem**; explore **hax** on the Braid state machine; close model-to-code gap | **libcrux + hax / HACL\*** | constant-time verified ML-KEM in the product; (stretch) extracted Rust proofs | 4–8 wk + ongoing |

Total novel-heavy core (S2–S6): roughly **20–35 engineer-weeks**. S4 and S6 carry the
most risk because no prior proof exists to fork directly.

---

## 7. CI / reproducibility

- **Pin every tool version** (exact commit / release) in a `formal/versions.lock` (or
  Nix flake / Docker image). Symbolic and computational results are sensitive to tool
  version; an un-pinned upgrade can silently change what closes. **TODO: create the
  lockfile.**
- **Run the models in CI.** Verifpal and TLA+/Apalache are fast enough to run on every
  PR; Tamarin/ProVerif/CryptoVerif may need a nightly job or a timeout budget. CI must
  **fail** if any lemma that previously closed now fails or times out (no silent
  regressions). EasyCrypt proofs run in CI once they are no longer `admit`-ted.
- **Differential testing against the Python reference as an oracle.** The Python
  implementation is the executable spec. For the KEM split specifically,
  `tests/test_kem.py::test_split_equals_reference_monolithic` is the empirical witness
  for [§4.1](#41-incremental-ml-kem-split--ind-cca-equivalence); keep it (and a KAT
  vector set) green in CI so the EasyCrypt model and the code provably agree on
  concrete vectors even before the proof closes. Likewise, extract concrete
  KDF/HKDF/HMAC test vectors from the Python code and assert the symbolic/computational
  models reference the *same* labels (a cheap guard against the "wrong label" failure
  mode). **TODO: add a `formal/labels_check` test that greps the byte-exact labels out
  of both `core/kdf.py` / `core/double_ratchet.py` and the model files and asserts
  equality.**

---

## 8. Explicit limits — what these models do **not** cover

These are **out of scope** for the symbolic/computational models and must be addressed
separately. Do not let a green proof create false confidence here.

| Limit | Why it matters | Mitigation / pointer |
|---|---|---|
| **Constant-time / side channels** | **`kyber-py` is NOT constant-time.** Symbolic and computational models assume idealized, leak-free primitives. Timing/cache side channels on ML-KEM (and the implicit-rejection decaps) are a real attack surface invisible to every model above. | Replace `kyber-py` with **libcrux-ml-kem** (verified constant-time) for production; verify CT with **Jasmin / ct-verif / `constant-time-analysis`**. **TODO.** |
| **RNG quality** | All secrecy proofs assume uniform randomness for `m`, ephemerals, salts. A weak/predictable RNG breaks everything regardless of proofs. | Out of model; require a vetted CSPRNG; document the assumption. |
| **Model-to-code gap** | A proof about a `.spthy`/EasyCrypt *model* is not a proof about the *Python* (or Rust) code. Labels, message framing, erasure coding, and error handling may diverge from the model. | Closed only by verified implementation (S7: libcrux/HACL\*, hax/DY\*) + the differential testing in §7. The erasure-coding layer (Reed-Solomon over GF(2⁸)) is **abstracted away** in all crypto models (treated as a reliable transport); its correctness is a separate coding-theory obligation. |
| **Deniability** | Signal-style offline/online deniability is **not** modeled. The dedicated Ed25519 `IK_sign` (vs XEdDSA) and the `ik_dh_sig` binding may *weaken* deniability relative to Signal. | **Explicitly unverified.** A human must decide whether deniability is a goal and, if so, model it (it is a distinct property requiring a simulator argument). |
| **Metadata privacy** | The relay sees username, device id, registration id, timestamps, and ciphertext sizes/timing. Confidentiality models say nothing about traffic analysis or social-graph leakage. | Out of model; document the metadata the untrusted relay learns ([`PROTOCOL_SPEC.md` §4](PROTOCOL_SPEC.md)); consider sealed-sender / padding as future work. |

---

## 9. Scaffold index (`formal/`)

These paths are the **four scaffolds** this plan targets. They **do not exist yet** (or
are skeletons) and must be created/completed by the human executing this plan. Each
should open with a header comment restating *what is modeled vs abstracted* and the
assumptions, and mark every open obligation with `TODO` / `admit` / `sorry`.

| Path | Tool | Covers | Key TODOs |
|---|---|---|---|
| [`../formal/verifpal/pqxdh.vp`](../formal/verifpal/pqxdh.vp) | Verifpal | S1 first-pass PQXDH secrecy/auth | model byte-exact `info`; add reveal queries |
| [`../formal/tamarin/`](../formal/tamarin/) (`pqxdh.spthy`, `scka.spthy`, `double_ratchet.spthy`) | Tamarin | S2 symbolic PQXDH + **SCKA (novel)** + DR; FS/PCS/hybrid/UKS/replay | SCKA from scratch (§4.2); hybrid 2-lemma split (§4.4); directional non-reuse (§4.3) |
| [`../formal/easycrypt/`](../formal/easycrypt/) | EasyCrypt | S4 **KEM-split equivalence + IND-CCA** (novel) | `split_equals_monolithic` (`admit`); IND-CCA reduction; fork formosa-mlkem |
| [`../formal/tla/SckaStateMachine.tla`](../formal/tla/SckaStateMachine.tla) | TLA+/Apalache | S5 11-state FSM: ≤1 key/epoch, no deadlock, progress, `MAX_SKIP` | encode 11 states + Send/Receive; invariants + liveness |

### How to install & run (quick reference)

> Versions to be pinned in `formal/versions.lock` (S0). Expect these commands once the
> scaffolds are filled in; today they will report unfinished/`admit`-ted obligations.

- **Verifpal** — `go install verifpal.com/cmd/verifpal@latest` (or download release);
  run `verifpal verify formal/verifpal/pqxdh.vp`. *Expected output:* per-query
  `confidentiality`/`authentication` results; `OK` or a counterexample trace.
- **Tamarin** — install via `brew install tamarin-prover` or the Haskell stack build;
  run `tamarin-prover --prove formal/tamarin/pqxdh.spthy`. *Expected:* each `lemma`
  reported `verified` or `falsified` (with attack graph). Some lemmas may need
  interactive mode (`tamarin-prover interactive ...`) or oracles.
- **ProVerif/CryptoVerif** — `opam install proverif cryptoverif`; run
  `proverif formal/proverif/pqxdh.pv` / `cryptoverif formal/cryptoverif/pqxdh.ocv`.
  *Expected:* `RESULT ... is true/false` per query; CryptoVerif emits a game sequence.
- **EasyCrypt** — `opam install easycrypt` (+ Why3/SMT provers `alt-ergo`, `z3`);
  run `easycrypt formal/easycrypt/kem_split.ec`. *Expected:* proof checks, **except**
  `admit`-ted lemmas which print as admitted (these are the open obligations).
- **TLA+/Apalache** — Apalache from GitHub releases (or TLC in the TLA+ Toolbox); run
  `apalache-mc check --inv=Inv formal/tla/SckaStateMachine.tla`. *Expected:* `No error
  found` or a counterexample trace for an invariant.
- **libcrux-ml-kem / hax** (S7) — `cargo` + the `hax` toolchain; extract and check the
  ML-KEM crate. *Expected:* verified constant-time ML-KEM to replace `kyber-py`.
- **Constant-time** — use the `constant-time-analysis` skill / ct-verif / Jasmin
  against the chosen ML-KEM implementation (S8 in §8).

---

*End of plan. Reminder: this is a scaffold. No proof here is complete; every "✓" in the
spec's matrix is an obligation, not a result, until the corresponding tool run closes
without `admit`/`sorry` and is reproduced in CI.*
