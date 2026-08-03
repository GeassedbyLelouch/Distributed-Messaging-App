# Cryptographic Protocol Security Analysis

Date: 2026-06-27

Scope: local package `ml_kem_braid/`, parent `README.md`, parent `docs/`, parent
`formal/`, and the requested Signal specifications:

- https://signal.org/docs/specifications/pqxdh/
- https://signal.org/docs/specifications/mlkembraid/
- https://signal.org/docs/specifications/doubleratchet/
- https://signal.org/docs/specifications/sesame/
- https://github.com/signalapp/libsignal

## Executive Verdict

No implementation-level cryptographic break was found in this pass. The code and
tests support the README's main design claims: PQXDH mixes X25519 and
ML-KEM-1024 into an identity-bound `SK`; the Braid SCKA uses ML-KEM-768 plus a
ratcheted HMAC authenticator; the Double Ratchet derives per-message keys with
directional `A->B` / `B->A` separation; and replay controls are present through
OPK consumption, message indices, `MAX_SKIP`, and transactional state commits.

The assurance status is weaker than the protocol goals: the formal models are
scaffolds, not discharged proofs. This matches `docs/FORMAL_VERIFICATION.md`,
which explicitly says nothing in the repository is proven yet. Formal tool
binaries were not installed in this environment, so Verifpal, Tamarin,
Apalache, and EasyCrypt proofs were not machine-run here.

## Local Verification Run

Commands run:

```bash
codex-proofs/scripts/verify_readme_claims.py --json
codex-proofs/scripts/run_formal_tools.sh
uv run pytest -q
```

Results:

- README-to-code evidence: `10 passed, 0 failed`, saved at
  `codex-proofs/results/readme_claims.json`.
- Formal prover availability: all four requested prover binaries were missing,
  saved at `codex-proofs/results/formal_tool_check.log`.
- Test suite: `220 passed, 3 warnings`, saved at
  `codex-proofs/results/pytest.log`.

## Property Matrix

| Property | Implementation evidence | Formal status | Verdict |
|---|---|---|---|
| Message confidentiality | PQXDH uses `ML_KEM_1024` and X25519, SCKA uses ML-KEM-768 by default, payloads use AES-GCM via Double Ratchet message keys. See `pqxdh/pqxdh.py:56`, `core/ml_kem.py:138`, `core/aead.py`. | Verifpal/Tamarin scaffolds present; no machine run. | Supported by code/tests, not proven. |
| Mutual authentication / UKS | Bundle signatures are verified, responder verifies `ik_dh_sig`, and `SK` HKDF `info` binds both identity signing keys. See `pqxdh/pqxdh.py:111`, `pqxdh/pqxdh.py:226`, `pqxdh/pqxdh.py:281`. | Tamarin/Verifpal obligations present. | Strong implementation evidence. |
| Per-message FS | `KDF_CK` derives one message key and next chain key; decrypt commits only after AEAD succeeds. See `core/double_ratchet.py:104`, `core/double_ratchet.py:276`. | Tamarin/Squirrel-level proof remains open. | Supported by design and tests. |
| PCS / healing | SCKA emits fresh ML-KEM epoch keys and feeds them to DR `ratchet_epoch`. See `protocol/states.py:620`, `client/client.py:89-94`. | Tamarin/Squirrel proof remains open. | Plausible under ML-KEM security and state erasure assumptions. |
| Replay resistance | OPK private key is deleted on responder use, DR rejects consumed/past indices, skip cache is bounded by `MAX_SKIP=1000`. See `pqxdh/pqxdh.py:307`, `core/double_ratchet.py:47`, `core/double_ratchet.py:252`. | Tamarin restriction scaffold present; TLA model covers uniqueness/progress. | Supported, with DoS caveat below. |
| Hybrid security | PQXDH mixes X25519 DH outputs and ML-KEM SS in HKDF. See `pqxdh/pqxdh.py:225`. | Computational proof not present. | Holds as a PQXDH proof obligation; not a full SCKA PCS guarantee if ML-KEM breaks. |
| State-machine correctness | Code has the 11-state SCKA machine and tests multi-epoch agreement. See `protocol/states.py`, `tests/test_braid_protocol.py`. | TLA model present but not run. | Tested, not model-checked here. |

## Findings

### F-01: Formal verification is not discharged

Severity: High assurance risk

The repository contains formal scaffolds and proof sketches, but they are not
completed proofs. The local `docs/FORMAL_VERIFICATION.md:3-8` states this
explicitly. The copied Codex proof artifacts also contain open `TODO`, `admit`,
and `sorry` markers:

- `models/verifpal/full_pqxdh_braid_chat.vp`
- `models/tamarin/scka_double_ratchet.spthy`
- `models/tla/SCKA.tla`
- `proofs/easycrypt/MLKEM_Split.ec`

Local result: `run_formal_tools.sh` skipped all formal tools because Verifpal,
Tamarin, Apalache, and EasyCrypt are not installed.

Impact: the code may be well-tested, but the requested Dolev-Yao plus
state-compromise claims are not machine-verified.

Recommendation: pin tool versions, install the tools, repair any parse/type
issues, then make CI fail on new counterexamples, timeouts, or admitted lemmas.

### F-02: Hybrid-security claim should be scoped more narrowly

Severity: Medium

PQXDH has a credible hybrid proof obligation: `SK` is derived from X25519 DH
outputs plus ML-KEM-1024 shared secret in one HKDF input. However, after the
initial handshake the SCKA healing source is ML-KEM-only. The Braid epoch key is
derived from `encaps1` or `decaps` and `KDF_OK`, without a fresh classical DH
component per epoch (`protocol/states.py:620-625`, `protocol/states.py:488-495`).

Impact: if ML-KEM is broken and an attacker uses the state-compromise oracle,
future SCKA epochs do not add unknown post-compromise entropy. X25519 protects
the initial root only while uncompromised root state remains secret; it does not
by itself provide post-compromise healing after a full live-state reveal.

Recommendation: document hybrid security as a PQXDH/session-root property unless
the SCKA is extended with a fresh classical ratchet source, or prove a narrower
composition theorem that states exactly what remains secure under each primitive
break.

### F-03: The split ML-KEM equivalence is still a proof obligation

Severity: Medium

The implementation matches the README's split design and the regression test
`tests/test_kem.py:40-60` checks `ct1 + ct2 == ref_c` against kyber-py's
monolithic `_encaps_internal` for all three ML-KEM parameter sets with a fixed
message `m`. That is strong differential testing, but it is not a universal
IND-CCA proof.

The EasyCrypt skeleton records the remaining side conditions: byte-for-byte
equivalence for every honest canonical `ek` and every FO message `m`, plus the
early-`ct1` ordering argument. The implementation checks `ek_vector` length in
`core/ml_kem.py:227-231` and validates `hek` at the protocol layer
(`protocol/states.py:720-723`, `protocol/states.py:747-750`), but the formal
lemma still needs a canonical-encoding side condition because `encaps2` does not
replay kyber-py's monolithic public-key modulus check on arbitrary public keys.

Recommendation: discharge `split_eq` against the FIPS-203 K-PKE encryption
equations or a verified ML-KEM spec, and state the lemma over canonical keys.

### F-04: OPK exhaustion and handshake DoS remain practical risks

Severity: Medium

`GET /keys/{username}/{device_id}` is unauthenticated and calls
`store.take_prekey_bundle`, which consumes one public one-time prekey when
available (`server/app.py:323-328`, `sesame/store.py:158-176`,
`sesame/sqlite_store.py:230-265`). The README explicitly says there is no rate
limiting, DoS protection, or spam filtering (`README.md:637`).

Impact: a network attacker can drain OPK pools without completing sessions. The
protocol falls back to no-OPK PQXDH when the pool is empty, which is expected in
Signal-style designs, but this reduces one-time prekey availability and can
force weaker freshness for new asynchronous handshakes.

Recommendation: add per-account/device quotas, rate limiting, abuse detection,
and replenishment telemetry. Consider authenticated or proof-of-work gated bundle
fetches if this is ever deployed beyond a test setting.

### F-05: Constant-time and verified-implementation gap

Severity: High for production

The README and formal plan correctly say `kyber-py` is a reference
implementation, not a production constant-time primitive. `docs/FORMAL_VERIFICATION.md:299`
calls out timing/cache side channels and implicit-rejection decapsulation as out
of scope for the symbolic/computational models.

Impact: a formally green protocol model would still not rule out timing or cache
leakage in Python ML-KEM operations.

Recommendation: replace `kyber-py` with a constant-time verified ML-KEM
implementation such as libcrux/formosa-mlkem for deployment, and run a separate
constant-time analysis discipline.

### F-06: Deployment hardening is intentionally optional

Severity: Low to Medium, deployment-dependent

TLS enforcement is off by default in `create_app(enforce_tls=False)` and only
enabled by the server entrypoint when cert/key environment variables are set
(`server/app.py:215-232`, `server/app.py:499-504`). The default store is
in-memory unless `BRAID_STORE_PATH` selects SQLite (`server/app.py:229`,
`server/app.py:492-493`).
The README documents these as optional features and says the project is not for
production without audit (`README.md:14-19`, `README.md:631-632`).

Impact: protocol confidentiality remains end-to-end, but plaintext HTTP exposes
tokens and metadata, and in-memory storage loses pending mail and prekey state on
restart.

Recommendation: make TLS and durable storage mandatory in any production profile.

## Included Formal Artifacts

### Verifpal

Path: `models/verifpal/full_pqxdh_braid_chat.vp`

Purpose: fast bounded symbolic pass over PQXDH -> first SCKA epoch -> one
Double Ratchet chat message. It models the high-level flow and expected
confidentiality/authentication queries.

Status: scaffold. It contains documented abstractions and TODOs. It was not run
because `verifpal` is not installed.

### Tamarin

Path: `models/tamarin/scka_double_ratchet.spthy`

Purpose: stateful symbolic model for SCKA plus Double Ratchet with reveal rules
for FS and PCS, OPK single-use restriction, and directional-chain lemmas.

Status: scaffold. It contains open proof obligations, including reveal-state
cleanup and a loose sources lemma. It was not run because `tamarin-prover` is not
installed.

### TLA+ / Apalache

Paths: `models/tla/SCKA.tla`, `models/tla/SCKA.cfg`

Purpose: state-machine model for agreement, per-epoch uniqueness, monotonicity,
progress, and no deadlock under a bounded fair channel abstraction.

Status: scaffold. It was not run because `apalache-mc` and TLC tooling are not
installed here.

### EasyCrypt-style KEM Split Proof

Paths: `proofs/easycrypt/MLKEM_Split.ec`,
`proofs/easycrypt/PROOF_SKETCH.md`

Purpose: formalize the reduction that split `Encaps1`/`Encaps2` is
IND-CCA-equivalent to standard ML-KEM because it produces the same ciphertext and
shared secret distribution.

Status: scaffold and written proof sketch. `split_eq` remains an admitted
obligation.

## Positive Findings

- The responder verifies the initiator's DH identity binding before deriving SK.
- Both identity signing public keys are included in PQXDH HKDF `info`.
- OPK private keys are deleted on responder use and replay is tested.
- The SCKA authenticator verifies ciphertext MAC under a candidate state before
  committing.
- The Double Ratchet separates directions with distinct HKDF labels and verifies
  cached skipped messages before eviction.
- Chat AEAD associated data binds sender, recipient, epoch, and message index.
- The full test suite passes in this environment.

## Bottom Line

The implementation is internally consistent with the README and has good
regression coverage for the prior adversarial-review fixes. The remaining work
is formal assurance and production-hardening, not a small code patch: complete
the verifier models, narrow the hybrid claim or add a classical SCKA source,
replace the Python ML-KEM backend before production, and add anti-DoS controls.
