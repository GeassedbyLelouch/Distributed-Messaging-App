# Security analysis & findings — ML-KEM Braid PQ chat

Scope: the cryptographic protocol (`ml_kem_braid/`), analysed against the goals in
the task brief and **every security claim in `README.md` §8**. Each claim is checked
against the actual code (not just the prose) and against what the formal models in
this folder can and cannot establish.

Confidence markers (per the project's claim-verification discipline):
**✓ VERIFIED** = read the code, traced the logic; **⚠ CAVEAT** = true but with an
important qualification; **✗ DISCREPANCY** = code does not match the claim.

Tool evidence referenced below: `results/kem_split.txt` (pytest/kyber-py, **1800/1800**),
`results/verifpal.txt` (Verifpal 0.52.0, active attacker), `results/tlc.txt`
(TLC, **No error found**), `results/tamarin.txt` (Tamarin 1.12.0, wellformed +
`exec_setup` verified).

---

## A. README §8 "Properties provided" — claim-by-claim verification

| # | README claim | Code | Verdict |
|---|---|---|---|
| 1 | **Post-quantum confidentiality** — ML-KEM-1024 in PQXDH; ML-KEM-768 (default) in Braid; security under Module-LWE | `pqxdh.py:56` (`ML_KEM_1024`), `ml_kem.py:138` (default `ML_KEM_768`) | **✓ VERIFIED**. Real `kyber-py` FIPS-203 primitives; split is byte-identical to reference (1800/1800, `results/kem_split.txt`). |
| 2 | **Forward secrecy** — ephemeral PQXDH keys & per-epoch keys not retained; past keys unrecoverable from current state | per-epoch `dk` lives only in transient state objects (`states.py`), dropped on role swap; DR `mk` used once then discarded (`double_ratchet.py:201`) | **✓ VERIFIED** for epoch/message keys. **⚠ CAVEAT**: see F-2 (PQXDH `SK` is retained in `MLKEMBraid._preshared_secret`; low impact). |
| 3 | **Post-compromise security** — fresh ML-KEM entropy each epoch heals a compromise | `states.py:621` `encaps1` fresh keypair per epoch; `KDF_AUTH` ratchets root | **⚠ CAVEAT** — holds against a compromise-then-passive adversary; an attacker who keeps the authenticator state can MITM the next epoch's KEM key. See F-3. |
| 4 | **Authenticated handshake** — Ed25519 bundle sigs + `ik_dh_sig` binding; `SK` binds both identity keys via HKDF `info`, defeating UKS | `pqxdh.py:111-119` (`bundle.verify`), `:282` (responder verifies `ik_dh_sig`), `:225-227` (`info = PQXDH_INFO‖IK_A‖IK_B`) | **✓ VERIFIED**. Verifpal: `sk_a`/`sk_b` secret + `chat_ct` authenticated under an **active** attacker (`results/verifpal.txt`). |
| 5 | **Identity-pinned usernames** — username pinned to Ed25519 key on first registration; `proof_sig` verified server-side | `sesame/store.py` `register_device`; `server/app.py` registration | **✓ VERIFIED** (regression test `test_security_fixes.py`). Out of crypto-protocol scope; not modelled formally here. |
| 6 | **Token-authenticated relay** — sender from bearer token, never the body | `server/app.py` (POST `/messages`, `/ws send`) | **✓ VERIFIED** (per README §7 + `test_security_fixes.py`). Transport-layer; not in the crypto models. |
| 7 | **OPK replay prevention** — one-time prekey deleted on use; replay raises `KeyError` | `pqxdh.py:307` `del secrets.opk_priv[message.opk_id]`; `:305` raises on missing | **✓ VERIFIED**. Modelled as `OPK_SingleUse` restriction in the Tamarin theory. |
| 8 | **Transactional authenticator ratchet** — verify ciphertext MAC under candidate key before advancing | `authenticator.py:135-163` `update_and_verify_ciphertext` (computes candidate, `compare_digest`, commits only on success) | **✓ VERIFIED**. Modelled (Eq-before-commit) in the Tamarin `SCKA_Epoch_Consumer` rule. |
| 9 | **Per-message forward secrecy** — Double Ratchet: `mk=HMAC(ck,0x01)`, `ck'=HMAC(ck,0x02)`, directional A→B/B→A, MAX_SKIP, transactional decrypt | `double_ratchet.py:104-114, 91-101, 47, 264-284` | **✓ VERIFIED**. Directional separation (`info="A->B"`/`"B->A"`) ⇒ distinct send chains (F-6); transactional decrypt commits only after AEAD success (`:278-283`). |
| 10 | **Transport security (optional)** — TLS, self-signed cert pinning, optional mTLS | `tls.py` | **✓ VERIFIED** present + tested (`test_tls.py`). Out of crypto-protocol scope. |
| 11 | **Durable storage (optional)** — SQLite backend, atomic OTK consume + mailbox drain | `sesame/sqlite_store.py` | **✓ VERIFIED** present + tested. Out of scope. |
| 12 | **Minimal server-side metadata** — no phone/email/real-names/contact graph; server never sees private keys or plaintext | `sesame/store.py`, `server/app.py` (opaque `body`) | **✓ VERIFIED** by inspection. |

**README §8 "Not provided" claims** (no rate limiting/DoS; no formal audit; no XEdDSA —
deviation via `ik_dh_sig`): **✓ VERIFIED accurate.** The XEdDSA deviation is exactly
the `ik_dh_sig` binding analysed in claim 4 / F-7.

**README §9 testing claim "220 tests pass": ✓ VERIFIED** — `uv run pytest -q` →
`220 passed` in this environment.

**README §1/§2 KEM-split fidelity claim** ("`ct1‖ct2` equals the exact FIPS-203
ciphertext"): **✓ VERIFIED and strengthened** — the repo's test uses one message
`m=0x5a·32`; `kem_split/verify_split_indcca.py` confirms it for **1800** random
encapsulations across all three variants (`results/kem_split.txt`).

---

## B. Findings (what the analysis surfaced)

### F-1 — KEM split is genuinely IND-CCA-equivalent to standard ML-KEM  ✓ (positive)
The `Encaps1`/`Encaps2` split is the most novel claim and the cleanest to justify.
`K = G(m‖hek)[:32]` is fixed in `encaps1` and is **independent of `ct2`** (`ml_kem.py:196`).
The harness confirms, for 1800 encapsulations: (a) `ct1‖ct2 == _encaps_internal(ek,m)`
byte-for-byte; (b) `ct1` is reproducible from `(ek_seed,hek,m)` alone (no `ek_vector`/`dk`);
(c) `K` equals `es.shared_secret` (independent of `ct2`); (d) FO implicit rejection on
tampered `ct2`. This empirically discharges Lemma 1 and Lemma 2's premise of the
EasyCrypt reduction (`easycrypt/PROOF_SKETCH.md`). **No issue.**

### F-2 — PQXDH `SK` is retained for the session lifetime  ⚠ (minor FS hygiene)
`MLKEMBraid._preshared_secret` keeps `SK` (`braid.py:111`) and the authenticator is
seeded from it. **Impact: low.** Epoch keys are `KDF_OK(ss_e, e)` — independent of `SK` —
and past ciphertext-MAC keys need past `ss_e` (whose `dk` is deleted), so retaining `SK`
does **not** break forward secrecy of message/epoch keys. It does mean a state
compromise also exposes `SK` (root of the authenticator chain and the DR root seed).
**Recommendation:** zeroize `SK` after the first authenticator/DR seeding, or document
it as retained-by-design.

### F-3 — PCS holds against a *passive-after-compromise* adversary only  ⚠ (expected, document)
PCS healing relies on fresh ML-KEM entropy mixed each epoch. But the new epoch's KEM
**public key travels in the header, authenticated by the very authenticator state** an
attacker would have on compromise. An attacker who compromises the authenticator
`(root, mac_key)` can forge a header (inject its own `ek_seed/hek`), causing the victim
to encapsulate to an attacker-controlled key — so the attacker stays in control and PCS
does **not** heal while it remains active. This is the **standard** Signal-style PCS
boundary (healing requires the attacker to go passive / one clean epoch to complete),
and the README's wording ("compromise of one epoch does not expose subsequent epochs
once fresh randomness is contributed") is consistent with it. **Recommendation:** state
the active-vs-passive boundary explicitly in §8. The Tamarin `post_compromise_security`
lemma encodes exactly this (secret unless a *new* reveal at/after the healing epoch).

### F-4 — `ek_vector` integrity rests on header-MAC + SHA3 collision resistance  ✓ (positive)
The encapsulator commits `ct1` from the header before `ek_vector` arrives, then checks
`hek == SHA3-256(ek_vector‖ek_seed)` (`states.py:721-723`). `hek` is inside the
MAC-authenticated header, so a substituted `ek_vector` requires a SHA3-256 collision.
**Sound.** (Symbolically: the Verifpal/Tamarin AEAD/MAC abstractions treat the hash as
collision-free; the real assumption is SHA3-256 collision resistance.)

### F-5 — Intra-SCKA replay is rejected  ✓ (positive)
Every header/ciphertext MAC binds the 8-byte epoch (`authenticator.py:155,189,211`), and
state handlers accept only `msg.epoch == epoch` (`states.py`). A replayed prior-epoch
object fails the MAC (wrong key) and/or the epoch guard. Tamarin `replay_resistance` /
`UniqueEpoch` and TLC `Uniqueness` encode the corresponding state-machine property.

### F-6 — Double Ratchet directional separation prevents key/nonce reuse  ✓ (positive)
`CK_AtoB = HKDF(seed, info="A->B")`, `CK_BtoA = HKDF(seed, info="B->A")`
(`double_ratchet.py:99-101`); Alice sends on AtoB, Bob on BtoA. Distinct `info` ⇒
distinct chains ⇒ the two parties never derive the same sending-chain key, so the same
`(epoch, index)` message key is produced by exactly one encryptor. With a fresh `mk` per
message and a fresh random GCM nonce (`aead.py:23`), there is no key/nonce reuse. This is
the subtle invariant the task brief flagged; **verified**.

### F-7 — Field-level handshake values are not individually authenticated — by design  ⚠ (not a bug)
Verifpal reports `authentication? kem_ct` and `authentication? ik_dh_sig_a` **fail**
under the active attacker. This is **correct and benign**: PQXDH authenticates the
*composite* `SK` (all four DHs + `ss` + both identities bound in the HKDF `info`), not
the bare KEM ciphertext or a relayed public signature. An injected `kem_ct` only yields a
non-matching `SK`, so the chat fails to decrypt; `sk_a`/`sk_b`/`plaintext`/`chat_ct` all
remain secret/authentic (`results/verifpal.txt`). Notably `sk_b` stays secret **even when
the attacker tampers with `ek_a`/`kem_ct`**, because `DH1` over the long-term identity DH
key + signed prekey survives — the **hybrid / multi-DH robustness**.

### F-8 — Initiator identity is accepted as asserted (authentication, not authorization)  ⚠ (by design)
`responder_handshake` verifies `ik_dh_sig` binds the initiator's DH key to *whatever*
Ed25519 identity the initiator presents (`pqxdh.py:282`); it does not check that identity
is a *known/expected* peer. That authorization lives one layer up (Sesame username
pinning, claim 5). Correct separation of concerns; worth stating so `responder_handshake`
isn't mistaken for an access-control check.

### F-9 — Side channels are out of scope and real  ⚠ (deployment)
`kyber-py` is a reference implementation and is **not constant-time**; decaps, the
HMAC/AEAD paths could leak via timing. No formal model here (or any symbolic/computational
KEM model) covers this. The README §"Not provided" already disclaims production use and
audit. **Recommendation:** for deployment, swap `kyber-py` for a constant-time verified
impl (libcrux ML-KEM / formosa-mlkem) and HACL\* for X25519/HKDF/AES-GCM, and run a
constant-time analysis (the repo has a `ct-check` skill).

### F-10 — Documentation-vs-code label abbreviations  ✗ (minor doc discrepancy)
The README §4b ASCII writes the header MAC as `HMAC(mac_key, "ekheader"‖epoch‖header)`
and the ciphertext MAC as `HMAC(mac_key, "ciphertext"‖epoch‖ct‖ct)`. The code prefixes
the **protocol_info** string and a colon: `mac_data = PROTOCOL_INFO‖":ekheader"‖epoch‖header`
(`authenticator.py:186-191`) and `PROTOCOL_INFO‖":ciphertext"‖epoch‖ct` (`:154-156, 210-216`).
No security impact (the prefix only *adds* domain separation), but the README's MAC inputs
are abbreviated relative to the code. **Recommendation:** align the §4b pseudo-code with
the actual MAC inputs.

### F-11 — `KDF_OK` salt is the zero string, by spec  ✓ (positive, note)
`KDF_OK(ss, e) = HKDF(ikm=ss, salt=0x00*32, info=PROTOCOL_INFO‖":SCKA Key"‖i8(e))`
(`kdf.py:184-195`). Zero salt is fine for HKDF when the IKM (`ss`) is a high-entropy KEM
secret; epoch is bound in `info` for per-epoch separation. Matches the README §4b. **No issue.**

---

## C. What the formal models establish (and what they do not)

| Property (task goal) | Tool here | Result |
|---|---|---|
| Message confidentiality (PQ + classical), UKS/identity binding | Verifpal (active DY) | **secrecy of SK/k1/plaintext + chat authentication PASS**; field-level auth fails by design (F-7) |
| KEM-split IND-CCA equivalence (the novel claim) | EasyCrypt sketch + Python harness | Lemma 1/2 **empirically 1800/1800**; reduction is the identity map; EasyCrypt main `admit`ted (no toolchain) |
| State-machine agreement / one-key-per-epoch / no-deadlock / progress | TLA+ → TLC | **No error found** (safety+liveness, MaxCopies=1); safety also at MaxCopies=2 over 1.89M states |
| FS / PCS over unbounded epochs; SCKA ciphertext auth; replay | Tamarin | model **wellformed**, `exec_setup` verified; FS/PCS/agreement lemmas **stated & well-formed** but need interactive proving / a custom oracle (standard for stateful ratchets) — see README "Tamarin status" |
| Side channels, RNG, model-to-code gap, deniability, metadata privacy | — | **out of scope** (F-9); require constant-time tooling and verified impls |

**Bottom line.** Every README §8 security claim is **VERIFIED in code** with two
qualifications to make explicit (F-2 SK retention; F-3 active-attacker PCS boundary) and
one minor doc fix (F-10). The novel KEM-split claim is the strongest result here:
byte-for-byte FIPS-203 fidelity at scale plus a tight identity reduction. No exploitable
vulnerability was found in the cryptographic core; the real residual risk is the
non-constant-time reference primitives (F-9), which the README already disclaims.
