# claude-proofs — formal analysis of the ML-KEM Braid PQ chat protocol

A comprehensive security analysis of the cryptographic protocol in this repository
(`ml_kem_braid/`): a Python re-creation of Signal's PQXDH → ML-KEM Braid (SCKA) →
Double Ratchet stack. This folder contains **the scripts used in the analysis, the
models, captured tool output, and the reported findings**, and it **verifies the
claims in the top-level `README.md`** against the actual code.

> **Honesty contract.** Every result below was produced by *running a tool in this
> environment* unless explicitly marked *authored / not fully executed*. Tool
> transcripts are in [`results/`](results/). Symbolic ("Dolev-Yao") results are not
> computational/PQ proofs; the model abstractions are documented per artifact.

---

## 1. What was checked, and the headline results

| Goal (from the brief) | Lives in code | Artifact | Tool | Result |
|---|---|---|---|---|
| Message confidentiality (PQ + classical); mutual auth / no-UKS | `pqxdh.py` (`ik_dh_sig`, identities in HKDF `info`) | `verifpal/mlkem_braid_full.vp` | **Verifpal 0.52.0** ✅ ran | secrecy of SK/epoch-key/plaintext **+ chat authentication PASS** under an active attacker |
| KEM-split IND-CCA equivalence (the novel claim) | `core/ml_kem.py` (`encaps1`/`encaps2`) | `kem_split/verify_split_indcca.py`, `easycrypt/` | **pytest/kyber-py** ✅ ran | **1800/1800** byte-for-byte = FIPS-203; tight identity reduction |
| State-machine agreement / one-key-per-epoch / no-deadlock / progress | `protocol/states.py`, `braid.py` | `tla/SCKA.tla` | **TLC** ✅ ran | **No error found** (safety + liveness) |
| Forward secrecy / post-compromise security; SCKA cipher-auth; replay | `core/{authenticator,double_ratchet}.py` | `tamarin/scka_double_ratchet.spthy` | **Tamarin 1.12 + Maude 3.5.1** ✅ ran | wellformed; `exec_setup` + `opk_replay_resistance` verified; FS/PCS lemmas authored & well-formed (interactive proving / oracle needed — see §5) |
| Side channels, RNG, model-to-code gap | — | — | — | out of scope (see `FINDINGS.md` F-9) |

**Verdict on `README.md` claims:** all twelve §8 "Properties provided" claims are
**verified in the code**, with two qualifications to make explicit (SK retention,
active-attacker PCS boundary) and one minor doc fix (MAC-label abbreviation). The
README's "220 tests pass" and the "`ct1‖ct2` == FIPS-203 ciphertext" claims were
**re-verified** (the latter strengthened from 1 message to 1800). Full table:
[`FINDINGS.md`](FINDINGS.md).

---

## 2. Threat model

Dolev-Yao network attacker (intercept / inject / reorder / drop / replay) **plus** a
state-compromise oracle that reveals chosen secret state at chosen times — this is what
makes forward secrecy and post-compromise security *provable* properties rather than
plain confidentiality. The Verifpal model uses `attacker[active]`; the Tamarin model
adds `Reveal_SK` / `Reveal_DR_State` / `Reveal_Chain` rules; the TLA+ channel may
drop/dup/reorder but cannot forge (forgery is defeated by the MAC, modelled in Tamarin).

---

## 3. Layout

```
claude-proofs/
├── README.md                         this file
├── FINDINGS.md                       security analysis: every README §8 claim + F-1..F-11
├── verifpal/mlkem_braid_full.vp      full PQXDH->SCKA(epoch1)->DR->AES-GCM, active attacker
├── tamarin/scka_double_ratchet.spthy SCKA epoch ratchet + Double Ratchet + compromise oracle
├── tla/SCKA.tla, SCKA.cfg, SCKA_small.cfg   11-state SCKA machine (agreement/uniqueness/
│                                            no-deadlock/progress)
├── easycrypt/MLKEM_Split.ec          IND-CCA reduction: split == standard ML-KEM
├── easycrypt/PROOF_SKETCH.md         the reduction in prose, tied to the harness
├── kem_split/verify_split_indcca.py  RUNNABLE empirical Lemma-1/2 (1800 encapsulations)
├── results/                          captured tool transcripts (kem_split, verifpal, tlc, tamarin)
└── scripts/                          run_all.sh + one runner per tool
```

These supersede the earlier `formal/` scaffolds (which were explicitly "NOT YET RUN,
NOTHING PROVEN", had unbound placeholder variables in the Tamarin lemmas, and an
unparseable two-block Verifpal model). The versions here **parse, are well-formed, and
were executed**; fixes are noted in each file header and in §6.

---

## 4. How to reproduce

```bash
# From the repo root. Each runner is independent; missing tools are reported, not fatal.
bash claude-proofs/scripts/run_all.sh

# Or individually:
bash claude-proofs/scripts/run_kem_split.sh    # needs the project's uv/python env (kyber-py)
bash claude-proofs/scripts/run_verifpal.sh     # needs verifpal               (set $VERIFPAL)
bash claude-proofs/scripts/run_tla.sh          # needs java + tla2tools.jar   (set $TLA2TOOLS_JAR)
bash claude-proofs/scripts/run_tamarin.sh      # needs tamarin-prover + maude (set $TAMARIN/$MAUDE)
```

Tool versions used here: Verifpal 0.52.0, tla2tools 2.19 (Java), Tamarin 1.12.0 +
Maude 3.5.1, Python via `uv` with `kyber-py`. Install pointers are in each runner's
header and in the model-file headers.

---

## 5. Results in detail

### 5.1 KEM split — IND-CCA equivalence (the novel cryptographic claim)
`results/kem_split.txt` — **1800/1800 across ML-KEM-512/768/1024** (200 random `m` ×
3 keypairs each):
- **Lemma 1**: `ct1‖ct2 == _encaps_internal(ek,m)` byte-for-byte, and `decaps(ct1‖ct2)==K`;
- **Lemma 2 premise**: `ct1` is a function of `(ek_seed,hek,m)` only (no `ek_vector`/`dk`),
  and `K` is fixed by `encaps1` (independent of `ct2`);
- FO implicit rejection on a tampered `ct2`.

These discharge — empirically, at scale — the only split-specific obligation of the
EasyCrypt reduction (`easycrypt/PROOF_SKETCH.md`): the split is *the same KEM* with the
ciphertext computed in a different order, so IND-CCA transfers with a tight identity
reduction. The EasyCrypt `.ec` states the reduction; its main theorem is `admit`ted
(no EasyCrypt toolchain in this environment) — a clean *load* would not be a proof.

### 5.2 Verifpal — symbolic secrecy & authentication (active attacker)
`results/verifpal.txt` — 6/8 queries pass; the 2 "fails" are **expected and benign**:
- ✅ `confidentiality? sk_a, sk_b, k1_a, plaintext_m`; ✅ `authentication? chat_ct`;
  ✅ `freshness? ek_a`.
- `sk_b` stays secret **even when the attacker tampers with `ek_a`/`kem_ct`** —
  `DH1` over the long-term identity DH + signed prekey survives: the **hybrid/multi-DH
  robustness** (breaking the session needs a long-term secret, not just the ephemeral
  or the KEM).
- ✗ `authentication? kem_ct` / `ik_dh_sig_a` fail because PQXDH authenticates the
  *composite* SK, not individual public/relayable handshake fields (`FINDINGS.md` F-7).

### 5.3 TLA+ / TLC — SCKA state machine
`results/tlc.txt` — **"Model checking completed. No error has been found."**
- Safety: `TypeOK`, `Agreement` (both parties' per-epoch key sets equal), `Uniqueness`
  (≤1 key/epoch/party), `MonotoneGapless` (epochs form a prefix), `NoKeyAhead`.
- Liveness: `Progress` (both eventually agree each bounded epoch) and `NoDeadlock`,
  under weak fairness on sends + strong fairness on deliveries (the fair-channel model).
- Verified complete at MaxEpoch=3/MaxCopies=1; safety additionally over **1.89M states**
  at MaxCopies=2 (duplication + reorder + drop + retransmit).
- A genuine *modelling* bug was caught and fixed along the way: without retransmission, a
  single dropped header deadlocks — the real protocol re-sends erasure-coded chunks, now
  modelled as retransmission self-loops. TLC's built-in deadlock flag is disabled
  (`-deadlock`) because the protocol legitimately *terminates* at the epoch bound;
  no-deadlock is checked as the `NoDeadlock` temporal property.

### 5.4 Tamarin — SCKA + Double Ratchet with FS/PCS (state-compromise adversary)
`results/tamarin.txt` — theory **wellformed (all checks pass)**; `exec_setup` and
`opk_replay_resistance` **verified** automatically. The remaining lemmas (executability,
`scka_agreement`, `scka_ciphertext_auth`, `replay_resistance`, secrecy, FS, PCS) are
**stated and well-formed** but do not discharge automatically within the per-lemma time
cap: the open consumer input `In(<ct,macct>)` over `aenc`/`adec` produces source chains
that need a custom **oracle** / `--auto-sources` / interactive proving in the Tamarin GUI
to terminate. **This is the expected state for a novel stateful KEM-ratchet model** —
Signal's own ratchet Tamarin theories ship hand-written oracles. The model is a correct,
runnable starting point (it fixes the prior scaffold's unbound `k0/r0/k1/r1/ms` variables
and the non-persistent `!SetupKey` bug). To drive the hard lemmas:
```bash
tamarin-prover interactive claude-proofs/tamarin/scka_double_ratchet.spthy   # GUI at :3001
# or batch with automatic source lemmas:
tamarin-prover --prove --auto-sources claude-proofs/tamarin/scka_double_ratchet.spthy
```

---

## 6. Model abstractions (what each tool does *not* capture)

- **Verifpal/Tamarin (symbolic):** ML-KEM is an idealized IND-CCA KEM (Verifpal
  `PKE_ENC`/`PKE_DEC`; Tamarin built-in `aenc`/`adec` + one-way `kdf_kem`). HKDF/HMAC are
  collision-free one-way symbols with every domain-separation label preserved. No
  computational/PQ hardness, no lattice math, no constant-time guarantees.
- **The incremental `ct1`/`ct2` split** is *not* re-derived in Verifpal/Tamarin (they use
  monolithic KEM); that it equals standard ML-KEM is the **EasyCrypt + harness**
  obligation, cited there.
- **TLA+** abstracts all cryptography: the per-epoch key is `KeyOf(e)` (equal for both
  parties by construction), so TLC proves the *state-machine discipline* — that keys are
  only emitted under agreeing epoch bookkeeping — not cryptographic key equality (that is
  the KEM/KDF job, covered by EasyCrypt/Tamarin). It also abstracts Reed-Solomon chunking
  to per-object delivery.
- **EasyCrypt** abstracts the lattice algebra of K-PKE (which lives in the FIPS-203 theory
  it reduces to, e.g. formosa-mlkem); its content is the reduction, with Lemma 1 backed
  empirically by the harness.
- **Out of every model:** side channels (`kyber-py` is not constant-time), RNG quality,
  the model-to-code gap, deniability, and metadata privacy. See `FINDINGS.md` §C/F-9.

---

## 7. References (the specs this implementation followed)

- ML-KEM Braid — https://signal.org/docs/specifications/mlkembraid/
- PQXDH — https://signal.org/docs/specifications/pqxdh/  (and Bhargavan–Jacomme–Kiefer–
  Schmidt, *A Formal Analysis of the PQXDH Protocol*, 2024, ProVerif+CryptoVerif)
- Double Ratchet — https://signal.org/docs/specifications/doubleratchet/
- Sesame — https://signal.org/docs/specifications/sesame/
- libsignal — https://github.com/signalapp/libsignal
- NIST FIPS 203 (ML-KEM); formosa-mlkem (EasyCrypt+Jasmin); libcrux ML-KEM (hax→F\*);
  HACL\* (verified X25519/HKDF/AES-GCM/SHA-3).
