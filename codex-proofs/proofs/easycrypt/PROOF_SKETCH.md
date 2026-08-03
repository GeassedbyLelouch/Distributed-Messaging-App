# Proof Sketch — The Incremental ML-KEM Split is IND-CCA-Secure

**Artifact:** `formal/easycrypt/PROOF_SKETCH.md` (this file) and the accompanying
EasyCrypt skeleton `formal/easycrypt/MLKEM_Split.ec`.

**Status:** SCAFFOLD / PLAN. **Nothing here has been machine-checked.** No EasyCrypt
toolchain was run while producing this document. Every claim that would normally be
discharged by a prover is marked with a `TODO`, `admit`, or `sorry` marker, and the
remaining human work is spelled out in §8. Do **not** cite this as "verified" or
"proven" — it is a reduction argument written out in prose plus an EasyCrypt
skeleton that a human must complete and `easycrypt`-check.

**Normative inputs (read these for byte-exact detail):**
- `docs/PROTOCOL_SPEC.md` §2 ("ML-KEM Braid SCKA → Incremental ML-KEM").
- `ml_kem_braid/core/ml_kem.py` — the split implementation (`encaps1`, `encaps2`,
  `decaps`).
- `tests/test_kem.py::test_split_equals_reference_monolithic` — the empirical
  byte-equality check that this proof must replace with a real lattice-equation proof.
- `kyber_py/ml_kem/ml_kem.py` — the backing FIPS-203 primitives
  (`_k_pke_encrypt`, `_encaps_internal`, `_decaps_internal`, `_G`, `_H`). The split is
  a re-ordering of `_k_pke_encrypt`; the proof's central lemma is a statement about
  these two code paths producing identical bytes.

---

## 1. What is being claimed (informal)

The Braid protocol needs to send an ML-KEM ciphertext in **two pieces**:

- `ct1` (the K-PKE `u`-component, `Compress_du(Aᵀ·ŷ + e1)`), computable from the
  64-byte **header** `ek_seed ‖ hek` alone (`ek_seed = ρ`, `hek = SHA3-256(ek)`); and
- `ct2` (the K-PKE `v`-component, `Compress_dv(t̂·ŷ + e2 + μ)`), computable once the
  large `ek_vector = Encode₁₂(t̂)` arrives.

The shared secret `K = G(m ‖ hek)[0:32]` is fixed by phase 1 (`encaps1`) and never
depends on `ct2`. This split lets the protocol overlap network round-trips (it can
emit `ct1` before it has received `ek_vector`).

**Claim (IND-CCA of the split).** The split KEM — `(KeyGen, EncapsSplit, Decaps)`,
where `EncapsSplit` is "run `encaps1` to get `(es, ct1, K)`, then `encaps2(es,·)` to
get `ct2`, and output `(K, ct1 ‖ ct2)`" — is IND-CCA-secure, with advantage equal to
that of an IND-CCA adversary against the standard FIPS-203 ML-KEM of the same
parameter set. In particular the split adds **zero** advantage: it is *the same KEM*
with the ciphertext computed in a different program order.

**Claim (the early-`ct1` leak is benign).** Revealing `ct1` to the adversary *before*
`ct2` is produced leaks nothing beyond what the full public ciphertext `ct1 ‖ ct2`
already leaks, because (a) `ct1` is a deterministic public function of `(ek_seed, m)`
and (b) the full ciphertext is transmitted in the clear anyway.

---

## 2. Notation and the two security games

Fix an ML-KEM parameter set `P ∈ {512, 768, 1024}` (`k, η₁, η₂, du, dv` as in
FIPS-203). Let `Π = (KeyGen, Encaps, Decaps)` be **standard FIPS-203 ML-KEM** for `P`
(in the code: `kyber_py`'s `ML_KEM_<P>` via `_encaps_internal` / `_decaps_internal`).

Define the **split KEM** `Σ = (KeyGen, EncapsSplit, Decaps)` with the *same* `KeyGen`
and *same* `Decaps`, and

```
EncapsSplit(ek):
    (ek_vector, ek_seed) = (ek[:-32], ek[-32:])
    hek                  = H(ek)                       # SHA3-256(ek)
    m  ←$ {0,1}^256                                    # FO message
    (es, ct1, K) = encaps1(ek_seed, hek; m)            # u-component + K
    ct2          = encaps2(es, ek_seed, ek_vector)     # v-component
    return (K, ct1 ‖ ct2)
```

`Decaps(dk, c) = _decaps_internal(dk, c)` for both — identical, including the
modulus/type checks and constant-time implicit rejection.

**IND-CCA game** `Game_INDCCA^{KEM}(A)` (real-or-random key, standard formulation):

```
(ek, dk) ← KeyGen()
b        ←$ {0,1}
(K0, c*) ← Encaps(ek)        # honest encapsulation
K1       ←$ K                # uniform shared-secret space ({0,1}^256)
b'       ← A^{Decaps(dk,·) excluding c*}(ek, c*, K_b)
return [b' = b]
```

`Adv^{INDCCA}_{KEM}(A) = | Pr[Game = 1] − 1/2 |`. The decapsulation oracle answers any
`c ≠ c*` (the standard "no challenge query" restriction).

---

## 3. Theorem

> **Theorem (split = standard).** For every IND-CCA adversary `A` against the split
> KEM `Σ` there is an IND-CCA adversary `B` against standard FIPS-203 ML-KEM `Π`, with
> essentially the same running time, such that
>
> ```
> Adv^{INDCCA}_{Σ}(A) = Adv^{INDCCA}_{Π}(B(A)).
> ```
>
> Consequently `Adv^{INDCCA}_{Σ}(A) ≤ Adv^{INDCCA}_{ML-KEM-P}(B)`, and the split is
> IND-CCA-secure under exactly the FIPS-203 ML-KEM IND-CCA assumption (which itself
> reduces, via the Fujisaki–Okamoto / `FO^{⊥}_m` transform, to the IND-CPA security of
> K-PKE, i.e. to Module-LWE; see formosa-mlkem / libcrux references in §7).

The reduction is the **identity** reduction: `B` forwards `A`'s queries verbatim. The
only thing standing between "trivial" and "rigorous" is the byte-equality lemma below,
which guarantees that `B`'s view (built from the *standard* `Encaps`) is identical to
the view `A` expects (built from the *split* `EncapsSplit`).

---

## 4. The central lemma (the one real obligation)

> **Lemma 1 (byte-for-byte equality).** For every parameter set `P`, every valid
> encapsulation key `ek = ek_vector ‖ ek_seed` (`= Encode₁₂(t̂) ‖ ρ`) with
> `hek = H(ek)`, and **every** message `m ∈ {0,1}^256`:
>
> ```
> let (es, ct1, K) = encaps1(ek_seed, hek; m)
>     ct2          = encaps2(es, ek_seed, ek_vector)
> in  (K, ct1 ‖ ct2)  =  _encaps_internal(ek, m)        # standard FIPS-203
> ```
>
> i.e. the split produces the **identical** shared secret `K` and the **identical**
> ciphertext bytes as standard ML-KEM run on the same `m`.

**Why it is true (the lattice-equation argument a human must formalize).**
Compare `encaps1`+`encaps2` (`ml_kem_braid/core/ml_kem.py:178-237`) against
`_k_pke_encrypt` + the `K,r = G(m‖H(ek))` line of `_encaps_internal`
(`kyber_py/ml_kem/ml_kem.py:215-265, 350-361`). Term by term:

| Quantity | Standard `_encaps_internal`/`_k_pke_encrypt` | Split `encaps1`/`encaps2` | Equal? |
|---|---|---|---|
| FO derive | `(K, r) = G(m ‖ H(ek))` | `(K, r) = G(m ‖ hek)`, `hek = H(ek)` | ✔ same `H(ek)`, same `G` ⇒ same `(K,r)` |
| matrix | `Â ᵀ = ExpandA(ρ)ᵀ` | `Â ᵀ = ExpandA(ek_seed)ᵀ`, `ek_seed = ρ` | ✔ |
| sample `y` | `y,N = SampleCBD_{η₁}(r, N=0)` | same call, same `r`, `N=0` | ✔ identical counter sequence |
| sample `e1` | `e1,N = SampleCBD_{η₂}(r, N)` | same | ✔ same `N` threading |
| sample `e2` | `e2,N = SampleCBD_{η₂}(r, N)` (poly) | same | ✔ same `N` threading |
| `ŷ` | `y.to_ntt()` | `y.to_ntt()` | ✔ |
| `u` | `(Âᵀ @ ŷ).from_ntt() + e1` | `(a_hat_t @ y_hat).from_ntt() + e1` | ✔ |
| `ct1`/`c1` | `u.compress(du).encode(du)` | `u.compress(du).encode(du)` | ✔ |
| `t̂` | `decode_vector(ek[:-32], k, 12, ntt)` | `decode_vector(ek_vector, k, 12, ntt)` | ✔ same bytes |
| `μ` | `R.decode(m,1).decompress(1)` | `R.decode(m,1).decompress(1)` | ✔ |
| `v` | `t̂.dot(ŷ).from_ntt() + e2 + μ` | `t_hat.dot(y_hat).from_ntt() + e2 + μ` | ✔ |
| `ct2`/`c2` | `v.compress(dv).encode(dv)` | `v.compress(dv).encode(dv)` | ✔ |
| output | `K, c1 ‖ c2` | `K, ct1 ‖ ct2` | ✔ |

The **only** semantic difference between the two programs is *when* `t̂` is decoded
and `ct2` formed (split defers it to `encaps2`); the deferral consumes the **same**
`es.y_hat`, `es.e2`, `es.m`, `es.shared_secret` sampled in `encaps1`, so no value is
re-randomized. Therefore the outputs are bit-identical functions of `(ek, m)`.

> **Caveat (input-validation surface).** Standard `_encaps_internal` performs the
> FIPS-203 **type check** and **modulus check** inside `_k_pke_encrypt`
> (`kyber_py/ml_kem/ml_kem.py:230-245`). The split performs the modulus check only
> implicitly: `encaps2` does a *length* check on `ek_vector` and then `decode_vector`,
> but does **not** re-encode-and-compare `t̂` the way `_k_pke_encrypt` does
> (`t_hat.encode(12) != t_hat_bytes`). For Lemma 1 this is irrelevant for *honest*,
> canonically-encoded keys (the only case the IND-CCA game uses — `ek` comes from
> `KeyGen`), but a human formalizing Lemma 1 must either (i) restrict the lemma's `ek`
> to canonically-encoded keys (sufficient for IND-CCA, since the challenger's `ek` is
> honestly generated), or (ii) prove the split rejects non-canonical `t̂` identically.
> This is recorded as `TODO-VALIDATION` in §8 and as a side condition on `axiom
> split_eq` in the `.ec` file. It does **not** affect the IND-CCA reduction because
> only the honest `ek` is encapsulated against.

**Current status of Lemma 1:** established **only empirically**, by
`tests/test_kem.py::test_split_equals_reference_monolithic`, which checks
`ct1 + ct2 == ref_c` and `ss == ref_K` for a *single* `m = 0x5a·32` across the three
parameter sets. That is a unit test, **not a proof**. A human must discharge Lemma 1
from the K-PKE algebraic equations (Algorithm 14, FIPS-203), ideally by *reusing the
existing machine-checked K-PKE encrypt spec* in formosa-mlkem / libcrux rather than
re-deriving the lattice algebra from scratch (see §7).

---

## 5. The reduction `B` and the game hops

`B` plays `Game_INDCCA^{Π}` (standard ML-KEM) and simulates `Game_INDCCA^{Σ}` (split)
for `A`:

```
B^{Decaps_Π(dk,·)}(ek, c*, K_b):           // inputs are B's own challenge
    // ek, c*, K_b were produced by the STANDARD challenger
    run A(ek, c*, K_b):
        on A's decaps query c (c ≠ c*):  forward to Decaps_Π(dk, c); return answer
        on A's final guess b':           output b'
```

`B` makes no modification to any value. The proof that `B`'s simulation is perfect is
a sequence of game hops:

- **Game 0 = `Game_INDCCA^{Σ}(A)`.** The challenge `(c*, K_0)` is produced by
  `EncapsSplit(ek)`; the oracle is `Σ.Decaps = _decaps_internal`.

- **Game 1.** Replace `EncapsSplit(ek)` by `Encaps(ek)` (standard). By **Lemma 1**,
  for the *same* random `m`, the two produce identical `(K, c)` distributions — the
  challenge is sampled from `m ←$ {0,1}^256` in both, and Lemma 1 says the map
  `m ↦ (K, c)` is the same function. Hence Game 1 and Game 0 are
  **perfectly indistinguishable**: `Pr[Game1=1] = Pr[Game0=1]`.
  *(This hop is the entire content of the split-specific argument.)*

- **Game 2.** Observe `Σ.Decaps ≡ Π.Decaps` *syntactically* (both call
  `_decaps_internal`, `ml_kem_braid/core/ml_kem.py:241-247`), so the decapsulation
  oracle in Game 1 is already exactly `Π`'s oracle. Game 2 = `Game_INDCCA^{Π}(B)`
  with `B` the identity forwarder above. `Pr[Game2=1] = Pr[Game1=1]`.

Chaining: `Pr[Game_Σ(A)=1] = Pr[Game_Π(B)=1]`, hence
`Adv^{INDCCA}_{Σ}(A) = Adv^{INDCCA}_{Π}(B)`. ∎ (modulo Lemma 1)

**Tightness.** The reduction is perfectly tight (advantage-preserving, no factor) and
runs in time `t_B = t_A + O(1)` — `B` does no extra cryptographic work.

---

## 6. The "early `ct1` leak" argument (separate, weaker obligation)

The IND-CCA game above hands the adversary the *whole* ciphertext `c* = ct1 ‖ ct2` at
once, so it already covers "the adversary sees `ct1`". The protocol, however, emits
`ct1` on the wire *before* `ct2` exists (it is produced from the header before
`ek_vector` arrives). We must argue this **ordering** leaks nothing extra.

> **Lemma 2 (no early-leak advantage).** In the SCKA protocol game where the
> network adversary observes `ct1` at time `t1` and `ct2` at a later time `t2 > t1`,
> the adversary's view is a deterministic function of the view in which it observes
> the pair `(ct1, ct2)` together at `t2`. Hence any attack using the early `ct1` is an
> attack against the standard (atomic-ciphertext) KEM with the same advantage.

**Justification.**
1. `ct1 = encaps1(ek_seed, hek; m).ct1` is a *deterministic, public* function of
   `(ek_seed, hek, m)`; `ek_seed` and `hek` are public header fields and `m` is the
   per-encapsulation FO randomness. The adversary could itself compute `ct1` from
   `(ek_seed, hek)` and *any candidate* `m`; it carries no secret-key-dependent
   information beyond what `c* = ct1‖ct2` already reveals.
2. `K = encaps1(...).shared_secret` is fixed at `t1` and is **independent of `ct2`**;
   so no "future" message changes the secret being challenged. The challenge key is
   well-defined the moment `ct1` is produced.
3. Therefore a simulator can answer the adversary at `t1` with `ct1` and at `t2` with
   `ct2`, using only the atomic challenge `c* = ct1‖ct2` it received from the standard
   KEM challenger (it simply withholds `ct2` until `t2`). Splitting the *delivery* of
   a public string across two times cannot increase advantage — formally, any
   functionality computable from `(ct1 @ t1, ct2 @ t2)` is computable from
   `(ct1‖ct2 @ t2)` together with the clock, because `ct1` is a public prefix.

**Modeling caveat.** Lemma 2 is *not* the same as Lemma 1 + the IND-CCA theorem; it is
a statement about the **protocol's message schedule**, which is outside the pure-KEM
IND-CCA game. The rigorous home for Lemma 2 is the SCKA Tamarin/EasyCrypt model where
message ordering is explicit (see `docs/PROTOCOL_SPEC.md` §2 and §A). In this artifact
Lemma 2 is stated and argued informally and is left as `TODO-EARLYLEAK` (§8). The
KEM-level Theorem (§3) is the load-bearing result; Lemma 2 only certifies that the
*ordering* the Braid SCKA imposes does not break that result.

---

## 7. Assumptions, and where to discharge them

| # | Assumption / obligation | Discharge venue |
|---|---|---|
| A1 | FIPS-203 ML-KEM-`P` is IND-CCA-secure (FO transform over IND-CPA K-PKE, Module-LWE). | **Assumed** (standard). Computational backing exists in EasyCrypt: the **formosa-mlkem** project (`github.com/formosa-crypto/formosa-mlkem`) machine-checks ML-KEM IND-CCA in EasyCrypt down to the Jasmin implementation; **libcrux**/`hax` provides an F\*/Rust-side proof. Cite, do not re-prove. |
| A2 | **Lemma 1** byte-equality (split = `_encaps_internal`). | **Open — the one real obligation.** Discharge against FIPS-203 Algorithm 14 (K-PKE.Encrypt). Best path: prove the split's `encaps1`/`encaps2` refine the *same* K-PKE encrypt function already specified in formosa-mlkem's EasyCrypt `Kyber` theory, by showing the two programs compute the same `(u, v)` polynomials. In the `.ec` skeleton it is `axiom split_eq` (an `admit`). |
| A3 | `Decaps` of split ≡ `Decaps` of standard. | **Trivial / syntactic** — both call `_decaps_internal`; in the `.ec` it is `axiom decaps_eq`, justified by code identity (`ml_kem.py:247`). Still mark `admit` until checked. |
| A4 | `H = SHA3-256`, `G = SHA3-512` modeled as the FIPS-203 hashes (ROM as in the FO proof). | Inherited from A1's model; the split uses the **same** `H`,`G` so nothing new is assumed. |
| A5 | **Lemma 2** (early-`ct1` ordering is benign). | **Open** — protocol-level; discharge in the SCKA model, not the KEM game. `TODO-EARLYLEAK`. |
| A6 | Input-validation surface of `encaps2` (non-canonical `t̂`). | Side condition on Lemma 1; honest-`ek` restriction suffices for IND-CCA. `TODO-VALIDATION`. |

**Out of model (must be handled elsewhere, per `docs/PROTOCOL_SPEC.md` §A):**
constant-time / side channels (`kyber-py` is *not* constant-time — this is a spec-level
result, not an implementation guarantee), RNG quality of `m ←$`, and the model-to-code
gap for the Python reference (only closed by a verified implementation such as
libcrux/HACL\*).

---

## 8. What a human must finish (checklist)

- [ ] **`TODO-LEMMA1` (A2, the real work):** Replace `axiom split_eq` in
  `MLKEM_Split.ec` with a proof. Recommended: import/port the K-PKE encrypt spec from
  formosa-mlkem and prove `encaps1 ∘ encaps2` equals it pointwise in `(u, v)`. The §4
  table is the term-by-term skeleton of that proof. Until then the empirical
  `test_split_equals_reference_monolithic` is the *only* evidence and must not be
  called a proof.
- [ ] **`TODO-VALIDATION` (A6):** State Lemma 1 over canonically-encoded `ek` (or prove
  `encaps2` rejects non-canonical `t̂` exactly as `_k_pke_encrypt` does). Add the side
  condition to `axiom split_eq`.
- [ ] **`TODO-DECAPS` (A3):** Discharge `axiom decaps_eq` by code identity
  (both = `_decaps_internal`). Trivial but must be checked, not assumed.
- [ ] **`TODO-EARLYLEAK` (A5):** Formalize Lemma 2 in the SCKA protocol model
  (Tamarin/EasyCrypt with explicit message ordering), not in the pure KEM game.
- [ ] **`TODO-INDCCA-A1`:** Decide whether to *assume* ML-KEM IND-CCA as an axiom
  (`axiom mlkem_indcca`) or to instantiate it from formosa-mlkem. The skeleton assumes
  it; flip to instantiation if you import their theory.
- [ ] **`TODO-TYPECHECK`:** Run `easycrypt` on `MLKEM_Split.ec` and fix syntax (the
  skeleton was written without a checker installed and is *not* guaranteed to parse).

---

## 9. How to check this (tooling)

```bash
# Install EasyCrypt (https://www.easycrypt.info/). Typical opam route:
opam pin add -n easycrypt https://github.com/EasyCrypt/easycrypt.git
opam install easycrypt
easycrypt why3config            # configure SMT backends (Z3, Alt-Ergo, CVC5)

# Check the skeleton (expect FAILURES at every `admit`/`axiom` until discharged):
easycrypt -I . MLKEM_Split.ec
```

**Expected output today:** EasyCrypt will *load* the file if the syntax is correct, and
report each `admit`/`axiom` as an unproven obligation (it will **not** error on
`admit`, it accepts it as a hole). It will print nothing resembling "Qed/closed proof"
for the main theorem until `TODO-LEMMA1`/`TODO-DECAPS` are discharged. If you see
parse/type errors, that is `TODO-TYPECHECK` — the file was authored without a local
checker. **Do not** interpret a clean *load* of a file full of `admit`s as a proof.
