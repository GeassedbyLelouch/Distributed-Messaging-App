# Proof sketch — the incremental ML-KEM split is IND-CCA-equivalent to standard ML-KEM

**Artifacts.** `MLKEM_Split.ec` (EasyCrypt skeleton) and this prose.
**Empirical backbone (runnable, and run):** `claude-proofs/kem_split/verify_split_indcca.py`.

**Status.** The EasyCrypt file was authored without a local toolchain and is **not
machine-checked**; every `axiom`/`admit` is an open obligation. The *one* real
obligation (Lemma 1) is discharged **empirically and at scale** by the harness
(1800/1800 byte-for-byte matches), which is strictly stronger than the repo's own
single-message unit test — but is still evidence, not a proof. Do not cite this as
"verified."

---

## 1. Claim

The Braid protocol sends an ML-KEM ciphertext in two pieces:

- `ct1` — the K-PKE `u`-component `Compress_du(Aᵀ·ŷ + e1)`, computable from the
  64-byte **header** `ek_seed ‖ hek` alone (`ek_seed = ρ`, `hek = SHA3-256(ek)`);
- `ct2` — the K-PKE `v`-component `Compress_dv(t̂·ŷ + e2 + μ)`, computable once the
  large `ek_vector = Encode₁₂(t̂)` arrives.

The shared secret `K = G(m ‖ hek)[0:32]` is fixed by phase 1 (`encaps1`) and **never
depends on `ct2`** (verified: `ml_kem.py:196` computes `K` in `encaps1`; `encaps2`
only forms `ct2`).

> **Theorem (split = standard).** For every IND-CCA adversary `A` against the split
> KEM `Σ = (KeyGen, EncapsSplit, Decaps)` there is an IND-CCA adversary `B` against
> standard FIPS-203 ML-KEM `Π` with essentially the same running time and
> `Adv^{cca}_Σ(A) = Adv^{cca}_Π(B)`. The split adds **zero** advantage — it is the
> same KEM with the ciphertext computed in a different program order.

The reduction `B` is the **identity** forwarder. Everything between "trivial" and
"rigorous" is Lemma 1.

---

## 2. Lemma 1 (the only real obligation) — `split_eq`

> For every parameter set `P ∈ {512,768,1024}`, every canonically-encoded
> `ek = ek_vector ‖ ek_seed` with `hek = H(ek)`, and **every** `m ∈ {0,1}²⁵⁶`:
> ```
> let (es, ct1, K) = encaps1(ek_seed, hek; m); ct2 = encaps2(es, ek_seed, ek_vector)
> in  (K, ct1 ‖ ct2) = _encaps_internal(ek, m)        # standard FIPS-203
> ```

**Why it holds (term-by-term, `ml_kem.py:178-237` vs `kyber_py` `_k_pke_encrypt`):**

| Quantity | standard `_encaps_internal` | split `encaps1`/`encaps2` | = |
|---|---|---|:-:|
| FO derive | `(K,r)=G(m‖H(ek))` | `(K,r)=G(m‖hek)`, `hek=H(ek)` | ✔ |
| matrix | `Âᵀ=ExpandA(ρ)ᵀ` | `Âᵀ=ExpandA(ek_seed)ᵀ`, `ek_seed=ρ` | ✔ |
| sample `y,e1,e2` | `SampleCBD(r, N=0,1,…)` | same `r`, same `N` threading | ✔ |
| `u` | `(Âᵀ@ŷ).from_ntt()+e1` | `(a_hat_t@y_hat).from_ntt()+e1` | ✔ |
| `ct1`/`c1` | `u.compress(du).encode(du)` | identical | ✔ |
| `t̂` | `decode_vector(ek[:-32],…)` | `decode_vector(ek_vector,…)` | ✔ |
| `v` | `t̂.dot(ŷ).from_ntt()+e2+μ` | `t_hat.dot(y_hat).from_ntt()+e2+μ` | ✔ |
| `ct2`/`c2` | `v.compress(dv).encode(dv)` | identical | ✔ |

The only difference is *when* `t̂` is decoded and `ct2` formed; the deferral reuses
the **same** `es.y_hat, es.e2, es.m, es.shared_secret` sampled in `encaps1`, so nothing
is re-randomized. ⇒ bit-identical functions of `(ek, m)`.

**Side condition (canonical ek).** `_k_pke_encrypt` re-encodes-and-compares `t̂`
(modulus check); `encaps2` does only a length check on `ek_vector`. Irrelevant for
IND-CCA — the challenger's `ek` is honestly generated (`dkeygen_canonical`) — so the
EasyCrypt `split_eq` is guarded by `is_canonical ek`.

**Empirical discharge (this is what was actually run):**
```
$ uv run python claude-proofs/kem_split/verify_split_indcca.py --trials 200 --keypairs 3
ML-KEM-512  : Lemma1 split==reference 600/600 ; decaps 600/600 ; implicit-reject 600/600
ML-KEM-768  : Lemma1 split==reference 600/600 ; decaps 600/600 ; implicit-reject 600/600
ML-KEM-1024 : Lemma1 split==reference 600/600 ; decaps 600/600 ; implicit-reject 600/600
RESULT: ALL CHECKS PASSED            # 1800 encapsulations, 3 fresh keypairs/variant
```
The repo's own test checks Lemma 1 for a *single* `m = 0x5a·32`; this harness checks
200 random `m` per keypair × 3 keypairs × 3 variants. Still a test, not a proof — the
rigorous discharge ports formosa-mlkem's verified K-PKE encrypt spec (assumption A1).

---

## 3. The reduction and game hops

```
B^{Decaps_Π(dk,·)}(ek, c*, K_b):   run A(ek, c*, K_b); forward each decaps query
                                   c≠c* to Decaps_Π; output A's guess
```
- **Game 0** = `IND-CCA_Σ(A)`: challenge `(c*,K0)` from `EncapsSplit`.
- **Game 1**: replace `EncapsSplit` by standard `Encaps`. By Lemma 1, for the same
  `m ←$ {0,1}²⁵⁶` the map `m ↦ (K,c)` is identical, so Game 1 ≡ Game 0 (perfect
  coupling on `m`). *This hop is the entire split-specific content.*
- **Game 2**: `Σ.Decaps ≡ Π.Decaps` syntactically (both `_decaps_internal`,
  `ml_kem.py:247`), and `B` forwards `A` verbatim ⇒ Game 2 = `IND-CCA_Π(B)`.

Chaining: `Pr[IND-CCA_Σ(A)] = Pr[IND-CCA_Π(B)]`. Perfectly tight, `t_B = t_A + O(1)`.

In the `.ec`: `split_indcca_eq` (admitted, two `byequiv` hops), `split_indcca_adv`
(corollary), `split_indcca_bound` (inherits the formosa-mlkem bound `eps_mlkem`).

---

## 4. Lemma 2 (early-`ct1` ordering is benign)

The IND-CCA game hands `A` the whole `c* = ct1‖ct2` at once, so it already covers "A
sees ct1". The protocol emits `ct1` **before** `ct2` exists; this ordering leaks
nothing extra because:
1. `ct1 = encaps1(ek_seed, hek; m).ct1` is a **deterministic public function** of
   `(ek_seed, hek, m)` — the harness confirms `ct1` recomputes identically from those
   inputs alone, with no `ek_vector` or `dk` dependence (Lemma2 check: 1800/1800);
2. `K = es.shared_secret` is fixed at phase 1 and **independent of `ct2`** (harness
   Lemma2 check: 1800/1800);
3. so a simulator can release `ct1` early and `ct2` later using only the atomic
   challenge `c*`, withholding `ct2` until its time. Splitting the *delivery* of a
   public string across two times cannot increase advantage.

Lemma 2 is a statement about the **message schedule**; its rigorous home is the SCKA
protocol model (the Verifpal/Tamarin artifacts here), not the pure-KEM game.

---

## 5. Assumptions

| # | Obligation | Where discharged |
|---|---|---|
| A1 | FIPS-203 ML-KEM-`P` is IND-CCA (FO over IND-CPA K-PKE / Module-LWE) | **assumed**; concrete proof exists in formosa-mlkem (EasyCrypt→Jasmin) / libcrux (hax→F\*) |
| A2 | **Lemma 1** byte-equality | **open**; empirically 1800/1800 here; rigorous = refine `split_eq` against FIPS-203 Alg. 14 |
| A3 | split `Decaps` ≡ standard `Decaps` | syntactic (`_decaps_internal`) |
| A5 | **Lemma 2** ordering | protocol model (Verifpal/Tamarin) |
| A6 | canonical-`ek` side condition on Lemma 1 | honest-`ek` restriction suffices for IND-CCA |

**Out of every model:** constant-time / side channels (`kyber-py` is *not*
constant-time — see FINDINGS.md F-9), RNG quality of `m ←$`, and the model-to-code gap
for the Python reference (closed only by a verified impl such as libcrux/HACL\*).
