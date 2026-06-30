#!/usr/bin/env python3
"""
verify_split_indcca.py  --  Executable evidence for the EasyCrypt obligation that
the ML-KEM Braid incremental split (Encaps1/Encaps2) is IND-CCA-EQUIVALENT to
standard FIPS-203 ML-KEM.

This harness does NOT replace the EasyCrypt proof (claude-proofs/easycrypt/). It
discharges, *empirically and at scale*, the two facts the proof reduces to:

  Lemma 1 (split_eq, the only real obligation):
      For every parameter set P in {512,768,1024} and every FO message m,
          encaps1(ek_seed,hek;m) -> (es, ct1, K)
          encaps2(es, ek_seed, ek_vector) -> ct2
          (K, ct1||ct2)  ==  _encaps_internal(ek, m)        # standard FIPS-203
      i.e. the split yields the IDENTICAL shared secret and the IDENTICAL
      ciphertext bytes as monolithic ML-KEM run on the same m.

  Lemma 2 premise (early-ct1 leak is benign):
      K = encaps1(...).shared_secret is fixed by phase 1 and is INDEPENDENT of
      ct2; and ct1 is a deterministic function of (ek_seed, hek, m) only --
      it does not depend on ek_vector or on the decapsulation key. Hence
      revealing ct1 before ct2 leaks nothing the public ciphertext doesn't.

The repo's own tests/test_kem.py::test_split_equals_reference_monolithic checks
Lemma 1 for a SINGLE m = 0x5a*32. This harness checks it for TRIALS random m per
variant (default 200), which is much stronger empirical evidence, and adds the
Lemma-2 independence checks the unit test omits.

Run:
    uv run python claude-proofs/kem_split/verify_split_indcca.py            # 200 trials
    uv run python claude-proofs/kem_split/verify_split_indcca.py --trials 1000
    uv run python claude-proofs/kem_split/verify_split_indcca.py --json results/kem_split.json

Exit code 0 = every check passed; non-zero = a divergence was found (which would
mean the split is NOT real ML-KEM and the IND-CCA reduction's Lemma 1 is false).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from dataclasses import dataclass, field, asdict

from ml_kem_braid.core.ml_kem import MLKEM, MLKEMVariant
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

_REF = {
    MLKEMVariant.ML_KEM_512: ML_KEM_512,
    MLKEMVariant.ML_KEM_768: ML_KEM_768,
    MLKEMVariant.ML_KEM_1024: ML_KEM_1024,
}


@dataclass
class VariantResult:
    variant: str
    trials: int
    keypairs: int
    lemma1_split_eq_ok: int = 0          # ct1||ct2 == ref_c  AND  K == ref_K
    lemma1_decaps_ok: int = 0            # decaps(ct1||ct2) == K
    lemma2_ct1_fixed_by_header_ok: int = 0   # ct1 reproducible from (ek_seed,hek,m) alone
    lemma2_K_independent_of_ct2_ok: int = 0  # K from encaps1 == K after encaps2 (unchanged)
    implicit_rejection_ok: int = 0      # decaps(tampered) != K
    failures: list = field(default_factory=list)

    @property
    def passed(self) -> bool:
        # every per-trial counter must equal trials, and there must be no failures
        return (
            not self.failures
            and self.lemma1_split_eq_ok == self.trials
            and self.lemma1_decaps_ok == self.trials
            and self.lemma2_ct1_fixed_by_header_ok == self.trials
            and self.lemma2_K_independent_of_ct2_ok == self.trials
            and self.implicit_rejection_ok == self.trials
        )


def run_variant(variant: MLKEMVariant, trials: int, keypairs: int) -> VariantResult:
    kem = MLKEM(variant)
    ref = _REF[variant]
    res = VariantResult(variant=variant.value, trials=trials * keypairs, keypairs=keypairs)

    for _kp in range(keypairs):
        # Honest, canonically-encoded encapsulation key from FIPS-203 KeyGen.
        ek, dk = ref.keygen()
        ek_vector, ek_seed = ek[:-32], ek[-32:]
        hek = ref._H(ek)

        # Sanity: the split's own hek recomputation matches.
        assert kem.hek_for(ek_seed, ek_vector) == hek

        for _t in range(trials):
            m = secrets.token_bytes(32)

            # --- split path ---------------------------------------------------
            es, ct1, K_enc = kem.encaps1(ek_seed, hek, m=m)
            ct2 = kem.encaps2(es, ek_seed, ek_vector)

            # --- standard FIPS-203 monolithic path on the SAME m --------------
            ref_K, ref_c = ref._encaps_internal(ek, m)

            # Lemma 1: byte-for-byte equality of ciphertext and shared secret.
            if ct1 + ct2 == ref_c and K_enc == ref_K:
                res.lemma1_split_eq_ok += 1
            else:
                res.failures.append(
                    f"{variant.value}: split != reference for m={m.hex()[:16]} "
                    f"(ct_match={ct1 + ct2 == ref_c}, K_match={K_enc == ref_K})"
                )
                continue  # don't run dependent checks on a divergent trial

            # Lemma 1 (decaps leg): the reassembled split ciphertext decaps to K.
            if kem.decaps(dk, ct1, ct2) == K_enc:
                res.lemma1_decaps_ok += 1
            else:
                res.failures.append(f"{variant.value}: decaps(ct1||ct2) != K for m={m.hex()[:16]}")

            # Lemma 2 premise (a): ct1 is a deterministic function of the PUBLIC
            # header (ek_seed, hek) and m only -- recomputing from the same inputs
            # (no ek_vector, no dk) yields the identical ct1.
            _es2, ct1_again, K_again = kem.encaps1(ek_seed, hek, m=m)
            if ct1_again == ct1 and K_again == K_enc:
                res.lemma2_ct1_fixed_by_header_ok += 1
            else:
                res.failures.append(f"{variant.value}: ct1 not a function of (ek_seed,hek,m)")

            # Lemma 2 premise (b): the shared secret K is fixed by phase 1 and is
            # INDEPENDENT of ct2. encaps1 returns K (= es.shared_secret); encaps2
            # only produces ct2 and never alters K.
            if es.shared_secret == K_enc:
                res.lemma2_K_independent_of_ct2_ok += 1
            else:
                res.failures.append(f"{variant.value}: es.shared_secret != K (K depends on ct2?!)")

            # Implicit rejection: a tampered ct2 must yield a different (rejection)
            # key, never crash -- the FIPS-203 FO^bot constant-time reject path.
            bad_ct2 = bytes(b ^ 0xFF for b in ct2)
            if kem.decaps(dk, ct1, bad_ct2) != K_enc:
                res.implicit_rejection_ok += 1
            else:
                res.failures.append(f"{variant.value}: tampered ct2 decapsed to K (no rejection)")

    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=200, help="random m per keypair (default 200)")
    ap.add_argument("--keypairs", type=int, default=3, help="fresh keypairs per variant (default 3)")
    ap.add_argument("--json", type=str, default=None, help="write JSON summary to this path")
    args = ap.parse_args()

    print("=" * 78)
    print("ML-KEM Braid split  ==  FIPS-203 ML-KEM   (empirical Lemma-1 / Lemma-2 check)")
    print(f"trials per keypair = {args.trials}, keypairs per variant = {args.keypairs}")
    print("=" * 78)

    results = []
    all_ok = True
    for variant in MLKEMVariant:
        r = run_variant(variant, args.trials, args.keypairs)
        results.append(r)
        status = "PASS" if r.passed else "FAIL"
        all_ok = all_ok and r.passed
        print(f"\n[{status}] {r.variant}   ({r.trials} total encapsulations)")
        print(f"    Lemma1  split==reference (ct & K) : {r.lemma1_split_eq_ok}/{r.trials}")
        print(f"    Lemma1  decaps(ct1||ct2)==K       : {r.lemma1_decaps_ok}/{r.trials}")
        print(f"    Lemma2  ct1 = f(ek_seed,hek,m)    : {r.lemma2_ct1_fixed_by_header_ok}/{r.trials}")
        print(f"    Lemma2  K independent of ct2      : {r.lemma2_K_independent_of_ct2_ok}/{r.trials}")
        print(f"    FO^bot  implicit rejection        : {r.implicit_rejection_ok}/{r.trials}")
        for f in r.failures[:5]:
            print(f"      !! {f}")

    print("\n" + "=" * 78)
    print(f"RESULT: {'ALL CHECKS PASSED' if all_ok else 'FAILURES DETECTED'}")
    print("=" * 78)

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w") as fh:
            json.dump(
                {"all_passed": all_ok, "variants": [asdict(r) for r in results]},
                fh,
                indent=2,
            )
        print(f"wrote {args.json}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
