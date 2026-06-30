"""Real ML-KEM incremental interface tests (FIPS-203, via kyber-py primitives)."""

import pytest

from ml_kem_braid.core.ml_kem import MLKEM, MLKEMVariant
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

_REF = {
    MLKEMVariant.ML_KEM_512: ML_KEM_512,
    MLKEMVariant.ML_KEM_768: ML_KEM_768,
    MLKEMVariant.ML_KEM_1024: ML_KEM_1024,
}


@pytest.mark.parametrize("variant", list(MLKEMVariant))
def test_keygen_sizes(variant):
    kem = MLKEM(variant)
    kp = kem.keygen()
    assert len(kp.ek_seed) == 32
    assert len(kp.ek_vector) == kem.params.ek_vector_size
    assert len(kp.hek) == 32
    # ek_seed||ek_vector must round-trip to the canonical ek that hashes to hek.
    assert kem.hek_for(kp.ek_seed, kp.ek_vector) == kp.hek


@pytest.mark.parametrize("variant", list(MLKEMVariant))
def test_incremental_matches_decaps(variant):
    """encaps1/encaps2 must produce a ciphertext that decaps to the same secret."""
    kem = MLKEM(variant)
    kp = kem.keygen()
    es, ct1, ss_enc = kem.encaps1(kp.ek_seed, kp.hek)
    ct2 = kem.encaps2(es, kp.ek_seed, kp.ek_vector)
    assert len(ct1) == kem.params.ct1_size
    assert len(ct2) == kem.params.ct2_size
    ss_dec = kem.decaps(kp.dk, ct1, ct2)
    assert ss_enc == ss_dec
    assert len(ss_dec) == 32


@pytest.mark.parametrize("variant", list(MLKEMVariant))
def test_split_equals_reference_monolithic(variant):
    """
    The Braid split must yield EXACTLY the standard FIPS-203 ciphertext for the
    same message m, proving it is real ML-KEM and not a look-alike.
    """
    kem = MLKEM(variant)
    ref = _REF[variant]
    ek, dk = ref.keygen()
    ek_vector, ek_seed = ek[:-32], ek[-32:]
    hek = ref._H(ek)

    m = b"\x5a" * 32
    es, ct1, ss = kem.encaps1(ek_seed, hek, m=m)
    ct2 = kem.encaps2(es, ek_seed, ek_vector)

    # Reference monolithic encapsulation with the same m.
    ref_K, ref_c = ref._encaps_internal(ek, m)
    assert ct1 + ct2 == ref_c, "incremental split diverges from FIPS-203 ciphertext"
    assert ss == ref_K
    assert ref.decaps(dk, ct1 + ct2) == ss


def test_wrong_ciphertext_implicit_rejection():
    """Tampered ciphertext must yield a different (rejection) secret, not crash."""
    kem = MLKEM(MLKEMVariant.ML_KEM_768)
    kp = kem.keygen()
    es, ct1, ss = kem.encaps1(kp.ek_seed, kp.hek)
    ct2 = kem.encaps2(es, kp.ek_seed, kp.ek_vector)
    bad_ct2 = bytes(b ^ 0xFF for b in ct2)
    rejected = kem.decaps(kp.dk, ct1, bad_ct2)
    assert rejected != ss  # implicit rejection -> pseudorandom key
