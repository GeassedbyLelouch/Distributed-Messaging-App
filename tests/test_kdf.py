"""HKDF (RFC 5869) known-answer tests locking down the hand-rolled implementation."""

import pytest

from ml_kem_braid.core.kdf import hkdf, hkdf_expand, hkdf_extract


def _h(s: str) -> bytes:
    return bytes.fromhex(s)


# RFC 5869 Appendix A.1 — Basic test case with SHA-256
A1_IKM = _h("0b" * 22)
A1_SALT = _h("000102030405060708090a0b0c")
A1_INFO = _h("f0f1f2f3f4f5f6f7f8f9")
A1_PRK = _h("077709362c2e32df0ddc3f0dc47bba63" "90b6c73bb50f9c3122ec844ad7c2b3e5")
A1_OKM = _h(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)

# RFC 5869 Appendix A.2 — Test with SHA-256 and longer inputs/outputs
A2_IKM = _h("".join(f"{i:02x}" for i in range(80)))
A2_SALT = _h("".join(f"{i:02x}" for i in range(0x60, 0x60 + 80)))
A2_INFO = _h("".join(f"{i:02x}" for i in range(0xB0, 0xB0 + 80)))
A2_PRK = _h("06a6b88c5853361a06104c9ceb35b45c" "ef760014904671014a193f40c15fc244")
A2_OKM = _h(
    "b11e398dc80327a1c8e7f78c596a4934"
    "4f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09"
    "da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f"
    "1d87"
)

# RFC 5869 Appendix A.3 — Test with SHA-256 and zero-length salt/info
A3_IKM = _h("0b" * 22)
A3_PRK = _h("19ef24a32c717b167f33a91d6f648bdf" "96596776afdb6377ac434c1c293ccb04")
A3_OKM = _h(
    "8da4e775a563c18f715f802a063c5a31"
    "b8a11f5c5ee1879ec3454e5f3c738d2d"
    "9d201395faa4b61a96c8"
)


@pytest.mark.parametrize(
    "ikm,salt,info,length,prk,okm",
    [
        (A1_IKM, A1_SALT, A1_INFO, 42, A1_PRK, A1_OKM),
        (A2_IKM, A2_SALT, A2_INFO, 82, A2_PRK, A2_OKM),
        (A3_IKM, b"", b"", 42, A3_PRK, A3_OKM),
    ],
    ids=["rfc5869-A.1", "rfc5869-A.2", "rfc5869-A.3"],
)
def test_rfc5869_known_answers(ikm, salt, info, length, prk, okm):
    assert hkdf_extract(salt, ikm) == prk
    assert hkdf_expand(prk, info, length) == okm
    assert hkdf(ikm, salt, info, length) == okm


def test_hkdf_expand_rejects_more_than_255_blocks():
    prk = A1_PRK
    assert len(hkdf_expand(prk, b"", 255 * 32)) == 255 * 32
    with pytest.raises(ValueError):
        hkdf_expand(prk, b"", 255 * 32 + 1)


def test_hkdf_expand_is_a_prefix_chain():
    """OKM of length L must be the prefix of any longer OKM (T(i) chain property)."""
    long_okm = hkdf_expand(A1_PRK, A1_INFO, 96)
    for length in (1, 32, 33, 64, 95):
        assert hkdf_expand(A1_PRK, A1_INFO, length) == long_okm[:length]
