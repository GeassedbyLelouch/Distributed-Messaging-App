import pytest
from ml_kem_braid.attestation.policy import IdentityPolicy, SgxPolicy

def test_identity_policy_holds_key():
    p = IdentityPolicy(trusted_identity=b"\x01" * 32)
    assert p.trusted_identity == b"\x01" * 32

def test_sgx_policy_requires_root_and_allowlist():
    with pytest.raises(ValueError):
        SgxPolicy(pinned_root_der=b"", mrenclave_allow=frozenset({b"\x00" * 32}),
                  mrsigner_allow=frozenset(), min_isv_svn=0)
    with pytest.raises(ValueError):
        SgxPolicy(pinned_root_der=b"root", mrenclave_allow=frozenset(),
                  mrsigner_allow=frozenset(), min_isv_svn=0)

def test_sgx_policy_valid():
    p = SgxPolicy(pinned_root_der=b"root", mrenclave_allow=frozenset({b"\xaa" * 32}),
                  mrsigner_allow=frozenset(), min_isv_svn=3)
    assert p.min_isv_svn == 3
