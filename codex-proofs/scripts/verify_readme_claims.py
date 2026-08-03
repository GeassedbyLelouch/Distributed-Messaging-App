#!/usr/bin/env python3
"""Check README-backed protocol claims against local code and tests.

This is a lightweight audit script, not a proof.  It verifies that the
README's cryptographic claims point to concrete implementation hooks:
KDF labels, identity binding, OPK consumption, transactional ratchets,
Double Ratchet direction separation, and regression tests.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path


SCRIPT = Path(__file__).resolve()
PACKAGE_ROOT = SCRIPT.parents[2]
REPO_ROOT = PACKAGE_ROOT.parent


@dataclass
class Check:
    name: str
    ok: bool
    evidence: list[str]
    detail: str = ""


def read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def contains(text: str, *needles: str) -> bool:
    return all(n in text for n in needles)


def line_refs(rel: str, *needles: str) -> list[str]:
    path = REPO_ROOT / rel
    lines = path.read_text(encoding="utf-8").splitlines()
    refs: list[str] = []
    for needle in needles:
        for idx, line in enumerate(lines, 1):
            if needle in line:
                refs.append(f"{rel}:{idx}: {line.strip()}")
                break
        else:
            refs.append(f"{rel}:?: missing {needle!r}")
    return refs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    readme = read("README.md")
    pqxdh = read("ml_kem_braid/pqxdh/pqxdh.py")
    mlkem = read("ml_kem_braid/core/ml_kem.py")
    kdf = read("ml_kem_braid/core/kdf.py")
    auth = read("ml_kem_braid/core/authenticator.py")
    dr = read("ml_kem_braid/core/double_ratchet.py")
    client = read("ml_kem_braid/client/client.py")
    server = read("ml_kem_braid/server/app.py")
    store = read("ml_kem_braid/sesame/store.py")
    sqlite_store = read("ml_kem_braid/sesame/sqlite_store.py")
    test_kem = read("tests/test_kem.py")
    test_security = read("tests/test_security_fixes.py")
    test_dr = read("tests/test_double_ratchet.py")
    formal_plan = read("docs/FORMAL_VERIFICATION.md")

    checks = [
        Check(
            "PQXDH uses ML-KEM-1024 and identity-bound HKDF info",
            contains(readme, "ML-KEM-1024", "info=`PQXDH_INFO") and
            contains(pqxdh, "PQXDH_KEM = ML_KEM_1024", "info = PQXDH_INFO + ik_a_sign + ik_b_sign"),
            line_refs(
                "README.md",
                "| PQXDH handshake | X25519",
                "| **Authenticated handshake** |",
            ) + line_refs(
                "ml_kem_braid/pqxdh/pqxdh.py",
                "PQXDH_KEM = ML_KEM_1024",
                "info = PQXDH_INFO + ik_a_sign + ik_b_sign",
            ),
        ),
        Check(
            "Responder verifies initiator DH identity binding",
            contains(pqxdh, "message.ik_dh_sig, message.ik_dh_pub") and
            contains(test_security, "test_responder_rejects_unbound_initiator_dh_key"),
            line_refs(
                "ml_kem_braid/pqxdh/pqxdh.py",
                "message.ik_dh_sig, message.ik_dh_pub",
            ) + line_refs(
                "tests/test_security_fixes.py",
                "test_responder_rejects_unbound_initiator_dh_key",
            ),
        ),
        Check(
            "One-time prekey replay prevention is implemented and tested",
            contains(readme, "replayed `InitialMessage`", "raises `KeyError`") and
            contains(pqxdh, "del secrets.opk_priv[message.opk_id]") and
            contains(test_security, "test_one_time_prekey_consumed_blocks_replay"),
            line_refs(
                "README.md",
                "| **OPK replay prevention** |",
            ) + line_refs(
                "ml_kem_braid/pqxdh/pqxdh.py",
                "del secrets.opk_priv[message.opk_id]",
            ) + line_refs(
                "tests/test_security_fixes.py",
                "test_one_time_prekey_consumed_blocks_replay",
            ),
        ),
        Check(
            "SCKA KDF labels match the README/spec claims",
            contains(kdf, "MLKEMBraid_MLKEM768_HMAC-SHA256", b":SCKA Key".decode(), b":Authenticator Update".decode()) and
            contains(auth, b":ekheader".decode(), b":ciphertext".decode()),
            line_refs(
                "ml_kem_braid/core/kdf.py",
                "MLKEMBraid_MLKEM768_HMAC-SHA256",
                'b":Authenticator Update"',
                'b":SCKA Key"',
            ) + line_refs(
                "ml_kem_braid/core/authenticator.py",
                'b":ekheader"',
                'b":ciphertext"',
            ),
        ),
        Check(
            "SCKA ciphertext authentication is transactional",
            contains(auth, "cand_root, cand_mac", "if not hmac.compare_digest", "self.state.root_key = cand_root") and
            contains(test_security, "test_failed_ciphertext_mac_does_not_mutate_authenticator"),
            line_refs(
                "ml_kem_braid/core/authenticator.py",
                "cand_root, cand_mac",
                "if not hmac.compare_digest",
                "self.state.root_key = cand_root",
            ) + line_refs(
                "tests/test_security_fixes.py",
                "test_failed_ciphertext_mac_does_not_mutate_authenticator",
            ),
        ),
        Check(
            "Incremental Encaps1/Encaps2 split has a byte-equality regression test",
            contains(readme, "ct1 \u2016 ct2", "proven in tests") and
            contains(mlkem, "def encaps1", "def encaps2", "return self._impl._decaps_internal(dk, ct1 + ct2)") and
            contains(test_kem, "test_split_equals_reference_monolithic", "ct1 + ct2 == ref_c"),
            line_refs(
                "README.md",
                "`ct1 \u2016 ct2` is identical",
            ) + line_refs(
                "ml_kem_braid/core/ml_kem.py",
                "def encaps1",
                "def encaps2",
                "return self._impl._decaps_internal(dk, ct1 + ct2)",
            ) + line_refs(
                "tests/test_kem.py",
                "test_split_equals_reference_monolithic",
                "ct1 + ct2 == ref_c",
            ),
            "This is empirical coverage, not a universal EasyCrypt proof.",
        ),
        Check(
            "Double Ratchet direction separation, MAX_SKIP, and commit-after-AEAD are present",
            contains(dr, '_INFO_ATOB = b"A->B"', '_INFO_BTOA = b"B->A"', "MAX_SKIP = 1000") and
            contains(dr, "aead_decrypt(mk, ciphertext, full_ad)", "self._ck_recv = ck_next") and
            contains(test_dr, "test_forged_message_does_not_evict_cached_key", "MAX_SKIP"),
            line_refs(
                "ml_kem_braid/core/double_ratchet.py",
                '_INFO_ATOB = b"A->B"',
                '_INFO_BTOA = b"B->A"',
                "MAX_SKIP = 1000",
                "plaintext = aead_decrypt(mk, ciphertext, full_ad)",
                "self._ck_recv = ck_next",
            ) + line_refs(
                "tests/test_double_ratchet.py",
                "test_forged_message_does_not_evict_cached_key",
                "MAX_SKIP",
            ),
        ),
        Check(
            "Chat associated data binds sender, recipient, epoch, and index",
            contains(client, "return f\"{s_user}:{s_dev}->{r_user}:{r_dev}\"") and
            contains(dr, 'b"hdr:"', "header.epoch.to_bytes", "header.index.to_bytes"),
            line_refs(
                "ml_kem_braid/client/client.py",
                "return f\"{s_user}:{s_dev}->{r_user}:{r_dev}\"",
            ) + line_refs(
                "ml_kem_braid/core/double_ratchet.py",
                'b"hdr:"',
                "header.epoch.to_bytes",
                "header.index.to_bytes",
            ),
        ),
        Check(
            "Relay sender identity and username pinning are enforced",
            contains(server, "Ed25519PublicKey.from_public_bytes", "registration_challenge", "sender_username=sender.username") and
            contains(store, "account.identity_key != identity_key") and
            contains(sqlite_store, "existing_row", "identity_key"),
            line_refs(
                "ml_kem_braid/server/app.py",
                "Ed25519PublicKey.from_public_bytes",
                "sender_username=sender.username",
            ) + line_refs(
                "ml_kem_braid/sesame/store.py",
                "account.identity_key != identity_key",
            ) + line_refs(
                "ml_kem_braid/sesame/sqlite_store.py",
                "existing_row is not None",
            ),
        ),
        Check(
            "README caveats are preserved: no rate limiting and no completed formal proof",
            contains(readme, "No rate limiting", "No formal audit") and
            contains(formal_plan, "Nothing in this repository is \"verified\" or \"proven\" yet"),
            line_refs(
                "README.md",
                "**No rate limiting, DoS protection, or spam filtering.**",
                "**No formal audit.**",
            ) + line_refs(
                "docs/FORMAL_VERIFICATION.md",
                "Nothing in this repository is \"verified\" or \"proven\" yet",
            ),
        ),
    ]

    payload = {
        "repo_root": str(REPO_ROOT),
        "package_root": str(PACKAGE_ROOT),
        "passed": sum(1 for c in checks if c.ok),
        "failed": sum(1 for c in checks if not c.ok),
        "checks": [asdict(c) for c in checks],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for check in checks:
            status = "PASS" if check.ok else "FAIL"
            print(f"{status}: {check.name}")
            if check.detail:
                print(f"  note: {check.detail}")
            for ref in check.evidence:
                print(f"  {ref}")

    return 0 if payload["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
