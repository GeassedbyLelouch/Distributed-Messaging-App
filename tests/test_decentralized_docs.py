from pathlib import Path


def test_readme_mentions_decentralized_anonymous_mode():
    text = Path("README.md").read_text()
    assert "Decentralized anonymous mode" in text
    assert "3-hop" in text
    assert "mandatory 3-hop anonymous transport" in text
    assert "relay-only rendezvous" in text
    assert "Direct P2P is disabled" in text


def test_protocol_spec_mentions_signed_records_and_opk_leases():
    text = Path("docs/PROTOCOL_SPEC.md").read_text()
    assert "SignedRecord" in text
    assert "OPK lease" in text
    assert "available -> leased -> consumed" in text
    assert "available -> leased -> expired" in text
    decentralized_section = text.split("## 5. Decentralized anonymous delivery", 1)[1]
    assert "replay" in decentralized_section.lower()


def test_decentralized_formal_model_scaffolds_exist():
    assert Path("ml_kem_braid/codex-proofs/models/tamarin/signed_contact_events.spthy").exists()
    assert Path("ml_kem_braid/codex-proofs/models/tla/OPKLease.tla").exists()
