# Codex Proof Bundle

This folder contains the security-analysis artifacts requested for the
ML-KEM Braid chat protocol.

## Contents

- `reports/security_analysis.md`: repo-grounded security analysis, findings,
  property matrix, and open proof obligations.
- `models/verifpal/full_pqxdh_braid_chat.vp`: first-pass symbolic model of the
  PQXDH -> Braid -> Double Ratchet chat flow.
- `models/tamarin/scka_double_ratchet.spthy`: symbolic SCKA plus Double Ratchet
  model with FS/PCS-oriented lemmas and state-compromise rules.
- `models/tla/SCKA.tla` and `models/tla/SCKA.cfg`: TLA+/TLC/Apalache SCKA
  state-machine model for agreement, uniqueness, progress, and no deadlock.
- `proofs/easycrypt/MLKEM_Split.ec` and `proofs/easycrypt/PROOF_SKETCH.md`:
  EasyCrypt-style split-ML-KEM IND-CCA equivalence scaffold and written proof
  sketch.
- `scripts/verify_readme_claims.py`: README-to-code/test evidence checker.
- `scripts/run_formal_tools.sh`: wrapper that runs available formal tools and
  records skips when tools are not installed.
- `results/`: outputs from the local evidence scripts and pytest.

## Local Results

The following commands were run from this checkout:

```bash
codex-proofs/scripts/verify_readme_claims.py --json
codex-proofs/scripts/run_formal_tools.sh
uv run pytest -q
```

Results are saved in:

- `results/readme_claims.json`: 10 checks passed, 0 failed.
- `results/formal_tool_check.log`: Verifpal, Tamarin, Apalache, and EasyCrypt
  were not installed, so formal proofs were not machine-run here.
- `results/pytest.log`: 220 tests passed, 3 warnings.

## Status

These artifacts do not claim the protocol is formally verified. They provide
the analysis bundle, runnable scaffolds, and explicit proof obligations needed
to continue verification with the corresponding prover toolchains.

## Decentralized Extensions

The decentralized migration adds two model scaffolds:

- `models/tamarin/signed_contact_events.spthy`: contact acceptance must be backed
  by a prior signed request.
- `models/tla/OPKLease.tla`: OPK state transitions prevent consumed OPKs from
  becoming available again.
