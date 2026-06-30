#!/usr/bin/env bash
# Run every machine-checkable artifact in claude-proofs and write results/.
# Each runner is independent; a missing tool is reported, not fatal.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

echo "==> [1/4] KEM split fidelity (pytest/kyber-py)  -> results/kem_split.txt"
bash scripts/run_kem_split.sh

echo "==> [2/4] Verifpal full-flow symbolic model     -> results/verifpal.txt"
bash scripts/run_verifpal.sh

echo "==> [3/4] TLA+ SCKA state machine (TLC)          -> results/tlc.txt"
bash scripts/run_tla.sh

echo "==> [4/4] Tamarin SCKA + Double Ratchet          -> results/tamarin.txt"
bash scripts/run_tamarin.sh

echo "==> done. See claude-proofs/results/ and claude-proofs/README.md (RESULTS)."
