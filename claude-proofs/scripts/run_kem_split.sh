#!/usr/bin/env bash
# KEM split fidelity harness (empirical Lemma 1 / Lemma 2 for the EasyCrypt proof).
# Requires the project's Python env (kyber-py): run from the repo root via `uv`.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
cd "$REPO"
TRIALS="${TRIALS:-200}"; KEYPAIRS="${KEYPAIRS:-3}"
uv run python claude-proofs/kem_split/verify_split_indcca.py \
    --trials "$TRIALS" --keypairs "$KEYPAIRS" \
    --json claude-proofs/results/kem_split.json | tee claude-proofs/results/kem_split.txt
