#!/usr/bin/env bash
# Run available formal tools against the codex-proofs models.
#
# This script is intentionally tolerant of missing tools: the current checkout
# may not have Verifpal, Tamarin, Apalache, or EasyCrypt installed.  Missing
# tools are reported as SKIP, while installed tools are run and their exit codes
# are recorded in the summary.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROOF_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERIFPAL_MODEL="${PROOF_DIR}/models/verifpal/full_pqxdh_braid_chat.vp"
TAMARIN_MODEL="${PROOF_DIR}/models/tamarin/scka_double_ratchet.spthy"
TLA_MODEL="${PROOF_DIR}/models/tla/SCKA.tla"
TLA_CFG="${PROOF_DIR}/models/tla/SCKA.cfg"
EC_MODEL="${PROOF_DIR}/proofs/easycrypt/MLKEM_Split.ec"

status=0

run_or_skip() {
  local tool="$1"
  shift
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'SKIP %-16s not installed\n' "$tool"
    return 0
  fi

  printf 'RUN  %-16s %s\n' "$tool" "$*"
  "$tool" "$@"
  local rc=$?
  printf 'DONE %-16s exit=%s\n' "$tool" "$rc"
  if [ "$rc" -ne 0 ]; then
    status=1
  fi
}

run_or_skip verifpal verify "$VERIFPAL_MODEL"
run_or_skip tamarin-prover --prove "$TAMARIN_MODEL"
run_or_skip apalache-mc check --config="$TLA_CFG" --inv=Inv "$TLA_MODEL"
run_or_skip easycrypt "$EC_MODEL"

exit "$status"
