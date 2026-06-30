#!/usr/bin/env bash
# Verifpal symbolic (Dolev-Yao) analysis of the full flow.
# Tool discovery: $VERIFPAL, then PATH, then claude-proofs/.tools/verifpal.
# Install: https://verifpal.com  (single static Go binary) or
#   go install verifpal.com/cmd/verifpal@latest
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
VP="${VERIFPAL:-}"
[ -z "$VP" ] && command -v verifpal >/dev/null && VP="$(command -v verifpal)"
[ -z "$VP" ] && [ -x "$ROOT/.tools/verifpal" ] && VP="$ROOT/.tools/verifpal"
if [ -z "$VP" ]; then
  echo "verifpal not found. Install from https://verifpal.com or set \$VERIFPAL." \
       | tee "$ROOT/results/verifpal.txt"; exit 0
fi
cd "$ROOT/verifpal"
# Strip ANSI + the live progress bar; keep verdicts + the one-line attack summaries.
# (Verifpal prints a multi-MB per-variable term dump for each FAIL; we drop it.)
"$VP" verify mlkem_braid_full.vp 2>&1 \
  | sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g; s/\x1B\[K//g' \
  | grep -E 'Result|Pass |Fail |-> |queries (failed|passed)' \
  | grep -vE 'deductions \|.*analyses' \
  | tee "$ROOT/results/verifpal.verdicts.txt"
echo "(verdicts above; curated interpretation in results/verifpal.txt)"
