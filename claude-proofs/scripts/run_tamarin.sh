#!/usr/bin/env bash
# Tamarin: well-formedness + per-lemma proofs of the SCKA + Double Ratchet theory.
# Tool discovery: $TAMARIN/$MAUDE, then PATH, then claude-proofs/.tools/.
# Install: tamarin-prover 1.12.x (https://tamarin-prover.com) + Maude 3.x
#   (https://github.com/maude-lang/Maude/releases) on PATH.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TAM="${TAMARIN:-}"
[ -z "$TAM" ] && command -v tamarin-prover >/dev/null && TAM="$(command -v tamarin-prover)"
[ -z "$TAM" ] && [ -x "$ROOT/.tools/tamarin-prover" ] && TAM="$ROOT/.tools/tamarin-prover"
# Maude must be on PATH for tamarin; allow a $MAUDE dir override.
[ -n "${MAUDE:-}" ] && export PATH="$(dirname "$MAUDE"):$PATH"
[ -d "$ROOT/.tools/maudebin" ] && export PATH="$ROOT/.tools/maudebin:$PATH" && export MAUDE_LIB="$ROOT/.tools"
if [ -z "$TAM" ] || ! command -v maude >/dev/null; then
  echo "tamarin-prover and/or maude not found. Install both (see header)." \
       | tee "$ROOT/results/tamarin.txt"; exit 0
fi
cd "$ROOT/tamarin"
OUT="$ROOT/results/tamarin.txt"
{ echo "### Tamarin $($TAM --version 2>/dev/null | grep -oE '1\.[0-9.]+' | head -1) + Maude $(maude --version 2>/dev/null | head -1)"
  echo "### theory scka_double_ratchet.spthy  (--prove per lemma, ${PERLEMMA:-150}s cap)"; echo
} > "$OUT"
"$TAM" scka_double_ratchet.spthy 2>&1 | grep -iE 'wellformedness' | head -1 >> "$OUT"
for L in exec_setup exec_epoch_agreement exec_message_delivery \
         scka_agreement scka_ciphertext_auth replay_resistance opk_replay_resistance \
         secret_epoch_key secret_message mutual_authentication_injective \
         forward_secrecy post_compromise_security; do
  R=$(timeout "${PERLEMMA:-150}" "$TAM" --prove="$L" scka_double_ratchet.spthy 2>/dev/null \
        | grep -E "^  $L " | head -1)
  [ -z "$R" ] && R="  $L : TIMEOUT/incomplete (>${PERLEMMA:-150}s)"
  echo "$R" | tee -a "$OUT"
done
