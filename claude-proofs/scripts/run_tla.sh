#!/usr/bin/env bash
# TLC model-check of the SCKA state machine (safety invariants + liveness).
# Tool discovery: $TLA2TOOLS_JAR, then claude-proofs/.tools/tla2tools.jar.
# Get tla2tools.jar: https://github.com/tlaplus/tlaplus/releases  (needs a JRE).
# NOTE: -deadlock DISABLES TLC's built-in deadlock flag (the protocol legitimately
# terminates at the epoch bound); no-deadlock is checked via the NoDeadlock property.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
JAR="${TLA2TOOLS_JAR:-}"
[ -z "$JAR" ] && [ -f "$ROOT/.tools/tla2tools.jar" ] && JAR="$ROOT/.tools/tla2tools.jar"
if [ -z "$JAR" ] || ! command -v java >/dev/null; then
  echo "tla2tools.jar or java not found. Get the jar from the TLA+ releases and/or" \
       "set \$TLA2TOOLS_JAR; install a JRE>=11." | tee "$ROOT/results/tlc.txt"; exit 0
fi
cd "$ROOT/tla"
# Primary, COMPLETE run: MaxCopies=1 verifies safety + liveness fast (~45s).
# For extra safety confidence at MaxCopies=2 (1.9M states; liveness is slow),
# run:  java -cp "$JAR" tlc2.TLC -deadlock -config SCKA.cfg SCKA.tla
CFG="${TLC_CONFIG:-SCKA_small.cfg}"
{ echo "### TLC SCKA.tla  (config: $CFG)"; date
  java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -deadlock -config "$CFG" SCKA.tla
  echo "### TLC_EXIT=$?"
} 2>&1 | tee "$ROOT/results/tlc.run.txt" \
       | grep -vE '\[to \|->|:> [0-9]+ @@|:> [0-9]+ \)|^  /\\ ' | tail -22
