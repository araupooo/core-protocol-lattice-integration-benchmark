#!/bin/bash
# run_benchmarks.sh — run the liboqs benchmark harness for both pinned
# builds and save UNEDITED logs to pack/outputs/.
# Usage: run_benchmarks.sh [workdir] [kem_iterations] [sig_iterations]
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
NK="${2:-200}"
NS="${3:-100}"
for f in "$WORK/bench_liboqs_ref" "$WORK/bench_liboqs_opt"; do
  [ -x "$f" ] || { echo "FAIL: missing $f (run scripts/build_all.sh first)"; exit 1; }
done
"$WORK/bench_liboqs_ref" "$NK" "$NS" 2>&1 | tee "$PACK/outputs/baseline-reference.log"
"$WORK/bench_liboqs_opt" "$NK" "$NS" 2>&1 | tee "$PACK/outputs/baseline-optimized.log"
echo "run_benchmarks: DONE"
