#!/bin/bash
# run_all.sh — full pipeline: build, certs, benchmarks, bottleneck
# reproduction, TLS measurements, regression tests.
# Usage: run_all.sh [workdir]
# Produces pack/outputs/* and prints a run manifest.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
export TLS_CERTDIR="$WORK/certs"
echo "run_all: pack=$PACK work=$WORK"
bash "$PACK/scripts/build_all.sh" "$WORK"
if [ ! -f "$WORK/certs/ecdsa-server.crt" ]; then
  bash "$PACK/scripts/make_certs.sh" "$WORK/oqs-ref-mod"
fi
bash "$PACK/scripts/run_benchmarks.sh" "$WORK" 200 100
bash "$PACK/scripts/reproduce_bottleneck.sh" "$WORK/oqs-ref-mod" "$PACK/outputs/before-remediation"
bash "$PACK/scripts/run_tls_handshakes.sh" "$WORK/oqs-ref-mod" reference 30 "$PACK/outputs/tls-reference.log"
bash "$PACK/scripts/run_tls_handshakes.sh" "$WORK/oqs-opt-mod" optimized 30 "$PACK/outputs/tls-optimized.log"
bash "$PACK/scripts/run_tests.sh" "$WORK"
echo "run_all: DONE — see $PACK/outputs/"
