#!/bin/bash
# clean_reproduce.sh — reproduce the headline numbers from a FRESH copy of
# pack/ (no build artifacts, no work directory, no certificates).
# Usage: clean_reproduce.sh <fresh_pack_copy_dir>
# The copy must contain fixtures/, src/, scripts/, configs/, docs/.
# The script builds the pinned stack from fixtures/ into a work directory
# next to the copy, regenerates all test certificates, re-runs the
# benchmarks (200 KEM / 100 SIG iterations), the bottleneck reproduction,
# a short TLS run (10 handshakes per build) and the regression tests.
# Outputs land in the copy's outputs/ directory.
# Expected runtime: ~25 minutes on a 2-CPU machine (two full liboqs builds).
set -u
COPY="${1:?usage: clean_reproduce.sh <fresh_pack_copy_dir>}"
COPY="$(cd "$COPY" && pwd)"
WORK="$(dirname "$COPY")/repro-work"
export TLS_CERTDIR="$WORK/certs"
echo "clean_reproduce: pack copy=$COPY work=$WORK"
echo "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
[ -f "$COPY/fixtures/liboqs-0.16.0.tar.gz" ] || { echo "FAIL: fixtures missing in copy"; exit 1; }
[ -f "$COPY/fixtures/oqs-provider-0.12.0.tar.gz" ] || { echo "FAIL: fixtures missing in copy"; exit 1; }
export FORCE_BUILD=1
bash "$COPY/scripts/build_all.sh" "$WORK"
bash "$COPY/scripts/make_certs.sh" "$WORK/oqs-ref-mod"
bash "$COPY/scripts/run_benchmarks.sh" "$WORK" 200 100
bash "$COPY/scripts/reproduce_bottleneck.sh" "$WORK/oqs-ref-mod" "$COPY/outputs/before-remediation"
bash "$COPY/scripts/run_tls_handshakes.sh" "$WORK/oqs-ref-mod" reference 10 "$COPY/outputs/tls-reference.log"
bash "$COPY/scripts/run_tls_handshakes.sh" "$WORK/oqs-opt-mod" optimized 10 "$COPY/outputs/tls-optimized.log"
bash "$COPY/scripts/run_tests.sh" "$WORK"
echo "clean_reproduce: DONE — compare $COPY/outputs/ with the shipped outputs/"
