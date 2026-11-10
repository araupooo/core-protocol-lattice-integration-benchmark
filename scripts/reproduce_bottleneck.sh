#!/bin/bash
# reproduce_bottleneck.sh — reproduce finding B-1: OpenSSL 3.0.13 cannot
# serve an ML-DSA-65 (or hybrid p384_mldsa65) server certificate.
# Three minimal triggers, each saved unedited:
#   1. mldsa65 cert, default security level -> "ca md too weak"
#   2. mldsa65 cert, SECLEVEL=0 config    -> "unknown certificate type"
#   3. p384_mldsa65 hybrid cert, SECLEVEL=0 -> "unknown certificate type"
# Usage: reproduce_bottleneck.sh <provider_dir> <out_prefix>
# Produces <out_prefix>-case1.log, -case2.log, -case3.log.
# Exit code is 0 if ALL THREE failures reproduce as documented (the failure
# IS the expected result); non-zero if any case behaves differently.
set -u
PROV_DIR="$1"; PREFIX="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$(cd "$HERE/.." && pwd)"
CERTDIR="${TLS_CERTDIR:-$PACK/../work/certs}"
export OPENSSL_MODULES="$PROV_DIR"
PORT=18444
FAIL=0

run_case() {
  local name="$1"; local cert="$2"; local key="$3"; local conf="$4"; local expect="$5"
  local log="${PREFIX}-${name}.log"
  echo "=== $name ===" > "$log"
  echo "cert=$cert" >> "$log"
  echo "openssl_conf=$conf" >> "$log"
  echo "openssl version: $(openssl version)" >> "$log"
  OPENSSL_CONF="$conf" openssl s_server -accept "127.0.0.1:$PORT" \
    -cert "$cert" -key "$key" \
    -groups X25519MLKEM768 -tls1_3 \
    -provider default -provider oqsprovider \
    -naccept 1 -quiet >> "$log" 2>&1 &
  local pid=$!
  sleep 2
  if kill -0 "$pid" 2>/dev/null; then
    echo "UNEXPECTED: s_server started (no failure reproduced)" >> "$log"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
    echo "$name: NO FAILURE (server started)" | tee -a "$log"
    FAIL=1
  else
    wait "$pid" 2>/dev/null || true
    if grep -q "$expect" "$log"; then
      echo "$name: reproduced — found expected error: $expect" | tee -a "$log"
    else
      echo "$name: FAILED differently than expected (wanted: $expect)" | tee -a "$log"
      FAIL=1
    fi
  fi
}

run_case case1-mldsa65-default \
  "$CERTDIR/server.crt" "$CERTDIR/server.key" \
  "$PACK/configs/openssl-providers.cnf" \
  "ca md too weak"
run_case case2-mldsa65-seclevel0 \
  "$CERTDIR/server.crt" "$CERTDIR/server.key" \
  "$PACK/configs/openssl-seclevel0.cnf" \
  "unknown certificate type"
run_case case3-hybrid-p384mldsa65-seclevel0 \
  "$CERTDIR/hybrid-server.crt" "$CERTDIR/hybrid-server.key" \
  "$PACK/configs/openssl-seclevel0.cnf" \
  "unknown certificate type"

if [ "$FAIL" -eq 0 ]; then
  echo "reproduce_bottleneck: ALL 3 CASES REPRODUCED as documented"
else
  echo "reproduce_bottleneck: MISMATCH — see logs"
fi
exit "$FAIL"
