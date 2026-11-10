#!/bin/bash
# run_tests.sh — focused regression tests for the remediation.
# Usage: run_tests.sh [workdir] ; output is written to stdout AND to
#   pack/outputs/test-output.log (fresh run overwrites it).
# workdir defaults to <pack>/../work. Builds are reused when present;
# run scripts/build_all.sh first (or set BUILD=1 to build if missing).
# Exit code 0 only if every test passes.
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
OUT="$PACK/outputs/test-output.log"
mkdir -p "$PACK/outputs"
exec > >(tee "$OUT") 2>&1
PASS=0; FAIL=0
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

echo "run_tests: pack=$PACK work=$WORK"
echo "openssl version: $(openssl version)"
echo "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# --- prerequisites -------------------------------------------------------
for f in "$WORK/oqs-ref-mod/oqsprovider.so" "$WORK/oqs-opt-mod/oqsprovider.so" \
         "$WORK/bench_liboqs_ref" "$WORK/bench_liboqs_opt"; do
  if [ ! -f "$f" ]; then
    if [ "${BUILD:-0}" = "1" ]; then
      echo "missing $f — building (BUILD=1)"
      bash "$PACK/scripts/build_all.sh" "$WORK" || { echo "FAIL: build_all"; exit 1; }
      break
    else
      echo "FAIL: prerequisite missing: $f (run scripts/build_all.sh first or set BUILD=1)"
      exit 1
    fi
  fi
done
CERTDIR="${TLS_CERTDIR:-$WORK/certs}"
for f in "$CERTDIR/server.crt" "$CERTDIR/ecdsa-server.crt" "$CERTDIR/hybrid-server.crt"; do
  [ -f "$f" ] || { echo "FAIL: prerequisite missing: $f (run scripts/make_certs.sh first)"; exit 1; }
done

# --- T1: B-1 pinned behaviour — the ML-DSA-65 cert failure reproduces -----
echo "--- T1: B-1 pinned behaviour (mldsa65 cert still fails on OpenSSL 3.0.13) ---"
if bash "$PACK/scripts/reproduce_bottleneck.sh" "$WORK/oqs-ref-mod" "$PACK/outputs/test-before-remediation"; then
  ok "T1 mldsa65/hybrid cert failures reproduce as documented (3/3 cases)"
else
  bad "T1 reproduce_bottleneck.sh did not reproduce all 3 cases"
fi

# --- T2: post-remediation handshakes succeed ------------------------------
echo "--- T2: post-remediation TLS handshakes (ECDSA cert + X25519MLKEM768) ---"
bash "$PACK/scripts/run_tls_handshakes.sh" "$WORK/oqs-opt-mod" test-opt 5 "$PACK/outputs/test-tls.log" >/dev/null 2>&1
if grep -q 'handshake summary full (test-opt)' "$PACK/outputs/test-tls.log" \
   && ! grep -qE 'NOT A|VERIFY NOT OK' "$PACK/outputs/test-tls.log" \
   && grep -q 'Reused, TLSv1.3' "$PACK/outputs/test-tls.log" \
   && grep -q 'group=0x11ec key_exchange_len=1216' "$PACK/outputs/test-tls.log"; then
  ok "T2 5 full + 5 resumed handshakes OK, group 0x11ec / key_share 1216 B"
else
  bad "T2 post-remediation handshakes did not all succeed (see outputs/test-tls.log)"
fi

# --- T3: liboqs round-trips + FIPS sizes ----------------------------------
echo "--- T3: liboqs round-trips and FIPS sizes ---"
"$WORK/bench_liboqs_ref" 50 25 > "$PACK/outputs/test-bench-ref.log" 2>&1
"$WORK/bench_liboqs_opt" 50 25 > "$PACK/outputs/test-bench-opt.log" 2>&1
T3OK=1
for f in "$PACK/outputs/test-bench-ref.log" "$PACK/outputs/test-bench-opt.log"; do
  grep -q 'shared-secret round-trip: OK' "$f" || T3OK=0
  grep -q 'sign/verify round-trip: OK' "$f" || T3OK=0
  grep -q 'MISMATCH' "$f" && T3OK=0
done
[ "$T3OK" = "1" ] && ok "T3 KEM/SIG round-trips OK, FIPS 203/204 sizes match (both builds)" \
                  || bad "T3 round-trip or size check failed"

# --- T4: optimized build faster than reference at the crypto layer --------
echo "--- T4: optimized KEM round faster than reference ---"
REF_TOTAL=$(python3 - "$PACK/outputs/test-bench-ref.log" <<'PYEOF'
import re, sys
t = open(sys.argv[1]).read()
vals = {}
for line in t.splitlines():
    m = re.match(r"\[KEM\] (keypair|encaps|decaps)\s+n=\d+\s+mean=\s*([0-9.]+) us", line)
    if m: vals[m.group(1)] = float(m.group(2))
print(sum(vals.values()))
PYEOF
)
OPT_TOTAL=$(python3 - "$PACK/outputs/test-bench-opt.log" <<'PYEOF'
import re, sys
t = open(sys.argv[1]).read()
vals = {}
for line in t.splitlines():
    m = re.match(r"\[KEM\] (keypair|encaps|decaps)\s+n=\d+\s+mean=\s*([0-9.]+) us", line)
    if m: vals[m.group(1)] = float(m.group(2))
print(sum(vals.values()))
PYEOF
)
echo "KEM round mean total: reference=${REF_TOTAL} us optimized=${OPT_TOTAL} us"
if python3 -c "exit(0 if $OPT_TOTAL < 0.5 * $REF_TOTAL else 1)"; then
  ok "T4 optimized KEM round (${OPT_TOTAL} us) < 50% of reference (${REF_TOTAL} us)"
else
  bad "T4 optimized KEM round not < 50% of reference"
fi

# --- T5: remediation patch applies cleanly --------------------------------
echo "--- T5: server-config.patch applies cleanly ---"
TMPD=$(mktemp -d)
cp "$PACK/src/remediation/server-config.cnf" "$TMPD/server-config.cnf"
cp "$PACK/src/remediation/server-config.patch" "$TMPD/"
(cd "$TMPD" && patch -R -p1 --dry-run < server-config.patch >/dev/null 2>&1 \
  && patch -R -p1 < server-config.patch >/dev/null 2>&1 \
  && patch -p1 < server-config.patch >/dev/null 2>&1 \
  && diff -q server-config.cnf "$PACK/src/remediation/server-config.cnf" >/dev/null 2>&1) \
  && ok "T5 server-config.patch reverse-applies and re-applies to the shipped config" \
  || bad "T5 server-config.patch round-trip failed"
rm -rf "$TMPD"

# --- T6: ML-DSA-65 X.509 chain verifies ------------------------------------
echo "--- T6: ML-DSA-65 certificate chain verifies ---"
if OPENSSL_MODULES="$WORK/oqs-ref-mod" openssl verify -provider default -provider oqsprovider \
     -CAfile "$CERTDIR/ca.crt" "$CERTDIR/server.crt" 2>&1 | grep -q ': OK'; then
  ok "T6 ML-DSA-65 server cert chain verifies against its CA"
else
  bad "T6 ML-DSA-65 chain verification failed"
fi

echo "run_tests: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "run_tests: ALL TESTS PASSED" || echo "run_tests: FAILURES PRESENT"
exit "$FAIL"
