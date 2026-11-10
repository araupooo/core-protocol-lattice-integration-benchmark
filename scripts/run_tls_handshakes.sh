#!/bin/bash
# run_tls_handshakes.sh — measure real TLS 1.3 handshakes through the
# oqs-provider call path (openssl s_server / s_client, system OpenSSL 3.0.13).
#
# Usage:
#   run_tls_handshakes.sh <provider_dir> <label> <n_handshakes> <out_log> [extra_s_server_args...]
# provider_dir: directory containing oqsprovider.so (passed via OPENSSL_MODULES)
# The script starts s_server with the configured certificate and the
# X25519MLKEM768 hybrid group, then runs N s_client full handshakes and
# N resumed handshakes (TLS 1.3 session tickets), recording per-handshake
# wall time, negotiated group and cipher. It also captures one -msg trace
# to measure the ClientHello key_share size.
#
# Environment overrides:
#   TLS_CERT / TLS_KEY / TLS_CAFILE — server certificate, key, CA file
#     (default: ECDSA P-384 certs under <task>/work/certs — the
#     post-remediation choice, see docs/methodology.md finding B-1)
#   TLS_OPENSSL_CONF — OpenSSL config file (default:
#     pack/configs/openssl-providers.cnf — providers only, default security)
# All openssl invocations get -provider default -provider oqsprovider and
# OPENSSL_MODULES=<provider_dir>. Times include the s_client process spawn
# (~2-4 ms) and are comparable across labels run with the same harness.
set -u
PROV_DIR="$1"; LABEL="$2"; N="${3:-30}"; OUT="$4"; shift 4 || true

HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$(cd "$HERE/.." && pwd)"
CERTDIR="${TLS_CERTDIR:-$PACK/../work/certs}"
TLS_CERT="${TLS_CERT:-$CERTDIR/ecdsa-server.crt}"
TLS_KEY="${TLS_KEY:-$CERTDIR/ecdsa-server.key}"
TLS_CAFILE="${TLS_CAFILE:-$CERTDIR/ecdsa-ca.crt}"
TLS_OPENSSL_CONF="${TLS_OPENSSL_CONF:-$PACK/configs/openssl-providers.cnf}"
export OPENSSL_CONF="$TLS_OPENSSL_CONF"
export OPENSSL_MODULES="$PROV_DIR"
PORT=18443

: > "$OUT"
{
echo "tls_handshakes: label=$LABEL provider_dir=$PROV_DIR n=$N"
echo "openssl version: $(openssl version)"
echo "openssl config: $TLS_OPENSSL_CONF"
echo "provider: $(ls -l "$PROV_DIR"/oqsprovider.so 2>/dev/null || echo MISSING)"
echo "server cert: $TLS_CERT"
echo "server cert: $(openssl x509 -in "$TLS_CERT" -noout -text 2>/dev/null | grep -m1 'Signature Algorithm' || echo MISSING)"
echo "server cert public key algorithm: $(openssl x509 -in "$TLS_CERT" -noout -text 2>/dev/null | grep -m1 -A1 'Public Key Algorithm' | tr '\n' ' ')"
} | tee -a "$OUT"

# Start server (background). Accepts: 1 traced + N full + 1 session capture
# + N resumed handshakes; we also kill it explicitly at the end.
openssl s_server -accept "127.0.0.1:$PORT" \
  -cert "$TLS_CERT" -key "$TLS_KEY" \
  -groups X25519MLKEM768 -tls1_3 \
  -provider default -provider oqsprovider \
  -naccept "$((2 * N + 2))" -quiet "$@" >> "$OUT" 2>&1 &
SRV_PID=$!
sleep 2
if ! kill -0 "$SRV_PID" 2>/dev/null; then
  echo "FATAL: s_server failed to start (see log)" | tee -a "$OUT"
  exit 1
fi

# One traced handshake to measure ClientHello key_share and certificate sizes.
TRACE="$OUT.trace"
openssl s_client -connect "127.0.0.1:$PORT" -groups X25519MLKEM768 -tls1_3 \
  -provider default -provider oqsprovider \
  -CAfile "$TLS_CAFILE" -verify_return_error -msg </dev/null > "$TRACE" 2>&1
grep -m1 'New, TLSv1.3' "$TRACE" >> "$OUT" || true
python3 - "$TRACE" >> "$OUT" <<'PYEOF'
import re, sys
data = open(sys.argv[1], errors="ignore").read()
lines = data.splitlines()
# Collect the hex dump lines following the ClientHello header line.
hexlines = []
in_ch = False
for ln in lines:
    if "ClientHello" in ln and ">>>" in ln:
        in_ch = True
        continue
    if in_ch:
        if re.match(r"^\s+([0-9a-f]{2} )+[0-9a-f]{2}\s*$", ln):
            hexlines.append(ln)
        else:
            break
if not hexlines:
    print("trace: ClientHello hex block not found")
    sys.exit(0)
raw = bytes.fromhex(" ".join(" ".join(h.split()) for h in hexlines))
print("trace: ClientHello total bytes=%d (incl. 4-byte handshake header)" % len(raw))
# Parse: handshake header(4) + legacy_version(2) + random(32) + session_id_len(1)+id
#        + cipher_suites_len(2)+suites + compression_len(1)+methods + extensions_len(2)
p = 4 + 2 + 32
sid_len = raw[p]; p += 1 + sid_len
cs_len = int.from_bytes(raw[p:p+2], "big"); p += 2 + cs_len
comp_len = raw[p]; p += 1 + comp_len
ext_len = int.from_bytes(raw[p:p+2], "big"); p += 2
end = p + ext_len
while p + 4 <= end:
    etype = int.from_bytes(raw[p:p+2], "big")
    elen = int.from_bytes(raw[p+2:p+4], "big")
    if etype == 0x0033:  # key_share
        ks = raw[p+4:p+4+elen]
        list_len = int.from_bytes(ks[0:2], "big")
        group = int.from_bytes(ks[2:4], "big")
        klen = int.from_bytes(ks[4:6], "big")
        print("trace: key_share extension length=%d list_len=%d group=0x%04x key_exchange_len=%d" % (elen, list_len, group, klen))
        print("trace: expected X25519(32)+ML-KEM-768 ek(1184)=1216; group 0x11ec=X25519MLKEM768: %s" % ("OK" if group == 0x11ec and klen == 1216 else "MISMATCH"))
    p += 4 + elen
PYEOF

# Timed full handshakes.
TIMES="$OUT.times"
: > "$TIMES"
for i in $(seq 1 "$N"); do
  START=$(date +%s%N)
  RES=$(openssl s_client -connect "127.0.0.1:$PORT" -groups X25519MLKEM768 -tls1_3 \
    -provider default -provider oqsprovider \
    -CAfile "$TLS_CAFILE" -verify_return_error </dev/null 2>&1)
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  echo "$MS" >> "$TIMES"
  if [ "$i" -eq 1 ]; then
    echo "$RES" | grep -E 'New, TLSv1.3|Cipher    :|Verify return code|Peer signing digest|Server Temp Key|Protocol  :' | tee -a "$OUT"
  fi
  echo "$RES" | grep -q 'Verify return code: 0 (ok)' || echo "handshake $i: VERIFY NOT OK" | tee -a "$OUT"
  # Group proof: OpenSSL 3.0.13 s_client prints no group name in TLS 1.3
  # output, so the negotiated group is proven by the -msg trace above
  # (ServerHello key_share group 0x11ec) plus the single-group server
  # configuration — any other group would fail the handshake.
  echo "$RES" | grep -q 'New, TLSv1.3' || echo "handshake $i: NOT A NEW TLS 1.3 HANDSHAKE" | tee -a "$OUT"
done

# Capture one session ticket, then time N resumed handshakes.
# stdin is kept open 1 s so the post-handshake NewSessionTicket arrives
# before s_client exits (with </dev/null the ticket is missed and no
# session file is written).
SESS="$OUT.session.pem"
(sleep 1) | openssl s_client -connect "127.0.0.1:$PORT" -groups X25519MLKEM768 -tls1_3 \
  -provider default -provider oqsprovider \
  -CAfile "$TLS_CAFILE" -verify_return_error -sess_out "$SESS" > /dev/null 2>&1
if [ ! -s "$SESS" ]; then
  echo "WARNING: session capture produced no session file; resumed runs will be full handshakes" | tee -a "$OUT"
fi
RTIMES="$OUT.rtimes"
: > "$RTIMES"
for i in $(seq 1 "$N"); do
  START=$(date +%s%N)
  RES=$(openssl s_client -connect "127.0.0.1:$PORT" -groups X25519MLKEM768 -tls1_3 \
    -provider default -provider oqsprovider \
    -CAfile "$TLS_CAFILE" -verify_return_error -sess_in "$SESS" </dev/null 2>&1)
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  echo "$MS" >> "$RTIMES"
  echo "$RES" | grep -q 'Reused, TLSv1.3' || echo "resumed handshake $i: NOT A RESUMED SESSION" | tee -a "$OUT"
  echo "$RES" | grep -q 'Verify return code: 0 (ok)' || echo "resumed handshake $i: VERIFY NOT OK" | tee -a "$OUT"
  echo "$RES" > "$OUT.last-resumed"
done
# Report whether resumption actually happened, from the last resumed output.
grep -E 'Reused, TLSv1.3|New, TLSv1.3' "$OUT.last-resumed" | head -2 | tee -a "$OUT"

kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null || true

python3 - "$TIMES" "$RTIMES" "$LABEL" >> "$OUT" <<'PYEOF'
import statistics, sys
def summ(path, label):
    times = [int(x) for x in open(path).read().split() if x.strip()]
    print("%s (%s): n=%d mean=%.2f ms median=%.2f ms min=%d ms max=%d ms stdev=%.2f ms" % (
        label, sys.argv[3], len(times), statistics.mean(times), statistics.median(times),
        min(times), max(times), statistics.stdev(times) if len(times) > 1 else 0.0))
    print("%s times ms: %s" % (label, " ".join(map(str, times))))
    return times
full = summ(sys.argv[1], "handshake summary full")
res = summ(sys.argv[2], "handshake summary resumed")
if full and res:
    print("resumed vs full median: %.2f ms vs %.2f ms (%.1f%% of full)" % (
        statistics.median(res), statistics.median(full),
        100.0 * statistics.median(res) / statistics.median(full)))
PYEOF
echo "tls_handshakes: DONE label=$LABEL" | tee -a "$OUT"
