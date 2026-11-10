#!/bin/bash
# make_certs.sh — generate all test certificates for the TLS harness.
# All are test artifacts only (CN=localhost / test CAs, 1-2 day validity),
# regenerated fresh by every clean reproduction; the ML-DSA-65 and hybrid
# keys are generated with the oqs-provider.
#   server.crt / server.key / ca.crt         — ML-DSA-65 (finding B-1)
#   hybrid-server.crt / hybrid-ca.crt        — p384_mldsa65 (finding B-1)
#   ecdsa-server.crt / ecdsa-ca.crt          — ECDSA P-384 (post-remediation)
# Usage: make_certs.sh <provider_dir>
# Certificates go to ${TLS_CERTDIR:-<task>/work/certs}.
set -eu
PROV_DIR="$1"
CERTDIR="${TLS_CERTDIR:-$(cd "$(dirname "$0")/../.." && pwd)/work/certs}"
mkdir -p "$CERTDIR"
cd "$CERTDIR"
export OPENSSL_MODULES="$PROV_DIR"
P=(-provider default -provider oqsprovider)
echo "generating ML-DSA-65 CA key + self-signed cert"
openssl req -x509 -new -newkey mldsa65 -keyout ca.key -out ca.crt -days 1 -nodes \
  -subj "/CN=Test ML-DSA-65 CA" "${P[@]}"
echo "generating ML-DSA-65 server key + CSR + cert signed by CA"
openssl req -new -newkey mldsa65 -keyout server.key -out server.csr -nodes \
  -subj "/CN=localhost" "${P[@]}"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 1 "${P[@]}"
echo "generating p384_mldsa65 hybrid CA + server cert"
openssl req -x509 -new -newkey p384_mldsa65 -keyout hybrid-ca.key -out hybrid-ca.crt \
  -days 1 -nodes -subj "/CN=Test hybrid CA" "${P[@]}"
openssl req -new -newkey p384_mldsa65 -keyout hybrid-server.key -out hybrid-server.csr \
  -nodes -subj "/CN=localhost" "${P[@]}"
openssl x509 -req -in hybrid-server.csr -CA hybrid-ca.crt -CAkey hybrid-ca.key \
  -CAcreateserial -out hybrid-server.crt -days 1 "${P[@]}"
echo "generating ECDSA P-384 CA + server cert (default provider)"
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout ecdsa-ca.key -out ecdsa-ca.crt -days 2 -nodes -subj "/CN=Test ECDSA P-384 CA"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout ecdsa-server.key -out ecdsa-server.csr -nodes -subj "/CN=localhost"
openssl x509 -req -in ecdsa-server.csr -CA ecdsa-ca.crt -CAkey ecdsa-ca.key \
  -CAcreateserial -out ecdsa-server.crt -days 2
echo "certs in $CERTDIR:"
for c in server.crt hybrid-server.crt ecdsa-server.crt; do
  echo "$c: $(openssl x509 -in "$c" -noout -text | grep -m1 'Signature Algorithm' | xargs)"
done
ls -l "$CERTDIR"
