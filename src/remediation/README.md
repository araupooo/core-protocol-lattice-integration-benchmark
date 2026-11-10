# Remediation for finding B-1 (and the performance finding)

## Finding B-1 — ML-DSA-65 server certificates cannot be served by OpenSSL 3.0.13

`openssl s_server` exits immediately when given an ML-DSA-65 (or hybrid
`p384_mldsa65`) server certificate. Two stacked rejections in OpenSSL 3.0.13
`ssl/ssl_rsa.c`:

1. Default security level: `SSL_CTX_use_certificate()` calls
   `ssl_security_cert()`, which rejects the certificate with
   `ca md too weak` — ML-DSA has no message digest, so the signature-digest
   strength check fails.
2. With `SECLEVEL=0` (configs/openssl-seclevel0.cnf) the first check passes
   but `ssl_set_cert()` then fails with `unknown certificate type`:
   `ssl_cert_lookup_by_pkey()` only knows built-in key types (RSA, ECDSA,
   DSA, ...); provider-defined keys such as ML-DSA-65 are not in its table.

Reproduced by `scripts/reproduce_bottleneck.sh` (exit 0 = all three cases
reproduce as documented); unedited logs in
`outputs/before-remediation-case{1,2,3}*.log`.

## Remediation R-1 — authenticate with a classical ECDSA P-384 certificate

Apply `server-config.patch` to the deployment's server configuration:

    patch -p1 < src/remediation/server-config.patch

It changes only the authentication material: `CERT`/`KEY`/`CAFILE` move
from the ML-DSA-65 certificate to an ECDSA P-384 certificate. The
post-quantum part of the handshake is unchanged: the hybrid
`X25519MLKEM768` key exchange still runs through oqs-provider, and the
ClientHello key_share is still 1216 bytes (X25519 32 + ML-KEM-768 ek 1184).

After applying the patch, the server starts and completes handshakes; see
`outputs/tls-reference.log` and `outputs/tls-optimized.log`
(all 30 full handshakes `Verify return code: 0 (ok)`, group proven by the
`-msg` trace: key_share group `0x11ec`).

ML-DSA-65 is NOT dropped from the assessment: it is exercised at the
liboqs API level (`outputs/baseline-*.log`: sign/verify round-trips, FIPS
204 sizes) and at the X.509 level (certificate generation and
`openssl verify` chain validation, OK). What remains unproven on this
OpenSSL branch is serving an ML-DSA-65 certificate in a live TLS server —
see LIMITATIONS in `docs/methodology.md`.

## Remediation R-2 — ship the optimized liboqs build

Build liboqs with `OQS_OPT_TARGET=auto` (native AVX2) instead of
`OQS_OPT_TARGET=generic`. Measured at the liboqs layer (same harness,
same iteration counts):

| operation (ML-KEM-768) | reference | optimized | speedup |
|---|---|---|---|
| keypair | 120.47 us | 31.33 us | 3.8x |
| encaps | 114.82 us | 20.18 us | 5.7x |
| decaps | 127.80 us | 25.61 us | 5.0x |

| operation (ML-DSA-65) | reference | optimized | speedup |
|---|---|---|---|
| keypair | 424.95 us | 59.36 us | 7.2x |
| sign | 1159.61 us | 173.63 us | 6.7x |
| verify | 380.86 us | 60.20 us | 6.3x |

Honest scope: at the `s_client` wall-clock level the optimized build shows
NO measurable handshake improvement (full-handshake medians: reference
18 ms, optimized 19–21 ms across two runs of 30) because wall time is
dominated by process spawn and scheduling (~15 ms floor even for resumed
handshakes). The 4–7x benefit is proven at the crypto-operation layer; a
benefit for in-process/high-throughput servers is plausible but UNMEASURED
by this harness and is not claimed.

## Remediation R-3 — keep TLS 1.3 session resumption enabled

`s_server` enables session tickets by default; repeat connections resume
and skip the KEM + signature exchange. Measured (30 handshakes each):
resumed median 14–15 ms vs full 18–21 ms (~17–29% faster, `Reused,
TLSv1.3` confirmed in every resumed run).

## Files

- `server-config.cnf` — the post-remediation server configuration.
- `server-config.patch` — unified diff (before → after); applies cleanly
  with `patch -p1` and reproduces `server-config.cnf` exactly.
- `../configs/openssl-providers.cnf` — OpenSSL config used for all
  post-remediation measurements (providers only, default security level).
- `../configs/openssl-seclevel0.cnf` — B-1 reproduction config (SECLEVEL=0);
  test-only, NOT part of the remediation.
