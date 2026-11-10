# Core-Protocol Lattice Integration Benchmark and Remediation

Benchmark and remediation pack for a lattice integration assessment on the
real OpenSSL 3.x TLS 1.3 call path via oqs-provider: pinned reference and
optimized ML-KEM/ML-DSA builds, unedited measurements, one reproduced
integration bottleneck with a tested remediation, and a findings page.

## Stack (pinned)

- OpenSSL 3.0.13 (system, Ubuntu 24.04) — TLS 1.3
- oqs-provider 0.12.0 (`fixtures/oqs-provider-0.12.0.tar.gz`)
- liboqs 0.16.0 (`fixtures/liboqs-0.16.0.tar.gz`)
- Key exchange: hybrid `X25519MLKEM768` (group `0x11ec`)
- Signatures: ML-DSA-65 (liboqs API + X.509 level); ECDSA P-384 served
  certificate (see finding B-1)

## Headline numbers

| Operation | Reference (generic, no AVX2) | Optimized (native AVX2) |
|---|---|---|
| ML-KEM-768 keypair | 120.47 us | 31.33 us |
| ML-KEM-768 encaps | 114.82 us | 20.18 us |
| ML-KEM-768 decaps | 127.80 us | 25.61 us |
| ML-DSA-65 sign | 1159.61 us | 173.63 us |
| ML-DSA-65 verify | 380.86 us | 60.20 us |

TLS 1.3 full handshakes (ECDSA P-384 cert + X25519MLKEM768, median of 30):
reference 18 ms, optimized 19–21 ms — **no measurable wall-clock
improvement** (wall time is dominated by process spawn; the crypto gap is
~0.3 ms). Resumed handshakes: 14–15 ms. ClientHello key_share 1216 B
(X25519 32 + ML-KEM-768 ek 1184), group `0x11ec` verified from the trace.

## Finding B-1

OpenSSL 3.0.13 cannot serve an ML-DSA-65 (or hybrid `p384_mldsa65`)
server certificate: `SSL_CTX_use_certificate: ca md too weak` at the
default security level, then `ssl_set_cert: unknown certificate type`
at `SECLEVEL=0` (`ssl/ssl_rsa.c`). Reproduced by
`scripts/reproduce_bottleneck.sh`. Remediation: authenticate with an
ECDSA P-384 certificate while keeping the hybrid X25519MLKEM768 key
exchange — patch `src/remediation/server-config.patch`, plus the
optimized build and session resumption. Full detail:
`docs/methodology.md`; claim-to-evidence index:
`docs/evidence-index.md`; rendered findings page:
`docs/index.html`.

## Layout

- `src/bench_liboqs.c` — liboqs benchmark harness (KEM + SIG throughput,
  FIPS size checks, round-trips, peak RSS).
- `src/remediation/` — `server-config.patch`, `server-config.cnf`,
  `README.md`.
- `scripts/` — `build_all.sh`, `run_benchmarks.sh`,
  `run_tls_handshakes.sh`, `reproduce_bottleneck.sh`, `make_certs.sh`,
  `run_tests.sh`, `run_all.sh`, `clean_reproduce.sh`,
  `verify_digests.sh`.
- `configs/` — `openssl-providers.cnf` (post-remediation),
  `openssl-seclevel0.cnf` (B-1 reproduction only).
- `fixtures/` — pinned source tarballs.
- `outputs/` — unedited logs + `run-manifest.md`.

## Reproduce

```sh
# Full pipeline (builds, certs, benchmarks, bottleneck repro, TLS, tests):
scripts/run_all.sh

# Regression tests only (6 tests; needs a prior build):
scripts/run_tests.sh

# From a fresh copy of this pack (rebuilds everything, ~25 min):
scripts/clean_reproduce.sh <fresh-pack-copy>
```

## Verify integrity

```sh
scripts/verify_digests.sh   # sha256sum -c SHA256SUMS, must exit 0
```

## Limitations (short version)

ML-DSA-65 certificates in a live TLS server are unproven on this stack;
no in-process/high-throughput TLS measurement was made; single machine,
loopback, small samples; test-only certificates. Full list:
`docs/methodology.md` (LIMITATIONS).
