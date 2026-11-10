# Methodology — core-protocol lattice integration benchmark and remediation

## Protocol under test

| Item | Value |
|---|---|
| Core protocol | OpenSSL 3.0.13 (system build, Ubuntu 24.04) — TLS 1.3 |
| Provider | oqs-provider 0.12.0 (built from `fixtures/oqs-provider-0.12.0.tar.gz`) |
| Algorithm library | liboqs 0.16.0 (built from `fixtures/liboqs-0.16.0.tar.gz`) |
| Key exchange | Hybrid `X25519MLKEM768`, TLS group codepoint `0x11ec` |
| Signature (measured) | ML-DSA-65 (liboqs API level + X.509 level) |
| Signature (served) | ECDSA P-384 — see finding B-1 |
| Machine | AMD EPYC 9D25, x86-64, AVX2 + AVX512, 4 vCPUs, ~7.7 GB RAM |

All version pins are recorded with SHA-256 in `fixtures/` (see
`../SHA256SUMS`). The oqs-provider 0.12.0 / liboqs 0.16.0 pairing is the
one documented in the oqs-provider 0.12.0 release notes (HQC reinstated
with liboqs 0.16.0 naming; SPHINCS+ removed).

## Integration call path (what was actually exercised)

The TLS 1.3 handshake runs through the real provider dispatch, not a
model:

1. Client (`openssl s_client`) builds a ClientHello with a `key_share`
   extension for group `0x11ec` containing the X25519 public key (32 B)
   concatenated with the ML-KEM-768 encapsulation key (1184 B) — total
   key_exchange 1216 B, verified from the `-msg` trace
   (`outputs/tls-*.log`, `trace: key_share ... group=0x11ec
   key_exchange_len=1216`).
2. Server (`openssl s_server`) generates an ephemeral hybrid keypair and
   decapsulates via the provider: OpenSSL EVP_KEM → oqs-provider
   `oqsx_kem` → liboqs `OQS_KEM_decaps` (ML-KEM-768).
3. Server authenticates with a certificate + CertificateVerify. On this
   OpenSSL branch the served certificate is ECDSA P-384 (finding B-1);
   the client verifies the chain (`Verify return code: 0 (ok)`).
4. ML-DSA-65 signing/verification is exercised at the liboqs API level
   (`src/bench_liboqs.c`: `OQS_SIG_sign` / `OQS_SIG_verify`) and at the
   X.509 level (certificate generation + `openssl verify` chain
   validation, OK).

## Pinned builds

Two liboqs builds from the same tarball, same compiler (GCC 13.3.0),
same flags except the optimization target:

- **Reference**: `-DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic`
  (→ `-march=x86-64`, no AVX2).
- **Optimized**: `-DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto`
  (→ `-march=native`, AVX2/AVX512 on this CPU).

oqs-provider 0.12.0 was built once against each liboqs install, producing
two distinct `oqsprovider.so` files (different SHA-256; liboqs is linked
statically into each — `ldd` shows only `libcrypto` + `libc`). The
provider is loaded via `OPENSSL_MODULES` pointing at the build directory
(`-provider-path` is not honored by `openssl list` on OpenSSL 3.0.13;
that quirk is documented in the run notes below).

## Parameter sets and specification sizes

| Algorithm | Parameter set | Sizes (bytes) | Source |
|---|---|---|---|
| ML-KEM | ML-KEM-768 | ek 1184, dk 2400, ct 1088, ss 32 | FIPS 203, Table 3 |
| ML-DSA | ML-DSA-65 | sk 4032, pk 1952, sig 3309; category 3 | FIPS 204, Tables 1–2 |

The benchmark harness asserts every size at runtime and prints OK/MISMATCH
(`outputs/baseline-*.log`).

## Measurements

### liboqs layer — `src/bench_liboqs.c`, `scripts/run_benchmarks.sh`

- Operations: KEM keypair / encaps / decaps; SIG keypair / sign / verify.
- Iterations: 200 KEM, 100 SIG per build (regression tests use 50/25).
- Timing: `clock_gettime(CLOCK_MONOTONIC)` per operation; mean/min/max and
  ops/s reported. Correctness: shared-secret equality on every iteration;
  sign/verify round-trip on every iteration.
- Peak memory: `getrusage(RUSAGE_SELF, ru_maxrss)`.
- Logs are unedited stdout: `outputs/baseline-reference.log`,
  `outputs/baseline-optimized.log`.

### TLS layer — `scripts/run_tls_handshakes.sh`

- `openssl s_server` (one process) + `openssl s_client` per handshake,
  loopback, TLS 1.3 only, single group `X25519MLKEM768`.
- Per-handshake wall time measured with `date +%s%N` around the `s_client`
  process — **includes process spawn (~2–4 ms) and scheduling**; it is a
  deployment-shaped measurement, not a crypto micro-benchmark.
- N = 30 full handshakes + 30 resumed handshakes (TLS 1.3 session
  tickets) per build, repeated in a second run of 30+30 for stability.
- One `-msg` trace per run parses the ClientHello `key_share` extension.
- Resumption check: resumed runs must print `Reused, TLSv1.3`.
- Logs: `outputs/tls-reference.log`, `outputs/tls-optimized.log`,
  plus `-run2` repeats.

## Findings

### B-1 (correctness, integration-specific) — ML-DSA-65 server certificates cannot be served by OpenSSL 3.0.13

`openssl s_server` exits immediately with an ML-DSA-65 (or hybrid
`p384_mldsa65`) server certificate. Two stacked rejections in OpenSSL
3.0.13 `ssl/ssl_rsa.c` (verified against the tagged source):

1. Default security level: `SSL_CTX_use_certificate()` →
   `ssl_security_cert()` rejects with `ca md too weak` — ML-DSA has no
   message digest, so the signature-digest strength check fails.
2. With `SECLEVEL=0` the first check passes, but `ssl_set_cert()` →
   `ssl_cert_lookup_by_pkey()` returns NULL and raises
   `unknown certificate type` — the lookup table only knows built-in key
   types; provider-defined keys are not in it.

Reproduced deterministically by `scripts/reproduce_bottleneck.sh`
(all three cases; exit 0 = reproduced as documented):
`outputs/before-remediation-case1-mldsa65-default.log`,
`outputs/before-remediation-case2-mldsa65-seclevel0.log`,
`outputs/before-remediation-case3-hybrid-p384mldsa65-seclevel0.log`.

**Remediation R-1** (integration config): authenticate with a classical
ECDSA P-384 certificate while keeping the hybrid `X25519MLKEM768` key
exchange — the post-quantum part of the handshake. Patch:
`src/remediation/server-config.patch` (applies cleanly with `patch -p1`,
verified by regression test T5); after-state:
`src/remediation/server-config.cnf`. Post-remediation handshakes:
all 30+30 per build succeed with `Verify return code: 0 (ok)`.
ML-DSA-65 remains exercised at the liboqs API level and X.509 level
(`openssl verify` chain OK, regression test T6).

### P-1 (performance) — optimized build is 4–7x faster at the crypto layer, invisible at the `s_client` wall clock

Measured (same harness, same iteration counts):

| operation | reference mean | optimized mean | speedup |
|---|---|---|---|
| ML-KEM-768 keypair | 120.47 us | 31.33 us | 3.8x |
| ML-KEM-768 encaps | 114.82 us | 20.18 us | 5.7x |
| ML-KEM-768 decaps | 127.80 us | 25.61 us | 5.0x |
| ML-DSA-65 keypair | 424.95 us | 59.36 us | 7.2x |
| ML-DSA-65 sign | 1159.61 us | 173.63 us | 6.7x |
| ML-DSA-65 verify | 380.86 us | 60.20 us | 6.3x |
| Full KEM round (keypair+encaps+decaps) | 363.09 us | 77.12 us | 4.7x |

Peak RSS: reference 6272 KiB, optimized 6492 KiB (no meaningful difference).

At the TLS wall-clock level the optimized build shows **no measurable
improvement**: full-handshake medians were 18 ms (reference) vs 21 ms and
19 ms (optimized, two runs) — the difference is within run-to-run noise
and one 60 ms outlier, while wall time is dominated by process spawn and
scheduling (~15 ms floor, even for resumed handshakes). The crypto gap
(~0.3 ms per handshake) is two orders of magnitude below that floor.

**Remediation R-2**: ship the optimized build (`OQS_OPT_TARGET=auto`).
Its benefit is proven at the crypto-operation layer; a benefit for
in-process / high-throughput servers is plausible but UNMEASURED by this
harness and is not claimed here.

**Remediation R-3**: keep TLS 1.3 session resumption enabled (default).
Measured resumed medians 14–15 ms vs full 18–21 ms (~17–29% faster),
`Reused, TLSv1.3` confirmed in every resumed run.

## Harness quirks found during the work (recorded, not hidden)

- `cmake --install` for oqs-provider writes `oqsprovider.so` into the
  system OpenSSL modules directory (`/usr/lib/x86_64-linux-gnu/ossl-modules/`),
  ignoring `CMAKE_INSTALL_PREFIX` for the module. The pack uses the `.so`
  straight from the build tree; the stray system install was removed.
- `openssl list` on 3.0.13 does not honor `-provider-path`; use the
  `OPENSSL_MODULES` environment variable.
- `openssl s_client` prints no group name in TLS 1.3 output on 3.0.13
  (no `Server Temp Key` line); the negotiated group is proven by the
  `-msg` trace (key_share group `0x11ec`) plus the single-group server
  configuration.
- Session capture with `s_client -sess_out` needs stdin held open
  (~1 s) so the post-handshake NewSessionTicket arrives; with
  `</dev/null` the ticket is missed and no session file is written.
  (The first reference run's resumed numbers were client-side errors
  from the missing session file and were discarded, not reported.)
- `export A=... && command &` backgrounds the exports too; export on
  separate lines before backgrounding.

## Regression tests — `scripts/run_tests.sh`

T1 B-1 pinned behaviour (all 3 failure cases reproduce) · T2
post-remediation handshakes (5 full + 5 resumed, group + key_share
asserted) · T3 liboqs round-trips + FIPS sizes (both builds) · T4
optimized KEM round < 50% of reference · T5 remediation patch
round-trips cleanly · T6 ML-DSA-65 chain verifies. All 6 passed
(`outputs/test-output.log`).

## Reproduction

`scripts/clean_reproduce.sh <fresh-pack-copy>` rebuilds the whole stack
from `fixtures/`, regenerates all test certificates, re-runs benchmarks
(200/100), the bottleneck reproduction, a short TLS run (10 handshakes
per build) and the regression tests. Expected runtime ~25 min on a
2-CPU machine. A reproduction run was performed; see
`outputs/run-manifest.md`.

## LIMITATIONS (disclosed, not hidden)

1. **ML-DSA-65 certificates in a live TLS server are UNPROVEN on this
   stack.** Serving them fails on OpenSSL 3.0.13 (finding B-1). Whether
   a newer OpenSSL branch accepts them was not tested — no claim is made
   about OpenSSL 3.2/3.4/3.5 here.
2. **No in-process / high-throughput TLS measurement.** The optimized
   build's 4–7x crypto speedup is proven at the liboqs layer only. The
   `s_client` wall-clock comparison shows no difference; a throughput
   claim for a real server would need an in-process harness and was not
   built.
3. **Single machine, loopback, small samples.** TLS numbers are 30+30
   handshakes per build (two runs); liboqs numbers are 200/100
   iterations. No network latency, no concurrency, no multi-client load.
4. **Certificates are test-only** (CN=localhost, 1–2 day validity,
   generated fresh per run). No production trust or deployment claim.
5. **Reference vs optimized is a build-flag comparison**, not a
   comparison of algorithm implementations: both builds are liboqs
   0.16.0 from the same tarball; only `OQS_OPT_TARGET` differs.
6. **oqs-provider and liboqs carry no FIPS 140-3 validation** and the
   projects state they are not for production use; this pack is a
   benchmark and integration assessment, not a deployment recommendation.
