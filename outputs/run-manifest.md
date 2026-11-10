# Run manifest

## Environment

- Date: 2026-11-11 (runs between ~01:05 and ~02:50 WIB; clean reproduction
  re-run after a runtime restart at ~01:45 WIB)
- Machine: Linux htch-runtime, AMD EPYC 9D25, x86-64, AVX2 + AVX512,
  4 vCPUs (1.5-CPU share), ~7.7 GB RAM, Ubuntu 24.04
- System OpenSSL: 3.0.13 (30 Jan 2024), libssl-dev 3.0.13
- Toolchain: GCC 13.3.0, CMake 3.28.3

## Pinned inputs

- liboqs 0.16.0 — `fixtures/liboqs-0.16.0.tar.gz`
  SHA-256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`
- oqs-provider 0.12.0 — `fixtures/oqs-provider-0.12.0.tar.gz`
  SHA-256 `81b1362af4276cb44afc98213cf0d8caeed8b966130844847163ad3a3b54b18f`

## Builds

- liboqs reference: `-DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic`
  (→ `-march=x86-64`); liboqs optimized: `-DOQS_OPT_TARGET=auto`
  (→ `-march=native`, AVX2/AVX512). Both `Release`, `OQS_BUILD_ONLY_LIB=ON`.
- oqs-provider 0.12.0 built once against each liboqs install; the
  resulting `oqsprovider.so` files are distinct (different SHA-256) and
  link liboqs statically (`ldd` shows only libcrypto + libc).
- Note: `cmake --install` for oqs-provider writes the module into the
  system OpenSSL modules directory, ignoring the install prefix; the pack
  uses the `.so` from the build tree, and the stray system install was
  removed afterwards.

## Runs performed (this pack's outputs/)

| Run | Log | Result |
|---|---|---|
| liboqs benchmark, reference (200 KEM / 100 SIG) | `baseline-reference.log` | KEM 120.47/114.82/127.80 us; SIG 424.95/1159.61/380.86 us; round-trips OK; sizes OK; peak RSS 6272 KiB |
| liboqs benchmark, optimized (200/100) | `baseline-optimized.log` | KEM 31.33/20.18/25.61 us; SIG 59.36/173.63/60.20 us; round-trips OK; sizes OK; peak RSS 6492 KiB |
| B-1 reproduction, 3 cases | `before-remediation-case{1,2,3}*.log` | All 3 reproduce as documented |
| TLS handshakes, reference, 30+30 | `tls-reference.log` | Full median 18 ms; resumed 15 ms; 0 failures |
| TLS handshakes, reference run 2, 30+30 | `tls-reference-run2.log` | Full median 18 ms; resumed 15 ms; 0 failures |
| TLS handshakes, optimized, 30+30 | `tls-optimized.log` | Full median 21 ms (one 60 ms outlier); resumed 15 ms; 0 failures |
| TLS handshakes, optimized run 2, 30+30 | `tls-optimized-run2.log` | Full median 19 ms; resumed 14 ms; 0 failures |
| Regression tests (6) | `test-output.log` | PASS=6 FAIL=0 |
| Regression test artifacts | `test-*.log`, `test-tls.log*` | T1–T6 evidence |

Sidecar files (`*.times`, `*.trace`) hold the raw per-handshake times and
the `-msg` trace behind each TLS log. The `before-remediation-mldsa65-default-early.log`
file is the first, pre-scripted observation of the B-1 failure (kept for
the record; the scripted reproduction supersedes it).

## Clean reproduction

`scripts/clean_reproduce.sh` was run from a fresh copy of the pack
(`../repro/pack`, work dir `../repro/repro-work`; full log
`../repro/clean-reproduce.log`). Result: **SUCCESS, exit 0**.

Reproduced headline numbers (fresh build, 200 KEM / 100 SIG iterations,
10+10 TLS handshakes per build):

- Reference liboqs: KEM keypair 93.84 us / encaps 86.58 us / decaps
  95.16 us (shipped: 120.47 / 114.82 / 127.80 us — same order, run-to-run
  variance on a shared VM); SIG keypair 319.98 / sign 820.45 / verify
  286.77 us; KEM round 275.57 us (shipped 363.09 us).
- Optimized liboqs: KEM keypair 30.14 / encaps 20.11 / decaps 25.60 us
  (shipped: 31.33 / 20.18 / 25.61 us — nearly identical); SIG keypair
  59.52 / sign 168.24 / verify 59.54 us; KEM round 75.84 us (shipped
  77.12 us).
- TLS: reference full median 17 ms, optimized 17.5 ms (again no
  wall-clock difference); resumed 14.5 / 14 ms.
- B-1: all 3 cases reproduced as documented.
- Regression tests: PASS=6 FAIL=0.

Note: the first clean-reproduction attempt was killed mid-build by a
runtime restart at ~01:45 WIB (reference liboqs at 73%); the re-run
resumed the partial build and completed. The reproduced copy's
`outputs/` differ from the shipped `outputs/` (fresh logs, different
timestamps/measurements) — that is expected; the shipped outputs are the
primary evidence.
