# Evidence index — claim to evidence

Every measured or specification-derived claim in this pack, its evidence,
and its primary source. `outputs/` logs are unedited program output.

## Specification claims (primary sources)

| # | Claim | Evidence in this pack | Primary source |
|---|---|---|---|
| S1 | ML-KEM-768: ek 1184 B, dk 2400 B, ct 1088 B, ss 32 B | `outputs/baseline-*.log` — runtime size checks print OK | FIPS 203, Table 3 (Sizes of keys and ciphertexts of ML-KEM) |
| S2 | ML-DSA-65: sk 4032 B, pk 1952 B, sig 3309 B; security category 3 | `outputs/baseline-*.log` — runtime size checks print OK | FIPS 204, Table 1 (parameter sets) and Table 2 (sizes of keys and signatures) |
| S3 | oqs-provider 0.12.0 pairs with liboqs 0.16.0 | `fixtures/` tarballs + `scripts/build_all.sh` (builds succeed); provider reports version 0.12.0, liboqs reports 0.16.0 | oqs-provider 0.12.0 release notes (GitHub releases): HQC reinstated with liboqs 0.16.0 naming; SPHINCS+ removed |
| S4 | X25519MLKEM768 TLS group codepoint is 0x11ec | `outputs/tls-*.log` — trace parse: `group=0x11ec` | oqs-provider 0.12.0 `ALGORITHMS.md` (KEM table) and IANA codepoint assignment referenced there |
| S5 | mldsa65 OID is 2.16.840.1.101.3.4.3.18 | Certificate text in `outputs/tls-reference.log` header / `scripts/make_certs.sh` output | oqs-provider 0.12.0 `ALGORITHMS.md` (signature table); FIPS 204 |
| S6 | OpenSSL 3.0.13 `ssl_set_cert()` rejects provider-defined keys (`unknown certificate type`) and `ssl_security_cert()` rejects digest-less signatures (`ca md too weak`) | `outputs/before-remediation-case*.log` | OpenSSL 3.0.13 source, `ssl/ssl_rsa.c`: `SSL_CTX_use_certificate()` (calls `ssl_security_cert`, then `ssl_set_cert`, which calls `ssl_cert_lookup_by_pkey`) |
| S7 | liboqs / oqs-provider carry no FIPS 140-3 validation and are not recommended for production use | `docs/methodology.md` LIMITATIONS | liboqs README (`WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT…`); oqs-provider README limitations |

## Measurement claims (results → raw outputs)

| # | Claim | Evidence |
|---|---|---|
| M1 | Reference build: ML-KEM-768 keypair 120.47 us, encaps 114.82 us, decaps 127.80 us (mean, n=200) | `outputs/baseline-reference.log` |
| M2 | Optimized build: ML-KEM-768 keypair 31.33 us, encaps 20.18 us, decaps 25.61 us (mean, n=200) | `outputs/baseline-optimized.log` |
| M3 | Reference build: ML-DSA-65 keypair 424.95 us, sign 1159.61 us, verify 380.86 us (mean, n=100) | `outputs/baseline-reference.log` |
| M4 | Optimized build: ML-DSA-65 keypair 59.36 us, sign 173.63 us, verify 60.20 us (mean, n=100) | `outputs/baseline-optimized.log` |
| M5 | KEM round-trip (encaps/decaps shared-secret equality) OK, 200 iterations, both builds | `outputs/baseline-*.log` |
| M6 | SIG sign/verify round-trip OK, 100 iterations, both builds | `outputs/baseline-*.log` |
| M7 | Peak RSS: reference 6272 KiB, optimized 6492 KiB | `outputs/baseline-*.log` |
| M8 | TLS full handshakes, ECDSA P-384 cert + X25519MLKEM768: reference median 18 ms (runs 1+2), optimized median 21 ms / 19 ms (runs 1+2), n=30 each | `outputs/tls-reference.log`, `outputs/tls-reference-run2.log`, `outputs/tls-optimized.log`, `outputs/tls-optimized-run2.log` |
| M9 | TLS resumed handshakes: reference median 15 ms, optimized 15 ms / 14 ms; `Reused, TLSv1.3` in every resumed run | same TLS logs |
| M10 | ClientHello key_share: group 0x11ec, key_exchange_len 1216 B (= X25519 32 + ML-KEM-768 ek 1184) | `outputs/tls-*.log` trace lines; raw trace in `outputs/tls-*.log.trace` |
| M11 | B-1 reproduces: mldsa65 default → `ca md too weak`; mldsa65 SECLEVEL=0 → `unknown certificate type`; p384_mldsa65 SECLEVEL=0 → `unknown certificate type` | `outputs/before-remediation-case1-mldsa65-default.log`, `...-case2-mldsa65-seclevel0.log`, `...-case3-hybrid-p384mldsa65-seclevel0.log` |
| M12 | ML-DSA-65 certificate chain verifies (`openssl verify ... OK`) | regression test T6 in `outputs/test-output.log` |
| M13 | Remediation patch applies cleanly and reproduces the shipped config | regression test T5 in `outputs/test-output.log` |
| M14 | All 6 regression tests pass | `outputs/test-output.log` (`run_tests: PASS=6 FAIL=0`) |
| M15 | Clean reproduction from a fresh copy of the pack succeeds | `../repro/clean-reproduce.log` (outside the pack; see `outputs/run-manifest.md`) |

## Negative / unmeasured claims (disclosed)

| # | Claim | Status |
|---|---|---|
| N1 | Optimized build improves TLS handshake wall-clock time | NOT SHOWN — medians 18 ms (ref) vs 19–21 ms (opt); difference within noise. Not claimed. |
| N2 | ML-DSA-65 certificates can be served by a newer OpenSSL branch | UNVERIFIED — not tested; no claim made. |
| N3 | Optimized build improves server throughput under load | UNMEASURED — would need an in-process harness; not claimed. |
| N4 | Any production-readiness or FIPS-validation claim | NOT CLAIMED — see S7. |

## File inventory (pack root)

- `README.md` — overview, layout, reproduction, headline numbers.
- `docs/methodology.md` — this assessment's method, findings, limitations.
- `docs/evidence-index.md` — this file.
- `docs/index.html` — rendered findings page (same tables, same disclosures).
- `src/bench_liboqs.c` — liboqs benchmark harness.
- `src/remediation/` — `server-config.patch`, `server-config.cnf`, `README.md`.
- `scripts/` — `build_all.sh`, `run_benchmarks.sh`, `run_tls_handshakes.sh`,
  `reproduce_bottleneck.sh`, `make_certs.sh`, `run_tests.sh`, `run_all.sh`,
  `clean_reproduce.sh`, `verify_digests.sh`.
- `configs/` — `openssl-providers.cnf` (post-remediation),
  `openssl-seclevel0.cnf` (B-1 reproduction only).
- `fixtures/` — `liboqs-0.16.0.tar.gz`, `oqs-provider-0.12.0.tar.gz`
  (pinned sources with SHA-256 in `SHA256SUMS`).
- `outputs/` — unedited logs + run manifest (see `outputs/run-manifest.md`).
- `SHA256SUMS` — digests over all pack files (verify with
  `scripts/verify_digests.sh`).
