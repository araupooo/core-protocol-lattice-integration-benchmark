/* bench_liboqs.c — liboqs-level throughput + peak-memory benchmark.
 *
 * Measures, for ML-KEM-768 and ML-DSA-65, the operations the oqs-provider
 * dispatches to inside the TLS 1.3 handshake call path:
 *   KEM: keypair generation, encapsulation, decapsulation
 *   SIG: keypair generation, signing, verification
 * Prints unedited per-operation timing (ops/s, mean/min/max microseconds),
 * FIPS size checks, correctness round-trips, and peak RSS.
 * Usage: bench_liboqs [iterations_kem] [iterations_sig]
 * Compile: cc -O2 -I<liboqs include> bench_liboqs.c -L<liboqs lib> -loqs -o bench_liboqs
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <oqs/oqs.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

typedef struct {
    double total_s, min_us, max_us;
    int n;
} Stats;

static void stats_init(Stats *s) { s->total_s = 0; s->min_us = 1e18; s->max_us = 0; s->n = 0; }
static void stats_add(Stats *s, double dt_s) {
    double us = dt_s * 1e6;
    s->total_s += dt_s;
    if (us < s->min_us) s->min_us = us;
    if (us > s->max_us) s->max_us = us;
    s->n++;
}
static void stats_print(const char *label, const Stats *s) {
    printf("%-28s n=%-5d mean=%9.2f us  min=%9.2f us  max=%9.2f us  rate=%9.2f ops/s\n",
           label, s->n, s->total_s * 1e6 / s->n, s->min_us, s->max_us, s->n / s->total_s);
}

static long peak_rss_kb(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss; /* KiB on Linux */
}

int main(int argc, char **argv) {
    int n_kem = argc > 1 ? atoi(argv[1]) : 200;
    int n_sig = argc > 2 ? atoi(argv[2]) : 100;
    printf("bench_liboqs: ML-KEM-768 / ML-DSA-65 throughput benchmark\n");
    printf("liboqs version: %s\n", OQS_VERSION_TEXT);
    printf("iterations: kem=%d sig=%d\n", n_kem, n_sig);

    /* ---- ML-KEM-768 ---- */
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) { fprintf(stderr, "FATAL: OQS_KEM_new(ML-KEM-768) failed\n"); return 1; }
    printf("\n[KEM] algorithm: %s\n", kem->method_name);
    printf("[KEM] length_public_key=%zu (FIPS 203 Table 3: 1184) %s\n",
           kem->length_public_key, kem->length_public_key == 1184 ? "OK" : "MISMATCH");
    printf("[KEM] length_secret_key=%zu (FIPS 203 Table 3: 2400) %s\n",
           kem->length_secret_key, kem->length_secret_key == 2400 ? "OK" : "MISMATCH");
    printf("[KEM] length_ciphertext=%zu (FIPS 203 Table 3: 1088) %s\n",
           kem->length_ciphertext, kem->length_ciphertext == 1088 ? "OK" : "MISMATCH");
    printf("[KEM] length_shared_secret=%zu (FIPS 203 Table 3: 32) %s\n",
           kem->length_shared_secret, kem->length_shared_secret == 32 ? "OK" : "MISMATCH");

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_e = malloc(kem->length_shared_secret);
    uint8_t *ss_d = malloc(kem->length_shared_secret);
    if (!pk || !sk || !ct || !ss_e || !ss_d) { fprintf(stderr, "FATAL: malloc\n"); return 1; }

    Stats kg, enc, dec;
    stats_init(&kg); stats_init(&enc); stats_init(&dec);
    for (int i = 0; i < n_kem; i++) {
        double t0 = now_s();
        if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: keypair\n"); return 1; }
        stats_add(&kg, now_s() - t0);
        t0 = now_s();
        if (OQS_KEM_encaps(kem, ct, ss_e, pk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: encaps\n"); return 1; }
        stats_add(&enc, now_s() - t0);
        t0 = now_s();
        if (OQS_KEM_decaps(kem, ss_d, ct, sk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: decaps\n"); return 1; }
        stats_add(&dec, now_s() - t0);
        if (memcmp(ss_e, ss_d, kem->length_shared_secret) != 0) {
            fprintf(stderr, "FATAL: shared-secret mismatch at iteration %d\n", i);
            return 1;
        }
    }
    printf("[KEM] shared-secret round-trip: OK (%d iterations)\n", n_kem);
    stats_print("[KEM] keypair", &kg);
    stats_print("[KEM] encaps", &enc);
    stats_print("[KEM] decaps", &dec);
    printf("[KEM] full KEM round (keypair+encaps+decaps) mean: %.2f us\n",
           (kg.total_s + enc.total_s + dec.total_s) * 1e6 / n_kem);
    OQS_KEM_free(kem);
    free(pk); free(sk); free(ct); free(ss_e); free(ss_d);

    /* ---- ML-DSA-65 ---- */
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) { fprintf(stderr, "FATAL: OQS_SIG_new(ML-DSA-65) failed\n"); return 1; }
    printf("\n[SIG] algorithm: %s\n", sig->method_name);
    printf("[SIG] length_public_key=%zu (FIPS 204 Table 2: 1952) %s\n",
           sig->length_public_key, sig->length_public_key == 1952 ? "OK" : "MISMATCH");
    printf("[SIG] length_secret_key=%zu (FIPS 204 Table 2: 4032) %s\n",
           sig->length_secret_key, sig->length_secret_key == 4032 ? "OK" : "MISMATCH");
    printf("[SIG] length_signature=%zu (FIPS 204 Table 2: 3309) %s\n",
           sig->length_signature, sig->length_signature == 3309 ? "OK" : "MISMATCH");

    uint8_t *spk = malloc(sig->length_public_key);
    uint8_t *ssk = malloc(sig->length_secret_key);
    uint8_t *sg = malloc(sig->length_signature);
    size_t sg_len = 0;
    const uint8_t msg[] = "TLS 1.3 CertificateVerify transcript hash input (64 bytes of test data)";
    if (!spk || !ssk || !sg) { fprintf(stderr, "FATAL: malloc\n"); return 1; }

    Stats skg, sgn, vrf;
    stats_init(&skg); stats_init(&sgn); stats_init(&vrf);
    for (int i = 0; i < n_sig; i++) {
        double t0 = now_s();
        if (OQS_SIG_keypair(sig, spk, ssk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: sig keypair\n"); return 1; }
        stats_add(&skg, now_s() - t0);
        t0 = now_s();
        if (OQS_SIG_sign(sig, sg, &sg_len, msg, sizeof(msg) - 1, ssk) != OQS_SUCCESS) {
            fprintf(stderr, "FATAL: sign\n"); return 1;
        }
        stats_add(&sgn, now_s() - t0);
        t0 = now_s();
        if (OQS_SIG_verify(sig, msg, sizeof(msg) - 1, sg, sg_len, spk) != OQS_SUCCESS) {
            fprintf(stderr, "FATAL: verify failed at iteration %d\n", i); return 1;
        }
        stats_add(&vrf, now_s() - t0);
    }
    printf("[SIG] sign/verify round-trip: OK (%d iterations, sig_len=%zu)\n", n_sig, sg_len);
    stats_print("[SIG] keypair", &skg);
    stats_print("[SIG] sign", &sgn);
    stats_print("[SIG] verify", &vrf);
    OQS_SIG_free(sig);
    free(spk); free(ssk); free(sg);

    printf("\npeak RSS: %ld KiB\n", peak_rss_kb());
    printf("bench_liboqs: DONE\n");
    return 0;
}
