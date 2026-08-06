/*
 * bench_sw.c --- software-only AEAD benchmark, portable C, no ISA extensions.
 *
 * Ascon-AEAD128 : official ascon-c reference tree (NIST SP 800-232)
 * ChaCha20-Poly1305, AES-128-GCM : Mbed TLS 3.6 (the reference embedded stack),
 *                                  built with AESNI/AESCE disabled.
 *
 * Every algorithm goes through the same loop, same MAVLink v2 frame geometry
 * (10-byte header as associated data, payload+CRC as plaintext), same timer.
 *
 * Run: ./bench_sw [iterations]   -> CSV on stdout
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k);
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec, const unsigned char *c,
                        unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub,
                        const unsigned char *k);

#define MAV_HDR 10
#define MAXPT   256
#define TAGLEN  16

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static double bench_ascon(int ptlen, long iters, int rt_too) {
    unsigned char key[16], npub[16], ad[MAV_HDR], pt[MAXPT], ct[MAXPT + TAGLEN], rt[MAXPT];
    unsigned long long clen = 0, mlen = 0;
    memset(key, 0x11, 16); memset(ad, 0xFD, MAV_HDR);
    memset(pt, 0x5A, MAXPT); memset(npub, 0, 16);
    double t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        memcpy(npub, &i, sizeof(long));
        crypto_aead_encrypt(ct, &clen, pt, ptlen, ad, MAV_HDR, NULL, npub, key);
        if (rt_too) crypto_aead_decrypt(rt, &mlen, NULL, ct, clen, ad, MAV_HDR, npub, key);
    }
    return (now_ns() - t0) / (double)iters;
}

static double bench_gcm(int ptlen, long iters, int rt_too) {
    unsigned char key[16], iv[12], ad[MAV_HDR], pt[MAXPT], ct[MAXPT], tag[TAGLEN], rt[MAXPT];
    mbedtls_gcm_context ctx;
    memset(key, 0x11, 16); memset(ad, 0xFD, MAV_HDR);
    memset(pt, 0x5A, MAXPT); memset(iv, 0, 12);
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128);  /* key schedule once */
    double t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        memcpy(iv, &i, sizeof(int));
        mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, ptlen, iv, 12,
                                  ad, MAV_HDR, pt, ct, TAGLEN, tag);
        if (rt_too) {
            if (mbedtls_gcm_auth_decrypt(&ctx, ptlen, iv, 12, ad, MAV_HDR,
                                         tag, TAGLEN, ct, rt) != 0) {
                fprintf(stderr, "GCM verify failed\n"); exit(1);
            }
        }
    }
    double d = (now_ns() - t0) / (double)iters;
    mbedtls_gcm_free(&ctx);
    return d;
}

static double bench_chapoly(int ptlen, long iters, int rt_too) {
    unsigned char key[32], iv[12], ad[MAV_HDR], pt[MAXPT], ct[MAXPT], tag[TAGLEN], rt[MAXPT];
    mbedtls_chachapoly_context ctx;
    memset(key, 0x11, 32); memset(ad, 0xFD, MAV_HDR);
    memset(pt, 0x5A, MAXPT); memset(iv, 0, 12);
    mbedtls_chachapoly_init(&ctx);
    mbedtls_chachapoly_setkey(&ctx, key);
    double t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        memcpy(iv, &i, sizeof(int));
        mbedtls_chachapoly_encrypt_and_tag(&ctx, ptlen, iv, ad, MAV_HDR, pt, ct, tag);
        if (rt_too) {
            if (mbedtls_chachapoly_auth_decrypt(&ctx, ptlen, iv, ad, MAV_HDR,
                                                tag, ct, rt) != 0) {
                fprintf(stderr, "ChaChaPoly verify failed\n"); exit(1);
            }
        }
    }
    double d = (now_ns() - t0) / (double)iters;
    mbedtls_chachapoly_free(&ctx);
    return d;
}

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 200000L;
    int dflt[] = {12, 22, 33, 64, 128};
    int sizes[64]; int nsz;
    if (argc > 2) {                       /* optional file of payload sizes  */
        FILE *f = fopen(argv[2], "r");
        if (!f) { perror(argv[2]); return 1; }
        nsz = 0; int v;
        while (nsz < 64 && fscanf(f, "%d", &v) == 1)
            if (v > 0 && v <= MAXPT) sizes[nsz++] = v;
        fclose(f);
    } else {
        nsz = (int)(sizeof(dflt) / sizeof(dflt[0]));
        memcpy(sizes, dflt, sizeof dflt);
    }

    bench_ascon(64, 20000, 1); bench_gcm(64, 20000, 1); bench_chapoly(64, 20000, 1);

    printf("algorithm,payload_bytes,protected_bytes,enc_ns,roundtrip_ns,"
           "enc_Mbps,frames_per_s,cpu_pct_at_100fps\n");
    for (int s = 0; s < nsz; s++) {
        int p = sizes[s], frame = p + MAV_HDR;
        struct { const char *n; double e, r; } R[3];
        R[0].n = "Ascon-AEAD128";     R[0].e = bench_ascon(p, iters, 0);   R[0].r = bench_ascon(p, iters, 1);
        R[1].n = "ChaCha20-Poly1305"; R[1].e = bench_chapoly(p, iters, 0); R[1].r = bench_chapoly(p, iters, 1);
        R[2].n = "AES-128-GCM";       R[2].e = bench_gcm(p, iters, 0);     R[2].r = bench_gcm(p, iters, 1);
        for (int i = 0; i < 3; i++)
            printf("%s,%d,%d,%.4f,%.4f,%.2f,%.0f,%.6f\n", R[i].n, p, frame,
                   R[i].e, R[i].r, (double)frame * 8.0 / R[i].e * 1000.0,
                   1e9 / R[i].e, (R[i].e * 100.0) / 1e7);
    }
    return 0;
}
