/*
 * bench_aead.c --- self-measured AEAD benchmark for the Ascon-MAVLink paper.
 *
 * Measures Ascon-AEAD128 (NIST SP 800-232, official ascon-c reference tree),
 * ChaCha20-Poly1305 and AES-128-GCM (OpenSSL libcrypto) on MAVLink v2 frame
 * geometry: 10-byte header as associated data, payload+CRC as plaintext.
 *
 * All three are driven through the same loop, the same frame sizes and the
 * same timer, so the numbers are directly comparable to each other.
 *
 * Build: see Makefile.  Run: ./bench_aead [iterations]
 * Output: CSV on stdout, human-readable notes on stderr.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>

/* ascon-c reference tree */
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

#define MAV_HDR 10          /* MAVLink v2 header, authenticated as AD  */
#define MAXPT   256
#define TAGLEN  16

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* ---------------- Ascon-AEAD128 ---------------- */
static double bench_ascon(int ptlen, long iters, int decrypt_too) {
    unsigned char key[16], npub[16], ad[MAV_HDR], pt[MAXPT], ct[MAXPT + TAGLEN];
    unsigned char rt[MAXPT];
    unsigned long long clen = 0, mlen = 0;
    memset(key, 0x11, sizeof key); memset(ad, 0xFD, sizeof ad);
    memset(pt, 0x5A, sizeof pt);   memset(npub, 0, sizeof npub);

    double t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        /* structured nonce: little-endian per-frame counter, as in proxy.py */
        memcpy(npub, &i, sizeof(long));
        crypto_aead_encrypt(ct, &clen, pt, ptlen, ad, MAV_HDR, NULL, npub, key);
        if (decrypt_too)
            crypto_aead_decrypt(rt, &mlen, NULL, ct, clen, ad, MAV_HDR, npub, key);
    }
    double t1 = now_ns();
    return (t1 - t0) / (double)iters;
}

/* ---------------- OpenSSL AEADs ---------------- */
static double bench_evp(const EVP_CIPHER *ciph, int ivlen, int ptlen,
                        long iters, int decrypt_too) {
    unsigned char key[32], iv[16], ad[MAV_HDR], pt[MAXPT], ct[MAXPT];
    unsigned char tag[TAGLEN], rt[MAXPT];
    int outl;
    memset(key, 0x11, sizeof key); memset(ad, 0xFD, sizeof ad);
    memset(pt, 0x5A, sizeof pt);   memset(iv, 0, sizeof iv);

    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *d = EVP_CIPHER_CTX_new();
    /* key schedule / GHASH precompute done once, as a real proxy would */
    EVP_EncryptInit_ex(e, ciph, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL);
    EVP_EncryptInit_ex(e, NULL, NULL, key, NULL);
    EVP_DecryptInit_ex(d, ciph, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL);
    EVP_DecryptInit_ex(d, NULL, NULL, key, NULL);

    double t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        memcpy(iv, &i, sizeof(long));
        EVP_EncryptInit_ex(e, NULL, NULL, NULL, iv);
        EVP_EncryptUpdate(e, NULL, &outl, ad, MAV_HDR);
        EVP_EncryptUpdate(e, ct, &outl, pt, ptlen);
        EVP_EncryptFinal_ex(e, ct + outl, &outl);
        EVP_CIPHER_CTX_ctrl(e, EVP_CTRL_AEAD_GET_TAG, TAGLEN, tag);
        if (decrypt_too) {
            EVP_DecryptInit_ex(d, NULL, NULL, NULL, iv);
            EVP_DecryptUpdate(d, NULL, &outl, ad, MAV_HDR);
            EVP_DecryptUpdate(d, rt, &outl, ct, ptlen);
            EVP_CIPHER_CTX_ctrl(d, EVP_CTRL_AEAD_SET_TAG, TAGLEN, tag);
            if (EVP_DecryptFinal_ex(d, rt + outl, &outl) <= 0) {
                fprintf(stderr, "TAG VERIFY FAILED\n"); exit(1);
            }
        }
    }
    double t1 = now_ns();
    EVP_CIPHER_CTX_free(e); EVP_CIPHER_CTX_free(d);
    return (t1 - t0) / (double)iters;
}

/* ------------- key-setup cost (one-off, per rekey) ------------- */
static double bench_keysetup(const EVP_CIPHER *ciph, long iters) {
    unsigned char key[32];
    memset(key, 0x11, sizeof key);
    EVP_CIPHER_CTX *e = EVP_CIPHER_CTX_new();
    double t0 = now_ns();
    for (long i = 0; i < iters; i++) {
        EVP_EncryptInit_ex(e, ciph, NULL, key, NULL);
    }
    double t1 = now_ns();
    EVP_CIPHER_CTX_free(e);
    return (t1 - t0) / (double)iters;
}

int main(int argc, char **argv) {
    long iters = (argc > 1) ? atol(argv[1]) : 200000L;
    int sizes[] = {12, 22, 33, 64, 128};   /* MAVLink payload+CRC sizes */
    int nsz = sizeof(sizes) / sizeof(sizes[0]);

    fprintf(stderr, "OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    fprintf(stderr, "iterations per point: %ld\n\n", iters);

    /* warm-up */
    bench_ascon(64, 20000, 1);
    bench_evp(EVP_chacha20_poly1305(), 12, 64, 20000, 1);
    bench_evp(EVP_aes_128_gcm(), 12, 64, 20000, 1);

    printf("algorithm,payload_bytes,frame_bytes,enc_ns,encdec_ns,"
           "enc_Mbps,frames_per_s,cpu_pct_at_100fps\n");

    for (int s = 0; s < nsz; s++) {
        int pt = sizes[s];
        int frame = MAV_HDR + pt;           /* bytes actually protected */
        struct { const char *name; double enc, ed; } r[3];

        r[0].name = "Ascon-AEAD128";
        r[0].enc = bench_ascon(pt, iters, 0);
        r[0].ed  = bench_ascon(pt, iters, 1);

        r[1].name = "ChaCha20-Poly1305";
        r[1].enc = bench_evp(EVP_chacha20_poly1305(), 12, pt, iters, 0);
        r[1].ed  = bench_evp(EVP_chacha20_poly1305(), 12, pt, iters, 1);

        r[2].name = "AES-128-GCM";
        r[2].enc = bench_evp(EVP_aes_128_gcm(), 12, pt, iters, 0);
        r[2].ed  = bench_evp(EVP_aes_128_gcm(), 12, pt, iters, 1);

        for (int i = 0; i < 3; i++) {
            double mbps = (double)frame * 8.0 / r[i].enc * 1000.0; /* B*8/ns -> Gbit/s*1e3 => Mbps */
            double fps  = 1e9 / r[i].enc;
            double cpu  = 100.0 * (r[i].enc * 100.0) / 1e9;        /* 100 frames/s */
            printf("%s,%d,%d,%.4f,%.4f,%.2f,%.0f,%.6f\n",
                   r[i].name, pt, frame, r[i].enc, r[i].ed, mbps, fps, cpu);
        }
    }

    fprintf(stderr, "\nkey-setup / rekey cost (ns per key install):\n");
    fprintf(stderr, "  ChaCha20-Poly1305 : %.1f ns\n",
            bench_keysetup(EVP_chacha20_poly1305(), 200000));
    fprintf(stderr, "  AES-128-GCM       : %.1f ns  (key schedule + GHASH H precompute)\n",
            bench_keysetup(EVP_aes_128_gcm(), 200000));
    fprintf(stderr, "  Ascon-AEAD128     : 0.0 ns  (key absorbed into permutation, no schedule)\n");
    return 0;
}
