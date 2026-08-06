/*
 * bench_m4.c -- AEAD comparison executed as bare-metal Cortex-M4 code.
 *
 * Runs under QEMU (mps2-an386, Cortex-M4) with -icount shift=0, which makes
 * virtual time advance one nanosecond per executed instruction. SysTick is
 * therefore an exact, deterministic instruction counter, and the figures below
 * are instructions retired on ARMv7E-M -- real Thumb-2 code on 32-bit
 * registers, not an x86 extrapolation.
 *
 * NOTE: this counts instructions, not cycles. On Cortex-M4 most ALU operations
 * are single-cycle and SRAM is zero-wait-state, so the two are close, but flash
 * wait states and pipeline effects are not modelled. Report as instructions.
 */
#include <stdint.h>
#include <string.h>
#include "sh.h"
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

#define SYST_CSR (*(volatile uint32_t *)0xE000E010)
#define SYST_RVR (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR (*(volatile uint32_t *)0xE000E018)

#define MAV_HDR 10          /* MAVLink v2 header, authenticated as AD */
#define TAGLEN  16
#define REPS    64          /* averaged over this many frames */

static uint8_t key[32], npub[16], ad[MAV_HDR], pt[256], ct[300], rt[256], tag[16];

static inline uint32_t tick(void) { return SYST_CVR; }

/* SysTick counts down at the core clock; with -icount shift=0 one tick equals
   a fixed number of instructions, established by calibrate() below. */
static uint32_t insn_per_tick = 1;

__attribute__((noinline, naked)) static void nop_block(void) {
    /* exactly 4096 NOPs, then return: a known instruction count */
    __asm__ volatile (".rept 4096\n\tnop\n\t.endr\n\tbx lr");
}

static uint32_t calibrate(void) {
    uint32_t a = tick();
    nop_block();
    uint32_t b = tick();
    uint32_t d = (a - b) & 0xFFFFFF;
    return d ? (4096u + d / 2) / d : 1;   /* 4096 NOPs, rounded */
}

static uint32_t bench_ascon(int ptlen) {
    unsigned long long clen, mlen;
    uint32_t a = tick();
    for (int i = 0; i < REPS; i++) {
        npub[0] = (uint8_t)i;
        crypto_aead_encrypt(ct, &clen, pt, ptlen, ad, MAV_HDR, 0, npub, key);
    }
    uint32_t b = tick();
    (void)mlen;
    return (((a - b) & 0xFFFFFF) * insn_per_tick) / REPS;
}

static uint32_t bench_ascon_rt(int ptlen) {
    unsigned long long clen, mlen;
    uint32_t a = tick();
    for (int i = 0; i < REPS; i++) {
        npub[0] = (uint8_t)i;
        crypto_aead_encrypt(ct, &clen, pt, ptlen, ad, MAV_HDR, 0, npub, key);
        crypto_aead_decrypt(rt, &mlen, 0, ct, clen, ad, MAV_HDR, npub, key);
    }
    uint32_t b = tick();
    return (((a - b) & 0xFFFFFF) * insn_per_tick) / REPS;
}

static mbedtls_gcm_context gcm;
static mbedtls_chachapoly_context cpc;

static uint32_t bench_gcm(int ptlen, int roundtrip) {
    uint32_t a = tick();
    for (int i = 0; i < REPS; i++) {
        npub[0] = (uint8_t)i;
        mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, ptlen, npub, 12,
                                  ad, MAV_HDR, pt, ct, TAGLEN, tag);
        if (roundtrip)
            mbedtls_gcm_auth_decrypt(&gcm, ptlen, npub, 12, ad, MAV_HDR,
                                     tag, TAGLEN, ct, rt);
    }
    uint32_t b = tick();
    return (((a - b) & 0xFFFFFF) * insn_per_tick) / REPS;
}

static uint32_t bench_cpc(int ptlen, int roundtrip) {
    uint32_t a = tick();
    for (int i = 0; i < REPS; i++) {
        npub[0] = (uint8_t)i;
        mbedtls_chachapoly_encrypt_and_tag(&cpc, ptlen, npub, ad, MAV_HDR,
                                           pt, ct, tag);
        if (roundtrip)
            mbedtls_chachapoly_auth_decrypt(&cpc, ptlen, npub, ad, MAV_HDR,
                                            tag, ct, rt);
    }
    uint32_t b = tick();
    return (((a - b) & 0xFFFFFF) * insn_per_tick) / REPS;
}

int main(void) {
    SYST_RVR = 0x00FFFFFF; SYST_CVR = 0; SYST_CSR = 5;
    memset(key, 0x11, sizeof key);
    memset(ad, 0xFD, sizeof ad);
    memset(pt, 0x5A, sizeof pt);
    memset(npub, 0, sizeof npub);

    insn_per_tick = calibrate();
    sh_num("instructions per SysTick tick (calibration) = ", insn_per_tick);

    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
    mbedtls_chachapoly_init(&cpc);
    mbedtls_chachapoly_setkey(&cpc, key);

    static const int sizes[] = {12, 22, 33, 64, 128};
    sh_puts("\ninstructions per frame, Cortex-M4 (ARMv7E-M)\n");
    sh_puts("payload,algorithm,encrypt,encrypt+verify\n");
    for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        int p = sizes[s];
        sh_num("--- payload bytes = ", (uint32_t)p);
        sh_num("Ascon-AEAD128      encrypt = ", bench_ascon(p));
        sh_num("Ascon-AEAD128      enc+ver = ", bench_ascon_rt(p));
        sh_num("ChaCha20-Poly1305  encrypt = ", bench_cpc(p, 0));
        sh_num("ChaCha20-Poly1305  enc+ver = ", bench_cpc(p, 1));
        sh_num("AES-128-GCM        encrypt = ", bench_gcm(p, 0));
        sh_num("AES-128-GCM        enc+ver = ", bench_gcm(p, 1));
    }

    /* one-off key installation cost */
    sh_puts("\nkey installation (instructions, one-off per rekey)\n");
    {
        uint32_t a = tick();
        for (int i = 0; i < REPS; i++)
            mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
        uint32_t b = tick();
        sh_num("AES-128-GCM key schedule + GHASH = ",
               (((a - b) & 0xFFFFFF) * insn_per_tick) / REPS);
        a = tick();
        for (int i = 0; i < REPS; i++) mbedtls_chachapoly_setkey(&cpc, key);
        b = tick();
        sh_num("ChaCha20-Poly1305 setkey        = ",
               (((a - b) & 0xFFFFFF) * insn_per_tick) / REPS);
        sh_puts("Ascon-AEAD128: none (key absorbed into permutation)\n");
    }

    sh_exit();
    return 0;
}
