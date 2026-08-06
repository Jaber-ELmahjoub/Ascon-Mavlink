/*
 * bench_handshake.c -- cost of the per-mission session-key handshake on an
 * emulated Cortex-M4, measured in instructions retired.
 *
 * Primitives:
 *   X25519            ephemeral ECDH  (Monocypher)
 *   Ed25519 (RFC 8032) identity signature, SHA-512 variant (Monocypher)
 *   Ascon-XOF128      session-key derivation (official ascon-c)
 *
 * Reports the cost of each step and the total per side, so the paper can quote
 * a measured handshake latency instead of an estimate.
 */
#include <stdint.h>
#include <string.h>
#include "sh.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);

#define SYST_RVR (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR (*(volatile uint32_t *)0xE000E018)
#define SYST_CSR (*(volatile uint32_t *)0xE000E010)
#define REPS 4

static inline uint32_t tick(void) { return SYST_CVR; }
static uint32_t ipt = 40;               /* instructions per SysTick tick */

__attribute__((noinline, naked)) static void nop_block(void) {
    __asm__ volatile (".rept 4096\n\tnop\n\t.endr\n\tbx lr");
}
static uint32_t calibrate(void) {
    uint32_t a = tick(); nop_block(); uint32_t b = tick();
    uint32_t d = (a - b) & 0xFFFFFF;
    return d ? (4096u + d / 2) / d : 1;
}
#define MEASURE(label, body) do {                                   \
    uint32_t _a = tick();                                           \
    for (int _r = 0; _r < REPS; _r++) { body; }                     \
    uint32_t _b = tick();                                           \
    uint32_t _n = (((_a - _b) & 0xFFFFFF) * ipt) / REPS;            \
    total += _n;                                                    \
    sh_num(label, _n);                                              \
} while (0)

/* long-term identity keys, provisioned once at pairing */
static uint8_t id_sk[64], id_pk[32];
/* ephemeral session keys, regenerated every mission */
static uint8_t eph_sk[32], eph_pk[32], peer_pk[32], shared[32];
static uint8_t sig[64], transcript[96], session_key[16], xof_out[64];

int main(void) {
    SYST_RVR = 0x00FFFFFF; SYST_CVR = 0; SYST_CSR = 5;
    ipt = calibrate();
    sh_num("instructions per SysTick tick (calibration) = ", ipt);

    memset(id_sk, 0x11, sizeof id_sk);
    memset(eph_sk, 0x22, sizeof eph_sk);
    memset(peer_pk, 0x33, sizeof peer_pk);

    uint32_t total = 0;
    sh_puts("\nhandshake cost per side, Cortex-M4 (instructions)\n");

    /* 1. derive long-term identity public key (pairing only, not per mission) */
    {
        uint8_t seed[32];
        memset(seed, 0x44, sizeof seed);
        uint32_t a = tick();
        for (int r = 0; r < REPS; r++) crypto_ed25519_key_pair(id_sk, id_pk, seed);
        uint32_t b = tick();
        sh_num("Ed25519 identity key pair (pairing only) = ",
               (((a - b) & 0xFFFFFF) * ipt) / REPS);
        memset(seed, 0x44, sizeof seed);   /* key_pair wipes the seed */
    }

    /* 2. ephemeral X25519 public key */
    MEASURE("X25519 ephemeral public key           = ",
            crypto_x25519_public_key(eph_pk, eph_sk));

    /* 3. sign the ephemeral public key with the identity key */
    memcpy(transcript, eph_pk, 32);
    MEASURE("Ed25519 sign ephemeral public key     = ",
            crypto_ed25519_sign(sig, id_sk, transcript, 32));

    /* 4. verify the peer's signed ephemeral public key */
    MEASURE("Ed25519 verify peer public key        = ",
            crypto_ed25519_check(sig, id_pk, transcript, 32));

    /* 5. ECDH shared secret */
    MEASURE("X25519 shared secret                  = ",
            crypto_x25519(shared, eph_sk, peer_pk));

    /* 6. derive the session key from secret + transcript */
    memcpy(transcript, shared, 32);
    memcpy(transcript + 32, eph_pk, 32);
    memcpy(transcript + 64, peer_pk, 32);
    MEASURE("Ascon-XOF128 session-key derivation   = ",
            crypto_hash(xof_out, transcript, sizeof transcript));
    memcpy(session_key, xof_out, 16);

    /* 7. erase ephemeral material -> forward secrecy */
    MEASURE("wipe ephemeral key material           = ",
            crypto_wipe(eph_sk, 32); crypto_wipe(shared, 32));

    sh_puts("\n");
    sh_num("TOTAL per-mission handshake, per side  = ", total);
    sh_num("  equivalent ms at 168 MHz (x1000)     = ", (total * 1000u) / 168000u);
    sh_puts("(divide the second figure by 1000 to read milliseconds)\n");
    sh_num("session key first byte (sanity check)  = ", session_key[0]);

    sh_exit();
    return 0;
}
