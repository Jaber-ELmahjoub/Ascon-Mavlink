#include <stdint.h>
#include <string.h>
#include "sh.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
int crypto_hash(unsigned char*, const unsigned char*, unsigned long long);
static uint8_t a[64], b[64], c[64], d[96];
#define PAINT 0xA5A5A5A5u
#define WINDOW (32u * 1024u / 4u)          /* 32 KB below the stack pointer */
int main(void) {
    uint32_t sp; __asm__ volatile ("mov %0, sp" : "=r"(sp));
    uint32_t *base = (uint32_t *)((sp - 256) - WINDOW * 4);
    for (uint32_t i = 0; i < WINDOW; i++) base[i] = PAINT;

    memset(b, 0x22, sizeof b); memset(c, 0x33, sizeof c);
    crypto_x25519_public_key(a, b);
    crypto_x25519(a, b, c);
    crypto_ed25519_sign(a, b, d, 32);
    crypto_ed25519_check(a, b, d, 32);
    crypto_hash(a, d, 96);

    uint32_t i = 0;
    while (i < WINDOW && base[i] == PAINT) i++;
    sh_num("peak stack used by handshake (bytes) = ", (WINDOW - i) * 4);
    sh_exit(); return 0;
}
