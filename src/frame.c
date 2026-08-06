/*
 * frame.c -- per-frame AEAD protection, anti-replay window, MAVLink framing.
 */
#include <string.h>
#include "ascon_mavlink.h"

/* ascon-c reference tree, Ascon-AEAD128 (NIST SP 800-232) */
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

static void put_le64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint64_t get_le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* ------------------------------------------------------------------ replay */
void am_replay_init(am_replay_t *r) {
    r->highest = 0;
    r->bitmap = 0;
    r->primed = 0;
}

int am_replay_check_and_update(am_replay_t *r, uint64_t counter) {
    if (!r->primed) {                       /* first frame of the session */
        r->primed = 1;
        r->highest = counter;
        r->bitmap = 1;
        return 1;
    }
    if (counter > r->highest) {             /* ahead of the window: advance */
        uint64_t shift = counter - r->highest;
        r->bitmap = (shift >= AM_REPLAY_WINDOW) ? 0 : (r->bitmap << shift);
        r->bitmap |= 1;
        r->highest = counter;
        return 1;
    }
    uint64_t back = r->highest - counter;
    if (back >= AM_REPLAY_WINDOW) return 0; /* too old to judge: reject */
    uint64_t mask = (uint64_t)1 << back;
    if (r->bitmap & mask) return 0;         /* already seen: replay */
    r->bitmap |= mask;                      /* legitimate reordering */
    return 1;
}

/* ------------------------------------------------------------- protection */
long am_protect_frame(const uint8_t *frame, size_t frame_len,
                      const uint8_t *key, uint64_t device_id, uint64_t counter,
                      uint8_t *out, size_t out_cap) {
    if (frame_len < AM_MAV_HDR) return -1;
    size_t body = frame_len - AM_MAV_HDR;
    if (out_cap < AM_MAV_HDR + AM_NONCELEN + body + AM_TAGLEN) return -1;

    memcpy(out, frame, AM_MAV_HDR);                       /* cleartext header */
    put_le64(out + AM_MAV_HDR, device_id);
    put_le64(out + AM_MAV_HDR + 8, counter);

    unsigned long long clen = 0;
    if (crypto_aead_encrypt(out + AM_MAV_HDR + AM_NONCELEN, &clen,
                            frame + AM_MAV_HDR, body,
                            frame, AM_MAV_HDR,
                            NULL, out + AM_MAV_HDR, key) != 0)
        return -1;
    return (long)(AM_MAV_HDR + AM_NONCELEN + clen);
}

long am_unprotect_frame(const uint8_t *dgram, size_t dgram_len,
                        const uint8_t *key, am_replay_t *replay,
                        uint8_t *out, size_t out_cap) {
    if (dgram_len < AM_MAV_HDR + AM_NONCELEN + AM_TAGLEN) return -1;
    const uint8_t *hdr   = dgram;
    const uint8_t *nonce = dgram + AM_MAV_HDR;
    const uint8_t *ct    = nonce + AM_NONCELEN;
    size_t clen = dgram_len - AM_MAV_HDR - AM_NONCELEN;

    if (out_cap < AM_MAV_HDR + clen) return -1;

    unsigned long long mlen = 0;
    if (crypto_aead_decrypt(out + AM_MAV_HDR, &mlen, NULL, ct, clen,
                            hdr, AM_MAV_HDR, nonce, key) != 0)
        return -1;                                   /* tag verification fail */

    /* Only after the tag verifies is the counter allowed to move the window,
       so a forged frame cannot desynchronise the receiver. */
    if (!am_replay_check_and_update(replay, get_le64(nonce + 8))) return -2;

    memcpy(out, hdr, AM_MAV_HDR);
    return (long)(AM_MAV_HDR + mlen);
}

/* -------------------------------------------------------------- framing */
size_t am_mav_frame_len(const uint8_t *buf, size_t avail) {
    if (avail < 1 || buf[0] != AM_MAV_MAGIC) return 0;
    if (avail < AM_MAV_HDR) return 0;
    size_t payload = buf[1];
    size_t incompat = buf[2];
    size_t total = AM_MAV_HDR + payload + AM_MAV_CRC +
                   ((incompat & 0x01) ? AM_MAV_SIG : 0);
    return (avail >= total) ? total : 0;
}
