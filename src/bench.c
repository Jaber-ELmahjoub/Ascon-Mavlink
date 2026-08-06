/*
 * bench.c -- throughput of the proxy core, for the Performance section.
 *
 * Measures the same work the Python prototype does per frame: framing, AEAD
 * protection with the header as associated data, and on the receive side tag
 * verification plus the replay-window check. Reports frames per second and
 * microseconds per frame so the figure is directly comparable with the
 * 5,175 frames/s of the Python baseline.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ascon_mavlink.h"

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static size_t make_frame(uint8_t *b, uint8_t plen, uint8_t seq) {
    b[0] = AM_MAV_MAGIC; b[1] = plen; b[2] = 0; b[3] = 0;
    b[4] = seq; b[5] = 1; b[6] = 1; b[7] = 30; b[8] = 0; b[9] = 0;
    for (int i = 0; i < plen; i++) b[AM_MAV_HDR + i] = (uint8_t)i;
    b[AM_MAV_HDR + plen] = 0xAB; b[AM_MAV_HDR + plen + 1] = 0xCD;
    return AM_MAV_HDR + plen + AM_MAV_CRC;
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 1000000;
    int sizes[] = {9, 22, 28, 31, 64};
    uint8_t key[AM_KEYLEN];
    memset(key, 0x11, sizeof key);

    printf("payload,frames_per_s_protect,us_per_frame_protect,"
           "frames_per_s_roundtrip,us_per_frame_roundtrip\n");

    for (unsigned s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        uint8_t frame[AM_MAX_FRAME], wire[AM_MAX_DGRAM], back[AM_MAX_FRAME];
        size_t flen = make_frame(frame, (uint8_t)sizes[s], 1);

        /* warm-up */
        for (int i = 0; i < 10000; i++)
            am_protect_frame(frame, flen, key, 1, i, wire, sizeof wire);

        double t0 = now_s();
        for (long i = 0; i < iters; i++)
            am_protect_frame(frame, flen, key, 1, (uint64_t)i, wire, sizeof wire);
        double t1 = now_s();
        double prot = (t1 - t0) / iters;

        am_replay_t rp; am_replay_init(&rp);
        t0 = now_s();
        for (long i = 0; i < iters; i++) {
            am_protect_frame(frame, flen, key, 1, (uint64_t)i, wire, sizeof wire);
            am_unprotect_frame(wire, (size_t)(flen + AM_OVERHEAD), key, &rp,
                               back, sizeof back);
        }
        t1 = now_s();
        double rt = (t1 - t0) / iters;

        printf("%d,%.0f,%.3f,%.0f,%.3f\n", sizes[s],
               1.0 / prot, prot * 1e6, 1.0 / rt, rt * 1e6);
    }
    return 0;
}
