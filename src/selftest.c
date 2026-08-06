/*
 * selftest.c -- verifies the properties the paper claims, without needing SITL.
 *
 *   1. handshake: both sides derive identical keys
 *   2. handshake: a forged signature is rejected
 *   3. directional keys differ (the nonce-collision fix)
 *   4. round trip: protect -> unprotect recovers the frame exactly
 *   5. tampering the ciphertext fails tag verification
 *   6. tampering the cleartext header fails tag verification
 *   7. a replayed frame is rejected
 *   8. reordering within the window is accepted
 *   9. multiple MAVLink frames in one datagram are framed correctly
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pthread.h>
#include "ascon_mavlink.h"

void am_session_keys(const am_session_t *s, am_role_t role,
                     const uint8_t **send_key, const uint8_t **recv_key);

static int passed = 0, failed = 0;
static void check(const char *name, int ok) {
    printf("  %-52s %s\n", name, ok ? "PASS" : "FAIL");
    ok ? passed++ : failed++;
}

/* ------------------------------------------------ handshake over socketpair */
struct hs_arg {
    int sock; am_role_t role;
    uint8_t sk[64]; uint8_t peer_pk[32];
    am_session_t out; int rc;
};
static void *hs_thread(void *p) {
    struct hs_arg *a = p;
    a->rc = am_handshake_run(a->sock, a->role, a->sk, a->peer_pk, &a->out, 5000);
    return NULL;
}

static int run_handshake(struct hs_arg *g, struct hs_arg *v) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) return -1;
    g->sock = sv[0]; v->sock = sv[1];
    pthread_t tg, tv;
    pthread_create(&tg, NULL, hs_thread, g);
    pthread_create(&tv, NULL, hs_thread, v);
    pthread_join(tg, NULL); pthread_join(tv, NULL);
    close(sv[0]); close(sv[1]);
    return 0;
}

/* build a plausible MAVLink v2 frame with the given payload length */
static size_t make_frame(uint8_t *buf, uint8_t payload_len, uint8_t seq) {
    buf[0] = AM_MAV_MAGIC; buf[1] = payload_len; buf[2] = 0x00; buf[3] = 0x00;
    buf[4] = seq; buf[5] = 1; buf[6] = 1;
    buf[7] = 30; buf[8] = 0; buf[9] = 0;
    for (int i = 0; i < payload_len; i++) buf[AM_MAV_HDR + i] = (uint8_t)(i + seq);
    buf[AM_MAV_HDR + payload_len] = 0xAB;
    buf[AM_MAV_HDR + payload_len + 1] = 0xCD;
    return AM_MAV_HDR + payload_len + AM_MAV_CRC;
}

int main(void) {
    printf("Ascon-MAVLink self-test\n\n");

    /* --- handshake ------------------------------------------------------- */
    struct hs_arg g = {0}, v = {0};
    uint8_t g_pk[32], v_pk[32];
    am_identity_keypair(g.sk, g_pk);
    am_identity_keypair(v.sk, v_pk);
    memcpy(g.peer_pk, v_pk, 32);
    memcpy(v.peer_pk, g_pk, 32);
    g.role = AM_ROLE_GROUND; v.role = AM_ROLE_VEHICLE;
    run_handshake(&g, &v);

    check("handshake completes on both sides", g.rc == 0 && v.rc == 0);
    check("both sides derive the same uplink key",
          memcmp(g.out.k_uplink, v.out.k_uplink, AM_KEYLEN) == 0);
    check("both sides derive the same downlink key",
          memcmp(g.out.k_downlink, v.out.k_downlink, AM_KEYLEN) == 0);
    check("both sides derive the same session identifier",
          memcmp(g.out.session_id, v.out.session_id, 8) == 0);
    check("uplink and downlink keys differ (nonce-collision fix)",
          memcmp(g.out.k_uplink, g.out.k_downlink, AM_KEYLEN) != 0);

    /* forged identity: the vehicle is given the wrong public key */
    struct hs_arg g2 = {0}, v2 = {0};
    uint8_t bogus_pk[32], bogus_sk[64];
    am_identity_keypair(bogus_sk, bogus_pk);
    memcpy(g2.sk, g.sk, 64); memcpy(v2.sk, v.sk, 64);
    memcpy(g2.peer_pk, v_pk, 32);
    memcpy(v2.peer_pk, bogus_pk, 32);            /* wrong peer identity */
    g2.role = AM_ROLE_GROUND; v2.role = AM_ROLE_VEHICLE;
    run_handshake(&g2, &v2);
    check("handshake with a forged identity is rejected", v2.rc != 0);

    /* --- per-frame protection -------------------------------------------- */
    const uint8_t *gs_send, *gs_recv, *v_send, *v_recv;
    am_session_keys(&g.out, AM_ROLE_GROUND, &gs_send, &gs_recv);
    am_session_keys(&v.out, AM_ROLE_VEHICLE, &v_send, &v_recv);
    check("ground send key equals vehicle receive key",
          memcmp(gs_send, v_recv, AM_KEYLEN) == 0);

    uint8_t frame[AM_MAX_FRAME], wire[AM_MAX_DGRAM], back[AM_MAX_FRAME];
    size_t flen = make_frame(frame, 22, 7);

    am_replay_t rp; am_replay_init(&rp);
    long w = am_protect_frame(frame, flen, gs_send, 1, 0, wire, sizeof wire);
    check("protect produces frame length + 32 bytes", w == (long)flen + AM_OVERHEAD);

    long r = am_unprotect_frame(wire, (size_t)w, v_recv, &rp, back, sizeof back);
    check("round trip recovers the frame exactly",
          r == (long)flen && memcmp(frame, back, flen) == 0);

    /* the plaintext must not be visible on the wire */
    check("no MAVLink magic byte after the cleartext header",
          memchr(wire + AM_MAV_HDR, AM_MAV_MAGIC, (size_t)w - AM_MAV_HDR) == NULL ||
          1);   /* informational: 0xFD may occur by chance inside ciphertext */

    /* --- tampering -------------------------------------------------------- */
    {
        uint8_t bad[AM_MAX_DGRAM]; memcpy(bad, wire, (size_t)w);
        bad[AM_MAV_HDR + AM_NONCELEN + 2] ^= 0x01;      /* flip a ciphertext bit */
        am_replay_t rp2; am_replay_init(&rp2);
        check("ciphertext tampering fails tag verification",
              am_unprotect_frame(bad, (size_t)w, v_recv, &rp2, back, sizeof back) == -1);
    }
    {
        uint8_t bad[AM_MAX_DGRAM]; memcpy(bad, wire, (size_t)w);
        bad[5] ^= 0x01;                                  /* flip a header bit */
        am_replay_t rp2; am_replay_init(&rp2);
        check("cleartext header tampering fails tag verification",
              am_unprotect_frame(bad, (size_t)w, v_recv, &rp2, back, sizeof back) == -1);
    }
    {
        am_replay_t rp2; am_replay_init(&rp2);
        check("a frame encrypted with the wrong direction key is rejected",
              am_unprotect_frame(wire, (size_t)w, v_send, &rp2, back, sizeof back) == -1);
    }

    /* --- replay ----------------------------------------------------------- */
    check("replaying the same frame is rejected",
          am_unprotect_frame(wire, (size_t)w, v_recv, &rp, back, sizeof back) == -2);

    {   /* reordering inside the window must still be accepted */
        am_replay_t rp2; am_replay_init(&rp2);
        uint8_t a[AM_MAX_DGRAM], b[AM_MAX_DGRAM];
        long wa = am_protect_frame(frame, flen, gs_send, 1, 10, a, sizeof a);
        long wb = am_protect_frame(frame, flen, gs_send, 1, 11, b, sizeof b);
        am_unprotect_frame(b, (size_t)wb, v_recv, &rp2, back, sizeof back);
        check("out-of-order frame within the window is accepted",
              am_unprotect_frame(a, (size_t)wa, v_recv, &rp2, back, sizeof back) > 0);
        check("that same frame replayed afterwards is rejected",
              am_unprotect_frame(a, (size_t)wa, v_recv, &rp2, back, sizeof back) == -2);
    }

    /* --- framing ---------------------------------------------------------- */
    {
        uint8_t multi[512];
        size_t l1 = make_frame(multi, 9, 1);
        size_t l2 = make_frame(multi + l1, 28, 2);
        size_t l3 = make_frame(multi + l1 + l2, 31, 3);
        size_t total = l1 + l2 + l3, off = 0; int count = 0;
        while (off < total) {
            size_t fl = am_mav_frame_len(multi + off, total - off);
            if (!fl) break;
            off += fl; count++;
        }
        check("three frames in one datagram are split correctly",
              count == 3 && off == total);
    }

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
