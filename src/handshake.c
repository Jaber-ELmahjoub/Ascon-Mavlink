#define _POSIX_C_SOURCE 200809L
/*
 * handshake.c -- authenticated per-mission session-key establishment.
 *
 * Two messages, each carrying a fresh random value, an ephemeral X25519
 * public key, and an Ed25519 signature over the transcript so far:
 *
 *   ground  -> vehicle : nonce_G (16) || eph_pk_G (32) || sig_G (64)
 *   vehicle -> ground  : nonce_V (16) || eph_pk_V (32) || sig_V (64)
 *
 * Both sides then compute the X25519 shared secret and derive 40 bytes with
 * Ascon-XOF128 over (shared secret || full transcript):
 *
 *   bytes  0..15  uplink key    (ground station -> vehicle)
 *   bytes 16..31  downlink key  (vehicle -> ground station)
 *   bytes 32..39  session identifier
 *
 * Separate directional keys mean the two endpoints never operate under the
 * same key, so their independently restarting counters cannot collide, and a
 * verifying tag identifies the sender rather than merely proving possession
 * of a shared secret. The ephemeral private key and the raw shared secret are
 * wiped immediately after derivation, giving forward secrecy.
 */
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>
#include <time.h>

#include "ascon_mavlink.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

int crypto_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen);          /* Ascon-XOF128 */

#define HS_NONCE   16
#define HS_PK      32
#define HS_SIG     64
#define HS_MSGLEN  (HS_NONCE + HS_PK + HS_SIG)

static int random_bytes(uint8_t *buf, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

int am_identity_keypair(uint8_t sk[64], uint8_t pk[32]) {
    uint8_t seed[32];
    if (random_bytes(seed, sizeof seed) != 0) return -1;
    crypto_ed25519_key_pair(sk, pk, seed);   /* wipes seed */
    return 0;
}

static int send_all(int sock, const uint8_t *buf, size_t n) {
    /* A connected UDP socket reports ECONNREFUSED once if the peer was not yet
       listening; the caller retransmits, so a single failure is not fatal. */
    return send(sock, buf, n, 0) == (ssize_t)n ? 0 : -1;
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Waits up to timeout_ms for a datagram of exactly n bytes. A connected UDP
   socket raises POLLERR when the peer is not yet bound (ICMP unreachable);
   the pending error is consumed and the wait continues, since the peer is
   simply not up yet. Timing is measured against the monotonic clock so that
   an immediately-returning poll cannot exhaust the budget by spinning. */
static int recv_timeout(int sock, uint8_t *buf, size_t n, int timeout_ms) {
    long deadline = now_ms() + timeout_ms;
    for (;;) {
        long remaining = deadline - now_ms();
        if (remaining <= 0) return -1;
        struct pollfd p = { .fd = sock, .events = POLLIN };
        int r = poll(&p, 1, (int)remaining);
        if (r <= 0) return -1;
        ssize_t got = recv(sock, buf, n, 0);
        if (got == (ssize_t)n) return 0;
        if (got < 0 && (errno == ECONNREFUSED || errno == EAGAIN ||
                        errno == EINTR)) {
            struct timespec pause = { 0, 20 * 1000 * 1000 };
            nanosleep(&pause, NULL);        /* peer not up yet: back off */
            continue;
        }
        return -1;
    }
}

/* The handshake runs over UDP before either endpoint is known to be up, so the
   first message is retransmitted until the peer answers or the budget expires.
   Retransmission is safe: the message is idempotent and carries the sender's
   freshness value, which the peer binds into the transcript. */
#define HS_RETRY_MS 250
static int send_until_reply(int sock, const uint8_t *msg, size_t mlen,
                            uint8_t *reply, size_t rlen, int timeout_ms) {
    long deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        send_all(sock, msg, mlen);
        if (recv_timeout(sock, reply, rlen, HS_RETRY_MS) == 0) return 0;
    }
    return -1;
}

static int wait_for_first(int sock, uint8_t *buf, size_t n, int timeout_ms) {
    long deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        if (recv_timeout(sock, buf, n, HS_RETRY_MS) == 0) return 0;
    }
    return -1;
}

int am_handshake_run(int sock, am_role_t role,
                     const uint8_t identity_sk[64],
                     const uint8_t peer_identity_pk[32],
                     am_session_t *out, int timeout_ms)
{
    uint8_t eph_sk[32], eph_pk[32], my_nonce[HS_NONCE];
    uint8_t mine[HS_MSGLEN], theirs[HS_MSGLEN];
    uint8_t transcript[2 * (HS_NONCE + HS_PK)];
    uint8_t shared[32], material[40];
    int rc = -1;

    if (random_bytes(eph_sk, sizeof eph_sk) != 0) return -1;
    if (random_bytes(my_nonce, sizeof my_nonce) != 0) return -1;
    crypto_x25519_public_key(eph_pk, eph_sk);

    memcpy(mine, my_nonce, HS_NONCE);
    memcpy(mine + HS_NONCE, eph_pk, HS_PK);

    /* The ground station speaks first; the vehicle answers. Both sign the
       transcript in the same canonical order (ground fields, then vehicle),
       so each side verifies exactly the bytes the other signed. */
    if (role == AM_ROLE_GROUND) {
        crypto_ed25519_sign(mine + HS_NONCE + HS_PK, identity_sk,
                            mine, HS_NONCE + HS_PK);
        if (send_until_reply(sock, mine, HS_MSGLEN, theirs, HS_MSGLEN,
                             timeout_ms) != 0) goto done;
        memcpy(transcript, mine, HS_NONCE + HS_PK);
        memcpy(transcript + HS_NONCE + HS_PK, theirs, HS_NONCE + HS_PK);
        if (crypto_ed25519_check(theirs + HS_NONCE + HS_PK, peer_identity_pk,
                                 transcript, sizeof transcript) != 0)
            goto done;                                   /* forged or tampered */
    } else {
        if (wait_for_first(sock, theirs, HS_MSGLEN, timeout_ms) != 0) goto done;
        if (crypto_ed25519_check(theirs + HS_NONCE + HS_PK, peer_identity_pk,
                                 theirs, HS_NONCE + HS_PK) != 0)
            goto done;
        memcpy(transcript, theirs, HS_NONCE + HS_PK);
        memcpy(transcript + HS_NONCE + HS_PK, mine, HS_NONCE + HS_PK);
        crypto_ed25519_sign(mine + HS_NONCE + HS_PK, identity_sk,
                            transcript, sizeof transcript);
        /* The responder answers repeatedly for a short while, because its reply
           may be lost while the initiator is still retransmitting. */
        for (int i = 0; i < 4; i++) { send_all(sock, mine, HS_MSGLEN); usleep(50000); }
    }

    crypto_x25519(shared, eph_sk, theirs + HS_NONCE);

    /* derive 40 bytes: uplink key || downlink key || session identifier */
    {
        uint8_t input[32 + sizeof transcript];
        uint8_t xof[64];
        memcpy(input, shared, 32);
        memcpy(input + 32, transcript, sizeof transcript);
        crypto_hash(xof, input, sizeof input);
        memcpy(material, xof, sizeof material);
        crypto_wipe(input, sizeof input);
        crypto_wipe(xof, sizeof xof);
    }

    memcpy(out->k_uplink,   material,      AM_KEYLEN);
    memcpy(out->k_downlink, material + 16, AM_KEYLEN);
    memcpy(out->session_id, material + 32, 8);
    rc = 0;

done:
    /* forward secrecy: neither the ephemeral key nor the raw secret survives */
    crypto_wipe(eph_sk, sizeof eph_sk);
    crypto_wipe(shared, sizeof shared);
    crypto_wipe(material, sizeof material);
    return rc;
}

/* Selects the pair of keys this endpoint uses: encrypt with its own direction,
   verify with the peer's. Getting this backwards fails closed. */
void am_session_keys(const am_session_t *s, am_role_t role,
                     const uint8_t **send_key, const uint8_t **recv_key) {
    if (role == AM_ROLE_GROUND) {
        *send_key = s->k_uplink;
        *recv_key = s->k_downlink;
    } else {
        *send_key = s->k_downlink;
        *recv_key = s->k_uplink;
    }
}
