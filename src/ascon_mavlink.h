/*
 * ascon_mavlink.h -- shared definitions for the Ascon-MAVLink security proxy.
 *
 * Wire format of a protected datagram:
 *
 *   +----------------+---------------------------+--------------+
 *   |  nonce 16 B    |  ciphertext (payload+CRC) |  tag 16 B    |
 *   +----------------+---------------------------+--------------+
 *
 *   nonce = device_id (8 B, little endian) || counter (8 B, little endian)
 *
 * The 10-byte MAVLink v2 header travels in cleartext and is bound into the tag
 * as associated data, so routing remains possible while tampering is detected.
 */
#ifndef ASCON_MAVLINK_H
#define ASCON_MAVLINK_H

#include <stdint.h>
#include <stddef.h>

#define AM_KEYLEN      16      /* Ascon-128 key                              */
#define AM_NONCELEN    16      /* Ascon-128 nonce                            */
#define AM_TAGLEN      16      /* Ascon-128 tag                              */
#define AM_MAV_HDR     10      /* MAVLink v2 header, authenticated as AD     */
#define AM_MAV_CRC      2
#define AM_MAV_SIG     13      /* optional signature block                   */
#define AM_MAV_MAGIC   0xFD
#define AM_MAX_FRAME   (AM_MAV_HDR + 255 + AM_MAV_CRC + AM_MAV_SIG)
#define AM_MAX_DGRAM   2048
#define AM_OVERHEAD    (AM_NONCELEN + AM_TAGLEN)   /* 32 bytes per frame     */

/* Anti-replay: high-water mark plus a bitmap of recently accepted counters,
   so reordering and duplication on a lossy radio link are tolerated while
   every replayed frame is still rejected (the IPsec ESP construction). */
#define AM_REPLAY_WINDOW 64

typedef struct {
    uint64_t highest;                  /* highest counter accepted so far   */
    uint64_t bitmap;                   /* seen flags for the preceding 64   */
    int      primed;                   /* zero until the first valid frame  */
} am_replay_t;

/* Session material produced by the handshake. Two directional keys mean the
   endpoints never share a (key, nonce) pair, and a verifying tag identifies
   the sender rather than merely proving possession of a shared secret. */
typedef struct {
    uint8_t  k_uplink[AM_KEYLEN];      /* ground station -> vehicle          */
    uint8_t  k_downlink[AM_KEYLEN];    /* vehicle -> ground station          */
    uint8_t  session_id[8];
} am_session_t;

typedef enum { AM_ROLE_GROUND = 0, AM_ROLE_VEHICLE = 1 } am_role_t;

/* --- replay window ------------------------------------------------------- */
void am_replay_init(am_replay_t *r);
int  am_replay_check_and_update(am_replay_t *r, uint64_t counter);

/* --- frame protection ----------------------------------------------------
 * Wire layout: header(10) || nonce(16) || ciphertext || tag(16)
 * The header is cleartext but authenticated as associated data.
 */
long am_protect_frame(const uint8_t *frame, size_t frame_len,
                      const uint8_t *key, uint64_t device_id, uint64_t counter,
                      uint8_t *out, size_t out_cap);

/* Returns the frame length, -1 if the tag fails, -2 if the frame is a replay. */
long am_unprotect_frame(const uint8_t *dgram, size_t dgram_len,
                        const uint8_t *key, am_replay_t *replay,
                        uint8_t *out, size_t out_cap);

/* --- MAVLink v2 framing -------------------------------------------------- */
/* Length of the MAVLink v2 frame beginning at buf, or 0 if incomplete. */
size_t am_mav_frame_len(const uint8_t *buf, size_t avail);

/* --- handshake ----------------------------------------------------------- */
int am_handshake_run(int sock, am_role_t role,
                     const uint8_t identity_sk[64],
                     const uint8_t peer_identity_pk[32],
                     am_session_t *out, int timeout_ms);

int am_identity_keypair(uint8_t sk[64], uint8_t pk[32]);

#endif /* ASCON_MAVLINK_H */
