/*
 * proxy.c -- transparent bidirectional Ascon-MAVLink security proxy.
 *
 *   plaintext side  <--UDP-->  [ proxy ]  <--UDP-->  untrusted segment
 *
 * On the ground the plaintext side faces the GCS; on the vehicle it faces the
 * autopilot. The same binary serves both, distinguished by --role.
 *
 * Usage:
 *   ascon-proxy --role ground  --plain-listen 14555 --plain-peer 127.0.0.1:14550 \
 *               --cipher-peer 127.0.0.1:14556 --cipher-listen 14557 \
 *               --id 1 --identity ground.key --peer-identity vehicle.pub \
 *               --hs-peer 127.0.0.1:14600
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>

#include "ascon_mavlink.h"

void am_session_keys(const am_session_t *s, am_role_t role,
                     const uint8_t **send_key, const uint8_t **recv_key);

static volatile sig_atomic_t running = 1;
static void on_signal(int s) { (void)s; running = 0; }

static struct {
    unsigned long frames_out, frames_in, tag_fail, replayed, unframed;
} stats;

static int udp_socket(uint16_t listen_port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET,
                             .sin_port = htons(listen_port),
                             .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return -1; }
    return s;
}

static int parse_addr(const char *spec, struct sockaddr_in *out) {
    char host[64]; int port;
    const char *colon = strrchr(spec, ':');
    if (!colon || (size_t)(colon - spec) >= sizeof host) return -1;
    memcpy(host, spec, colon - spec);
    host[colon - spec] = 0;
    port = atoi(colon + 1);
    memset(out, 0, sizeof *out);
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);
    return inet_pton(AF_INET, host, &out->sin_addr) == 1 ? 0 : -1;
}

static int read_file(const char *path, uint8_t *buf, size_t n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

int main(int argc, char **argv) {
    const char *role_s = NULL, *plain_peer_s = NULL, *cipher_peer_s = NULL;
    const char *identity_s = NULL, *peer_identity_s = NULL, *hs_peer_s = NULL;
    int plain_listen = 0, cipher_listen = 0, hs_listen = 0;
    uint64_t device_id = 1;
    int verbose = 0;

    static struct option opts[] = {
        {"role",           required_argument, 0, 'r'},
        {"plain-listen",   required_argument, 0, 'l'},
        {"plain-peer",     required_argument, 0, 'p'},
        {"cipher-listen",  required_argument, 0, 'L'},
        {"cipher-peer",    required_argument, 0, 'P'},
        {"id",             required_argument, 0, 'i'},
        {"identity",       required_argument, 0, 'k'},
        {"peer-identity",  required_argument, 0, 'K'},
        {"hs-listen",      required_argument, 0, 'H'},
        {"hs-peer",        required_argument, 0, 'h'},
        {"verbose",        no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };
    int c, idx;
    while ((c = getopt_long(argc, argv, "", opts, &idx)) != -1) {
        switch (c) {
        case 'r': role_s = optarg; break;
        case 'l': plain_listen = atoi(optarg); break;
        case 'p': plain_peer_s = optarg; break;
        case 'L': cipher_listen = atoi(optarg); break;
        case 'P': cipher_peer_s = optarg; break;
        case 'i': device_id = strtoull(optarg, NULL, 10); break;
        case 'k': identity_s = optarg; break;
        case 'K': peer_identity_s = optarg; break;
        case 'H': hs_listen = atoi(optarg); break;
        case 'h': hs_peer_s = optarg; break;
        case 'v': verbose = 1; break;
        default: return 2;
        }
    }
    if (!role_s || !identity_s || !peer_identity_s || !hs_peer_s) {
        fprintf(stderr, "missing required option; see comment at top of proxy.c\n");
        return 2;
    }
    am_role_t role = strcmp(role_s, "ground") == 0 ? AM_ROLE_GROUND
                                                   : AM_ROLE_VEHICLE;

    uint8_t identity_sk[64], peer_pk[32];
    if (read_file(identity_s, identity_sk, sizeof identity_sk) != 0) {
        fprintf(stderr, "cannot read identity key %s\n", identity_s); return 1;
    }
    if (read_file(peer_identity_s, peer_pk, sizeof peer_pk) != 0) {
        fprintf(stderr, "cannot read peer identity %s\n", peer_identity_s); return 1;
    }

    /* ---------------- session establishment, once, before flight --------- */
    struct sockaddr_in hs_peer;
    if (parse_addr(hs_peer_s, &hs_peer) != 0) { fprintf(stderr, "bad --hs-peer\n"); return 2; }
    int hs = udp_socket((uint16_t)hs_listen);
    if (hs < 0) { perror("handshake socket"); return 1; }
    if (connect(hs, (struct sockaddr *)&hs_peer, sizeof hs_peer) < 0) {
        perror("handshake connect"); return 1;
    }
    am_session_t session;
    fprintf(stderr, "[%s] running handshake...\n", role_s);
    if (am_handshake_run(hs, role, identity_sk, peer_pk, &session, 10000) != 0) {
        fprintf(stderr, "[%s] HANDSHAKE FAILED (no session key, refusing to run)\n",
                role_s);
        return 1;
    }
    close(hs);
    fprintf(stderr, "[%s] session established, id %02x%02x%02x%02x...\n", role_s,
            session.session_id[0], session.session_id[1],
            session.session_id[2], session.session_id[3]);

    const uint8_t *send_key, *recv_key;
    am_session_keys(&session, role, &send_key, &recv_key);

    /* ---------------- data path ------------------------------------------ */
    struct sockaddr_in plain_peer, cipher_peer;
    memset(&plain_peer, 0, sizeof plain_peer);
    memset(&cipher_peer, 0, sizeof cipher_peer);
    if (plain_peer_s && parse_addr(plain_peer_s, &plain_peer) != 0) {
        fprintf(stderr, "bad --plain-peer\n"); return 2;
    }
    if (cipher_peer_s && parse_addr(cipher_peer_s, &cipher_peer) != 0) {
        fprintf(stderr, "bad --cipher-peer\n"); return 2;
    }
    int sp = udp_socket((uint16_t)plain_listen);
    int sc = udp_socket((uint16_t)cipher_listen);
    if (sp < 0 || sc < 0) { perror("socket"); return 1; }

    am_replay_t replay;
    am_replay_init(&replay);
    uint64_t counter = 0;

    /* MAVProxy and ArduPilot SITL send from an ephemeral source port, so the
       address to reply to is not known in advance. Both sides are learned from
       the first datagram received and refreshed thereafter, which also lets an
       endpoint move or reconnect without restarting the proxy. */
    int plain_known  = plain_peer.sin_port  != 0;
    int cipher_known = cipher_peer.sin_port != 0;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    uint8_t in[AM_MAX_DGRAM], out[AM_MAX_DGRAM];
    struct pollfd fds[2] = { { .fd = sp, .events = POLLIN },
                             { .fd = sc, .events = POLLIN } };

    while (running) {
        if (poll(fds, 2, 500) <= 0) continue;

        /* plaintext -> protected: split the datagram into MAVLink frames and
           protect each one, so several frames per datagram are handled. */
        if (fds[0].revents & POLLIN) {
            struct sockaddr_in from; socklen_t flen_ = sizeof from;
            ssize_t n = recvfrom(sp, in, sizeof in, 0,
                                 (struct sockaddr *)&from, &flen_);
            if (n > 0 && !plain_known) {
                plain_peer = from; plain_known = 1;
                fprintf(stderr, "[%s] plaintext peer learned: %s:%u\n", role_s,
                        inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            }
            for (ssize_t off = 0; off < n; ) {
                size_t flen = am_mav_frame_len(in + off, (size_t)(n - off));
                if (flen == 0) { stats.unframed++; break; }
                long w = am_protect_frame(in + off, flen, send_key,
                                          device_id, counter++, out, sizeof out);
                if (w > 0 && cipher_known) {
                    sendto(sc, out, (size_t)w, 0,
                           (struct sockaddr *)&cipher_peer, sizeof cipher_peer);
                    stats.frames_out++;
                    if (verbose)
                        fprintf(stderr, "[%s] out %zu -> %ld bytes (+%ld) ctr=%llu\n",
                                role_s, flen, w, w - (long)flen,
                                (unsigned long long)(counter - 1));
                }
                off += (ssize_t)flen;
            }
        }

        /* protected -> plaintext: verify, check replay, forward */
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from; socklen_t flen_ = sizeof from;
            ssize_t n = recvfrom(sc, in, sizeof in, 0,
                                 (struct sockaddr *)&from, &flen_);
            long w = am_unprotect_frame(in, (size_t)n, recv_key, &replay,
                                        out, sizeof out);
            if (w > 0) {
                /* only a frame that passed tag verification may update the
                   peer address, so a forged datagram cannot redirect traffic */
                if (!cipher_known) {
                    cipher_peer = from; cipher_known = 1;
                    fprintf(stderr, "[%s] protected peer learned: %s:%u\n", role_s,
                            inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                }
                if (plain_known)
                    sendto(sp, out, (size_t)w, 0,
                           (struct sockaddr *)&plain_peer, sizeof plain_peer);
                stats.frames_in++;
                if (verbose)
                    fprintf(stderr, "[%s] in  %zd -> %ld bytes\n", role_s, n, w);
            } else if (w == -2) {
                stats.replayed++;
                if (verbose) fprintf(stderr, "[%s] REPLAY rejected\n", role_s);
            } else {
                stats.tag_fail++;
                if (verbose) fprintf(stderr, "[%s] TAG FAILURE, dropped\n", role_s);
            }
        }
    }

    fprintf(stderr,
            "[%s] protected %lu, verified %lu, tag failures %lu, replays %lu, unframed %lu\n",
            role_s, stats.frames_out, stats.frames_in, stats.tag_fail,
            stats.replayed, stats.unframed);
    return 0;
}
