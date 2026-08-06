/*
 * keygen.c -- generate a long-term Ed25519 identity key pair.
 *
 * Run once per endpoint, at pairing time:
 *     ./ascon-keygen ground     -> ground.key (secret), ground.pub (public)
 *
 * Exchange only the .pub files over a trusted local channel. The .key file
 * never leaves the machine.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "ascon_mavlink.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 2;
    }
    uint8_t sk[64], pk[32];
    if (am_identity_keypair(sk, pk) != 0) {
        fprintf(stderr, "cannot read system randomness\n");
        return 1;
    }
    char path[256];
    snprintf(path, sizeof path, "%s.key", argv[1]);
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }
    fwrite(sk, 1, sizeof sk, f);
    fclose(f);
    chmod(path, 0600);

    snprintf(path, sizeof path, "%s.pub", argv[1]);
    f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }
    fwrite(pk, 1, sizeof pk, f);
    fclose(f);

    printf("wrote %s.key (secret, keep on this machine) and %s.pub (share)\n",
           argv[1], argv[1]);
    return 0;
}
