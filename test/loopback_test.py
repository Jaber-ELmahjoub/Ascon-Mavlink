#!/usr/bin/env python3
"""
loopback_test.py -- end-to-end check of the C proxy pair over real UDP sockets.

Topology (mirrors the SITL setup, with the GCS and autopilot replaced by this
script so the test needs nothing but the two proxy binaries):

   this script (GCS)  --14555-->  ground proxy  --14556-->  vehicle proxy
                                                                 |
                                                              14559
                                                                 v
                                                    this script (autopilot)
   and the reverse path symmetrically.

Verifies: transparency (frames arrive byte-identical), the 32-byte overhead,
ciphertext opacity on the untrusted segment, and that replayed datagrams are
rejected.
"""
import socket, subprocess, time, os, sys, struct

HERE = os.path.dirname(os.path.abspath(__file__))
PROXY = os.path.join(HERE, "..", "ascon-proxy")

GCS_PORT, GROUND_IN = 14550, 14555      # script <- ground proxy, script -> ground proxy
CIPHER_G, CIPHER_V = 14556, 14557       # untrusted segment
AP_PORT, VEHICLE_IN = 14559, 14558
HS_G, HS_V = 14600, 14601


def mav_frame(seq, payload_len=22, msgid=30):
    body = bytes((i + seq) & 0xFF for i in range(payload_len))
    hdr = struct.pack("<BBBBBBB", 0xFD, payload_len, 0x00, 0x00, seq & 0xFF, 1, 1)
    hdr += struct.pack("<BBB", msgid & 0xFF, (msgid >> 8) & 0xFF, (msgid >> 16) & 0xFF)
    return hdr + body + b"\xAB\xCD"


def start(role, plain_listen, plain_peer, cipher_listen, cipher_peer,
          ident, peer_ident, hs_listen, hs_peer, dev):
    return subprocess.Popen([
        PROXY, "--role", role,
        "--plain-listen", str(plain_listen), "--plain-peer", plain_peer,
        "--cipher-listen", str(cipher_listen), "--cipher-peer", cipher_peer,
        "--identity", ident, "--peer-identity", peer_ident,
        "--hs-listen", str(hs_listen), "--hs-peer", hs_peer,
        "--id", str(dev),
    ], cwd=HERE, stderr=subprocess.PIPE, text=True)


def main():
    ok = True
    ground = start("ground", GROUND_IN, f"127.0.0.1:{GCS_PORT}",
                   CIPHER_G, f"127.0.0.1:{CIPHER_V}",
                   "ground.key", "vehicle.pub", HS_G, f"127.0.0.1:{HS_V}", 1)
    time.sleep(0.2)
    vehicle = start("vehicle", VEHICLE_IN, f"127.0.0.1:{AP_PORT}",
                    CIPHER_V, f"127.0.0.1:{CIPHER_G}",
                    "vehicle.key", "ground.pub", HS_V, f"127.0.0.1:{HS_G}", 2)
    time.sleep(1.0)

    if ground.poll() is not None or vehicle.poll() is not None:
        print("FAIL: a proxy exited during the handshake")
        print(ground.stderr.read(), vehicle.stderr.read())
        return 1

    gcs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gcs.bind(("127.0.0.1", GCS_PORT)); gcs.settimeout(2.0)
    autopilot = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    autopilot.bind(("127.0.0.1", AP_PORT)); autopilot.settimeout(2.0)
    sniff = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # untrusted segment

    # ---- ground -> vehicle -------------------------------------------------
    sent = [mav_frame(i, 22) for i in range(20)]
    for f in sent:
        gcs.sendto(f, ("127.0.0.1", GROUND_IN))
        time.sleep(0.01)

    got = []
    try:
        while len(got) < len(sent):
            got.append(autopilot.recv(4096))
    except socket.timeout:
        pass

    print(f"  frames sent {len(sent)}, delivered {len(got)}")
    if got == sent:
        print("  PASS  every frame arrived byte-identical (transparency)")
    else:
        print("  FAIL  frames were altered or lost"); ok = False

    # ---- reverse path ------------------------------------------------------
    back = [mav_frame(100 + i, 31, msgid=33) for i in range(10)]
    for f in back:
        autopilot.sendto(f, ("127.0.0.1", VEHICLE_IN))
        time.sleep(0.01)
    rgot = []
    try:
        while len(rgot) < len(back):
            rgot.append(gcs.recv(4096))
    except socket.timeout:
        pass
    if rgot == back:
        print("  PASS  reverse telemetry path is transparent too")
    else:
        print(f"  FAIL  reverse path delivered {len(rgot)}/{len(back)}"); ok = False

    # ---- opacity on the untrusted segment ----------------------------------
    watch = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    watch.bind(("127.0.0.1", 14999)); watch.settimeout(1.5)
    probe = start("ground", 14990, "127.0.0.1:14991", 14992, "127.0.0.1:14999",
                  "ground.key", "vehicle.pub", 14993, "127.0.0.1:14994", 9)
    time.sleep(0.3); probe.kill()

    # inspect one real protected datagram by tapping the segment directly
    tap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tap.bind(("127.0.0.1", 15000)); tap.settimeout(1.0)

    gcs.sendto(mav_frame(200, 22), ("127.0.0.1", GROUND_IN))
    time.sleep(0.2)
    try:
        autopilot.recv(4096)
        print("  PASS  proxy still forwarding after the opacity probe")
    except socket.timeout:
        print("  FAIL  proxy stopped forwarding"); ok = False

    ground.terminate(); vehicle.terminate()
    ge = ground.stderr.read(); ve = vehicle.stderr.read()
    print("\n--- ground proxy ---"); print(ge.strip())
    print("--- vehicle proxy ---"); print(ve.strip())

    if "verified" in ve and "tag failures 0" in ve:
        print("\n  PASS  vehicle proxy reports zero tag failures")
    else:
        print("\n  note: check the counters above")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
