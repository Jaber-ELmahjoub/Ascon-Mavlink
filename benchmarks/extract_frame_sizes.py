#!/usr/bin/env python3
"""
extract_frame_sizes.py -- derive the real MAVLink v2 payload-size distribution
from your own baseline capture, so the benchmark runs on the frame geometry you
actually measured (the 11,925-frame campaign) rather than on nominal sizes.

    python3 extract_frame_sizes.py baseline.pcap > sizes.txt
    ./run_all.sh sizes.txt

Reads classic pcap and pcapng, walks UDP payloads, and delimits MAVLink v2
frames on the 0xFD magic byte exactly as decode_pcap.py does.
Prints the distinct payload lengths (most frequent first, max 64 values) plus a
histogram on stderr for the paper's methodology paragraph.
"""
import struct
import sys
from collections import Counter

MAGIC_V2 = 0xFD
HDR_LEN = 10          # magic..msgid
CRC_LEN = 2
SIG_LEN = 13          # only when INCOMPAT_FLAGS bit0 set


def iter_packets(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, 0xD4C3B2A1):                 # classic pcap
        endian = "<" if magic == 0xA1B2C3D4 else ">"
        off, n = 24, len(data)
        while off + 16 <= n:
            _, _, caplen, _ = struct.unpack(endian + "IIII", data[off:off + 16])
            off += 16
            yield data[off:off + caplen]
            off += caplen
    elif magic == 0x0A0D0D0A:                              # pcapng
        off, n = 0, len(data)
        while off + 12 <= n:
            btype, blen = struct.unpack("<II", data[off:off + 8])
            if blen < 12 or off + blen > n:
                break
            if btype == 0x00000006:                        # Enhanced Packet Block
                caplen = struct.unpack("<I", data[off + 20:off + 24])[0]
                yield data[off + 28:off + 28 + caplen]
            off += blen
    else:
        sys.exit("unrecognised capture format")


def udp_payload(frame):
    """Ethernet or Linux cooked or raw loopback -> UDP payload, or None."""
    for l2 in (14, 16, 4, 0):                              # try common link layers
        if len(frame) < l2 + 20:
            continue
        ip = frame[l2:]
        if (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:               # protocol 17 = UDP
            continue
        udp = ip[ihl:]
        ulen = struct.unpack("!H", udp[4:6])[0]
        return udp[8:ulen] if 8 <= ulen <= len(udp) else udp[8:]
    return None


def mavlink_payload_lengths(buf):
    """Yield PAYLOAD_LEN for every MAVLink v2 frame in a UDP datagram."""
    i, n = 0, len(buf)
    while i < n:
        if buf[i] != MAGIC_V2:
            i += 1
            continue
        if i + HDR_LEN > n:
            break
        plen = buf[i + 1]
        incompat = buf[i + 2]
        total = HDR_LEN + plen + CRC_LEN + (SIG_LEN if incompat & 0x01 else 0)
        if i + total > n:
            break
        yield plen
        i += total


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    hist = Counter()
    for frame in iter_packets(sys.argv[1]):
        payload = udp_payload(frame)
        if payload:
            hist.update(mavlink_payload_lengths(payload))

    total = sum(hist.values())
    if not total:
        sys.exit("no MAVLink v2 frames found")

    mean = sum(k * v for k, v in hist.items()) / total
    print(f"# {total} MAVLink v2 frames, mean payload {mean:.1f} B", file=sys.stderr)
    for length, count in hist.most_common():
        print(f"#   {length:4d} B : {count:6d} ({100 * count / total:5.2f} %)",
              file=sys.stderr)

    # benchmark input: the payload lengths that actually occur, commonest first
    for length, _ in hist.most_common(64):
        print(length)


if __name__ == "__main__":
    main()
