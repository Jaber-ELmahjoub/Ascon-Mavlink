# Ascon-MAVLink

Transparent Ascon-128 authenticated-encryption proxy for MAVLink v2, with the
complete measurement harness used to produce the results in the accompanying
paper.

> **Lightweight Authenticated Encryption for MAVLink Protocol: Design,
> Implementation, and Evaluation of an Ascon-128 Security Layer**
> J. El Mahjoub and A. Abdellaoui, *IEEE Access*, 2026.

MAVLink transmits telemetry and commands in cleartext, its optional signing
mechanism is disabled by default, and the `SETUP_SIGNING` message that
provisions the signing key transmits that key in the clear. This repository
implements a security overlay that requires no change to the autopilot or the
ground-control station: a pair of UDP proxies wrap every frame in Ascon-128
AEAD, the algorithm standardised by NIST in SP 800-232 for constrained devices.

## What is here

| Directory | Contents |
|---|---|
| `src/` | The C implementation: proxy, handshake, per-frame AEAD, key generation |
| `benchmarks/host/` | AEAD comparison on a host CPU (Table II methodology) |
| `benchmarks/cortex-m4/` | Bare-metal Cortex-M4 instruction counting (Tables II and III) |
| `figures/` | Script that regenerates Fig. 8 from measured data |
| `test/` | End-to-end loopback test over real UDP sockets |

Every number in the paper is reproduced by a script in this repository. No
figure is taken from the literature.

## Quick start

```sh
cd src
make deps          # fetches ascon-c and Monocypher
make
make test          # 17 checks, all must pass
```

Then create the long-term identity keys, once per drone/GCS pair:

```sh
./ascon-keygen ground
./ascon-keygen vehicle
```

Copy `vehicle.pub` to the ground station and `ground.pub` to the vehicle over a
trusted local channel. The `.key` files never leave the machine that made them.

## Running the proxies

Ground station:

```sh
./ascon-proxy --role ground \
  --plain-listen 14555 --plain-peer 127.0.0.1:14550 \
  --cipher-listen 14556 --cipher-peer 127.0.0.1:14557 \
  --identity ground.key --peer-identity vehicle.pub \
  --hs-listen 14600 --hs-peer 127.0.0.1:14601 --id 1
```

Vehicle:

```sh
./ascon-proxy --role vehicle \
  --plain-listen 14558 --plain-peer 127.0.0.1:14559 \
  --cipher-listen 14557 --cipher-peer 127.0.0.1:14556 \
  --identity vehicle.key --peer-identity ground.pub \
  --hs-listen 14601 --hs-peer 127.0.0.1:14600 --id 2
```

Both must print the same session identifier. Point the GCS at port 14555 and
have the autopilot emit on 14558; nothing else in the flight stack changes.

The rule for the port arguments: `--cipher-peer` of one side equals
`--cipher-listen` of the other, and likewise for `--hs-peer` and `--hs-listen`.

## Design

**Wire format.** `header(10) || nonce(16) || ciphertext || tag(16)`, a constant
32 bytes of overhead. The MAVLink header stays in cleartext so intermediate
software can route on system and component identifiers, but it is bound into
the tag as associated data, so any manipulation is detected.

**Nonce.** A 64-bit device identifier concatenated with a 64-bit per-frame
counter. Deterministic, so no randomness is needed at runtime, and the counter
doubles as the replay sequence number.

**Directional keys.** The handshake derives 40 bytes from Ascon-XOF128: an
uplink key, a downlink key, and a session identifier. Each endpoint encrypts
under its own direction key and verifies under the peer's. This guarantees the
two endpoints never share a (key, nonce) pair even though both counters restart
at zero, and it makes a verifying tag identify the sender rather than merely
proving possession of a shared secret.

**Anti-replay.** High-water mark plus a 64-entry bitmap, as in IPsec ESP. Strict
monotonicity would discard legitimate frames reordered by a lossy radio link;
the window tolerates reordering while still rejecting every replay. The window
advances only *after* the tag verifies, so a forged frame carrying an inflated
counter cannot desynchronise the receiver.

**Forward secrecy.** Ephemeral X25519 private keys and the raw shared secret are
wiped immediately after key derivation. An adversary who records a flight and
later obtains the vehicle, including its long-term identity key, cannot
reconstruct the session key.

**Fail closed.** If the handshake does not complete, the proxy exits rather than
forwarding anything unprotected.

## Reproducing the measurements

Cortex-M4 instruction counts and footprint (Tables II and III):

```sh
cd benchmarks/cortex-m4
./run_m4.sh armv7m_lowsize
```

Runs the three AEAD constructions as bare-metal Cortex-M4 firmware under
instruction-accurate emulation. The calibration line must read exactly 40, and
repeated runs must give identical counts — the emulator is deterministic.

Host AEAD comparison:

```sh
cd benchmarks/host
./run_all.sh
```

Throughput of the C proxy core:

```sh
cd src && ./ascon-bench 500000
```

To benchmark against your own traffic rather than nominal frame sizes, extract
the payload distribution from a capture first:

```sh
python3 benchmarks/extract_frame_sizes.py baseline.pcap > sizes.txt
```

## Dependencies

Fetched by `make deps`, not vendored:

- [ascon-c](https://github.com/ascon/ascon-c) — Ascon-AEAD128 and Ascon-XOF128,
  the official reference implementation of NIST SP 800-232
- [Monocypher](https://github.com/LoupVaillant/Monocypher) — X25519 and Ed25519,
  compact and constant-time

The Cortex-M4 benchmarks additionally use Mbed TLS 3.6.2 for the
ChaCha20-Poly1305 and AES-128-GCM baselines, and `arm-none-eabi-gcc` with QEMU.

## Status

Research code accompanying a paper. It has been validated against ArduPilot SITL
and passes the self-test, but it has not been audited and has not flown on
physical hardware. Do not deploy it on an aircraft that can hurt someone without
your own review.

## License

MIT — see `LICENSE`.
