#!/usr/bin/env bash
# run_m4.sh -- run the AEAD comparison as real Cortex-M4 code under QEMU.
#
# QEMU does NOT implement the DWT cycle counter (it reads back zero), so cycles
# cannot be measured this way. What -icount shift=0 does give is exact,
# deterministic instruction counting: virtual time advances one nanosecond per
# executed instruction, so SysTick becomes an instruction counter. The
# calibration line printed at startup should read exactly 40.
#
#   ./run_m4.sh [ascon_variant]
# e.g.
#   ./run_m4.sh armv7m_lowsize   # ARMv7-M assembly permutation (default, paper)
#   ./run_m4.sh opt32_lowsize    # portable 32-bit C (paper)
#
# Paper conditions (Table II): arm-none-eabi-gcc 15.3.1, picolibc 1.8.12,
# ascon-c commit 446347f, Mbed TLS 3.6.2, QEMU 11.1, -O2.
set -e
IMPL=${1:-armv7m_lowsize}
ASCON_COMMIT=446347f
OPT=${OPT:--O2}

# picolibc-arm-none-eabi provides the C library (Debian/Kali); on distributions
# that still ship newlib, install libnewlib-arm-none-eabi and use nosys.specs.
sudo apt-get install -y gcc-arm-none-eabi picolibc-arm-none-eabi qemu-system-arm
[ -d ascon-c ] || { git clone https://github.com/ascon/ascon-c.git && git -C ascon-c checkout -q "$ASCON_COMMIT"; }
[ -d mbedtls ] || git clone --depth 1 -b v3.6.2 https://github.com/Mbed-TLS/mbedtls.git

A=ascon-c/crypto_aead/asconaead128/$IMPL
MB=mbedtls/library
[ -d "$A" ] || { echo "no such Ascon variant: $IMPL"; exit 1; }

ASCON_SRC=""
for c in "$A"/*.c; do
  [ "$(basename "$c")" = printstate.c ] && continue
  ASCON_SRC="$ASCON_SRC $c"
done
for s in "$A"/*.S; do [ -e "$s" ] && ASCON_SRC="$ASCON_SRC $s"; done

MB_SRC=""
for f in aes gcm chacha20 poly1305 chachapoly platform_util cipher cipher_wrap constant_time; do
  MB_SRC="$MB_SRC $MB/$f.c"
done

# IMPORTANT: compare like with like. Mbed TLS is built for speed by default, so
# build Ascon at -O2 too. Mixing -Os Ascon with -O2 Mbed TLS understates Ascon.
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb $OPT -DNDEBUG \
  -DMBEDTLS_CONFIG_FILE='"mbedtls_cfg.h"' \
  -nostartfiles --specs=picolibc.specs -T link.ld \
  -I. -Imbedtls/include -I$MB -I"$A" -Iascon-c/tests \
  startup.c bench_m4.c $ASCON_SRC $MB_SRC -o "bench_m4_$IMPL.elf" 2>&1 | grep -i " error" || true

# semihosting output goes to stderr
qemu-system-arm -M mps2-an386 -cpu cortex-m4 -nographic -icount shift=0 \
  -semihosting-config enable=on,target=native -kernel "bench_m4_$IMPL.elf" \
  2>&1 | tee "results_m4_$IMPL.txt"

echo
echo "-> results_m4_$IMPL.txt"
