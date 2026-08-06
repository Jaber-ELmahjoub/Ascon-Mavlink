#!/usr/bin/env bash
# run_all.sh -- reproduces every number of the new Table II on your own machine.
#
#   ./run_all.sh            # default MAVLink payload sizes
#   ./run_all.sh sizes.txt  # payload sizes extracted from your own capture
#
# Produces:  results_host.csv   (Panel A: throughput / latency)
#            results_arm.txt    (Panel B: Cortex-M4 flash and RAM footprint)
set -e
ITERS=${ITERS:-300000}
REPEATS=${REPEATS:-5}
SIZEFILE=${1:-}

echo "== 0. dependencies =="
sudo apt-get install -y build-essential git libssl-dev gcc-arm-none-eabi binutils-arm-none-eabi

echo "== 1. sources =="
[ -d ascon-c ] || git clone --depth 1 https://github.com/ascon/ascon-c.git
[ -d mbedtls ] || git clone --depth 1 -b v3.6.2 https://github.com/Mbed-TLS/mbedtls.git

ASCON64=ascon-c/crypto_aead/asconaead128/opt64
MB=mbedtls/library
MBSRC=""
for f in aes gcm chacha20 poly1305 chachapoly platform_util cipher cipher_wrap constant_time; do
  MBSRC="$MBSRC $MB/$f.c"
done

echo "== 2. host benchmark (portable C, no ISA crypto extensions) =="
gcc -O2 -DNDEBUG -DASCON_INLINE_MODE=1 -DMBEDTLS_CONFIG_FILE='"mbedtls_cfg.h"' \
    -I. -Imbedtls/include -I$MB -I$ASCON64 -Iascon-c/tests \
    bench_sw.c $ASCON64/aead.c $MBSRC -o bench_sw

: > results_host.csv
for r in $(seq 1 "$REPEATS"); do
  if [ -n "$SIZEFILE" ]; then ./bench_sw "$ITERS" "$SIZEFILE"; else ./bench_sw "$ITERS"; fi \
    | { [ "$r" = 1 ] && cat || tail -n +2; } >> results_host.csv
done
echo "   -> results_host.csv   ($REPEATS repetitions; take the median per row)"

echo "== 3. reference point: what hardware AES acceleration buys (OpenSSL) =="
gcc -O3 -march=native -DNDEBUG -DASCON_INLINE_MODE=1 -I$ASCON64 -Iascon-c/tests \
    bench_hw.c $ASCON64/aead.c -lcrypto -o bench_hw
./bench_hw "$ITERS" > results_host_openssl.csv 2> results_keysetup.txt
echo "   -> results_host_openssl.csv, results_keysetup.txt"

echo "== 4. Cortex-M4 static footprint (cross-compile, no board needed) =="
CF="-mcpu=cortex-m4 -mthumb -Os -DNDEBUG -ffunction-sections -fdata-sections -c"
rm -rf armobj && mkdir -p armobj

# --- Ascon-AEAD128, portable 32-bit low-size build ---
A32=ascon-c/crypto_aead/asconaead128/opt32_lowsize
for c in $A32/*.c; do
  b=$(basename "$c" .c); [ "$b" = printstate ] && continue
  arm-none-eabi-gcc $CF -I$A32 -Iascon-c/tests "$c" -o "armobj/ascon_$b.o"
done
# --- Ascon-AEAD128, hand-optimised ARMv7-M build (best case on M4) ---
A7M=ascon-c/crypto_aead/asconaead128/armv7m_lowsize
for c in $A7M/*.c; do
  b=$(basename "$c" .c); [ "$b" = printstate ] && continue
  arm-none-eabi-gcc $CF -I$A7M -Iascon-c/tests "$c" -o "armobj/asconv7m_$b.o"
done
# --- Mbed TLS AEADs ---
for f in aes gcm chacha20 poly1305 chachapoly cipher cipher_wrap constant_time platform_util; do
  arm-none-eabi-gcc $CF -DMBEDTLS_CONFIG_FILE='"mbedtls_cfg.h"' \
      -I. -Imbedtls/include -I$MB "$MB/$f.c" -o "armobj/$f.o"
done

# --- context sizes as seen by the target compiler ---
cat > armobj/ctxsize.c <<'EOF'
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"
#include "api.h"
#include "ascon.h"
char ascon_state[sizeof(ascon_state_t)];
char chachapoly_ctx[sizeof(mbedtls_chachapoly_context)];
char aes_gcm_ctx[sizeof(mbedtls_gcm_context)];
EOF
arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -Os -c \
    -DMBEDTLS_CONFIG_FILE='"mbedtls_cfg.h"' -I. -Imbedtls/include -I$MB -I$A32 \
    armobj/ctxsize.c -o armobj/ctxsize.o

{
  echo "### Cortex-M4 flash footprint, AEAD core only (-Os, arm-none-eabi-gcc)"
  echo "-- Ascon-AEAD128 (opt32_lowsize, portable C)"
  arm-none-eabi-size -t armobj/ascon_*.o | tail -1
  echo "-- Ascon-AEAD128 (armv7m_lowsize, ARM assembly permutation)"
  arm-none-eabi-size -t armobj/asconv7m_*.o | tail -1
  echo "-- ChaCha20-Poly1305 (chacha20 + poly1305 + chachapoly)"
  arm-none-eabi-size -t armobj/chacha20.o armobj/poly1305.o armobj/chachapoly.o | tail -1
  echo "-- AES-128-GCM (aes + gcm)"
  arm-none-eabi-size -t armobj/aes.o armobj/gcm.o | tail -1
  echo "-- AES-128-GCM additional Mbed TLS cipher abstraction layer"
  arm-none-eabi-size -t armobj/cipher.o armobj/cipher_wrap.o armobj/constant_time.o armobj/platform_util.o | tail -1
  echo
  echo "### Working RAM per session context (bytes, target ABI)"
  arm-none-eabi-nm -S --size-sort armobj/ctxsize.o
  echo
  echo "### Per-object detail"
  arm-none-eabi-size armobj/*.o
} | tee results_arm.txt

echo
echo "Done. Panel A -> results_host.csv ; Panel B -> results_arm.txt"
