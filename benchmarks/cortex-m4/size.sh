#!/usr/bin/env bash
# size.sh -- flash footprint (.text) of each AEAD core on Cortex-M4, -Os.
# Run after run_m4.sh has fetched ascon-c and mbedtls. Output: results_size_m4.txt
set -e
CF="-mcpu=cortex-m4 -mthumb -Os -DNDEBUG -ffunction-sections -c"
{
for V in opt32_lowsize armv7m_lowsize; do
  A=ascon-c/crypto_aead/asconaead128/$V; rm -rf sz_$V; mkdir -p sz_$V
  for c in $(ls $A/*.c | grep -v printstate) $(ls $A/*.S 2>/dev/null); do
    arm-none-eabi-gcc $CF -I$A -Iascon-c/tests "$c" -o sz_$V/$(basename "$c").o
  done
  echo "== Ascon-AEAD128 $V"; arm-none-eabi-size -t sz_$V/*.o | tail -1
done
rm -rf sz_mb; mkdir -p sz_mb
for f in chacha20 poly1305 chachapoly aes gcm; do
  arm-none-eabi-gcc $CF -DMBEDTLS_CONFIG_FILE='"mbedtls_cfg.h"' -I. -Imbedtls/include -Imbedtls/library mbedtls/library/$f.c -o sz_mb/$f.o
done
echo "== ChaCha20-Poly1305"; arm-none-eabi-size -t sz_mb/chacha20.o sz_mb/poly1305.o sz_mb/chachapoly.o | tail -1
echo "== AES-128-GCM";       arm-none-eabi-size -t sz_mb/aes.o sz_mb/gcm.o | tail -1
} | tee results_size_m4.txt
