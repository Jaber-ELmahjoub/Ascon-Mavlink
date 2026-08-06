# Makefile -- Ascon-MAVLink security proxy (C implementation)
#
#   make deps     fetch ascon-c and Monocypher
#   make          build ascon-proxy, ascon-keygen, ascon-selftest
#   make test     run the loopback self-test
#
# Ascon-AEAD128 and Ascon-XOF128 come from the official ascon-c reference tree;
# X25519 and Ed25519 from Monocypher, a compact constant-time implementation.

CC      ?= cc
CFLAGS  ?= -O2 -std=c11 -Wall -Wextra -Wno-unused-parameter
ASCON   := ascon-c
MONO    := Monocypher/src

AEAD    := $(ASCON)/crypto_aead/asconaead128/opt64
XOF     := $(ASCON)/crypto_hash/asconxof128/opt64

INCLUDES := -I. -I$(AEAD) -I$(XOF) -I$(MONO) -I$(MONO)/optional -I$(ASCON)/tests

# The AEAD and XOF trees both define an internal permutation; compiling them
# into separate objects with distinct prefixes is avoided by relying on the
# reference tree's own static linkage.
AEAD_SRC := $(AEAD)/aead.c
XOF_SRC  := $(XOF)/hash.c
MONO_SRC := $(MONO)/monocypher.c $(MONO)/optional/monocypher-ed25519.c

COMMON   := frame.c handshake.c

all: ascon-proxy ascon-keygen ascon-selftest

deps:
	@test -d $(ASCON) || git clone --depth 1 https://github.com/ascon/ascon-c.git
	@test -d Monocypher || git clone --depth 1 https://github.com/LoupVaillant/Monocypher.git
	@echo "dependencies ready"

ascon-proxy: proxy.c $(COMMON)
	$(CC) $(CFLAGS) $(INCLUDES) -DASCON_INLINE_MODE=1 -o $@ \
	   proxy.c $(COMMON) $(AEAD_SRC) $(XOF_SRC) $(MONO_SRC)

ascon-keygen: keygen.c $(COMMON)
	$(CC) $(CFLAGS) $(INCLUDES) -DASCON_INLINE_MODE=1 -o $@ \
	   keygen.c $(COMMON) $(AEAD_SRC) $(XOF_SRC) $(MONO_SRC)

ascon-selftest: selftest.c $(COMMON)
	$(CC) $(CFLAGS) $(INCLUDES) -DASCON_INLINE_MODE=1 -o $@ \
	   selftest.c $(COMMON) $(AEAD_SRC) $(XOF_SRC) $(MONO_SRC)

test: ascon-selftest
	./ascon-selftest

clean:
	rm -f ascon-proxy ascon-keygen ascon-selftest *.o

.PHONY: all deps test clean
