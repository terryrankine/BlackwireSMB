# Standalone PS5 payload build for the Blackwire NFS probe.
# Follows the ps5-payload-dev/sdk sample convention: the SDK's prospero.mk
# provides CC (prospero-clang) and PS5_DEPLOY.
#
# libnfs is built here from vendor/libnfs as a static archive with the same
# CMake toolchain, optimisation and path-mapping flags that tools/build/deps.py
# uses for libsmb2. Blackwire itself does not link libnfs yet.
#
# This payload is NOT part of the Blackwire build. It is a diagnostic tool.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ROOT         := $(abspath ../..)
LIBNFS_SRC   := $(ROOT)/vendor/libnfs
LIBNFS_BUILD := $(abspath build/libnfs)
LIBNFS_A     := $(LIBNFS_BUILD)/lib/libnfs.a

# Same as deps.py dependency_source_flags(): keep checkout, SDK and output
# paths out of DWARF and file strings.
DEP_CFLAGS := -O2 -g -gno-record-command-line \
	-ffile-prefix-map=$(ROOT)=/blackwire -fdebug-prefix-map=$(ROOT)=/blackwire \
	-ffile-prefix-map=$(PS5_PAYLOAD_SDK)=/ps5-sdk -fdebug-prefix-map=$(PS5_PAYLOAD_SDK)=/ps5-sdk \
	-ffile-prefix-map=$(LIBNFS_BUILD)=/blackwire/dependency-build \
	-fdebug-prefix-map=$(LIBNFS_BUILD)=/blackwire/dependency-build

ELF := blackwire-nfs-probe.elf

# Compile-time overrides of the probe defaults, e.g.
# make PROBE_DEFS='-DNFS_PROBE_SERVER=\"10.0.0.5\"'
PROBE_DEFS ?=

CFLAGS += -Wall -Wextra -Werror -g -I$(LIBNFS_SRC)/include $(PROBE_DEFS)

all: $(ELF)

$(LIBNFS_A):
	cmake -S $(LIBNFS_SRC) -B $(LIBNFS_BUILD) \
		-DCMAKE_TOOLCHAIN_FILE=$(PS5_PAYLOAD_SDK)/toolchain/prospero.cmake \
		-DBUILD_SHARED_LIBS=OFF -DENABLE_NFS4_2=OFF -DENABLE_TLS=OFF \
		-DENABLE_MULTITHREADING=OFF -DENABLE_EXAMPLES=OFF -DENABLE_UTILS=OFF \
		-DENABLE_TESTS=OFF -DENABLE_DOCUMENTATION=OFF \
		"-DCMAKE_C_FLAGS=$(DEP_CFLAGS)"
	cmake --build $(LIBNFS_BUILD) --parallel 4

$(ELF): main.c $(LIBNFS_A)
	$(CC) $(CFLAGS) -o $@ main.c $(LIBNFS_A)

clean:
	rm -rf $(ELF) build

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(ELF)

.PHONY: all clean test
