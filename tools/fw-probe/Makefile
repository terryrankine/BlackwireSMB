# Standalone PS5 payload build for the Blackwire firmware/profile probe.
# Follows the ps5-payload-dev/sdk sample convention: the SDK's prospero.mk
# provides CC (prospero-clang), PS5_DEPLOY and the default libraries that
# resolve kernel_get_fw_version() and the read-only sysctl path.
#
# This payload is NOT part of the Blackwire build. It is a diagnostic tool.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := blackwire-fw-probe.elf

CFLAGS += -Wall -Wextra -Werror -g

all: $(ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
