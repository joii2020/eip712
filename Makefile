TARGET := riscv64-unknown-linux-gnu-

CC := $(TARGET)gcc
LD := $(TARGET)gcc
OBJCOPY := $(TARGET)objcopy


CFLAGS := -fPIC -O3 -fno-builtin-printf -fno-builtin-memcmp -nostdinc -nostdlib -nostartfiles -fvisibility=hidden -fdata-sections -ffunction-sections -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I deps/ckb-c-std-lib/molecule -I c -I build -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g

LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections


all: 
	mkdir -p build

clean: FORCE
	rm -rf build/*

build/test: src/test/test_base.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^	


.PHONY: FORCE
FORCE:
