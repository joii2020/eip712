# TARGET := riscv64-unknown-elf-
TARGET := riscv64-unknown-linux-gnu-

CC := $(TARGET)gcc
LD := $(TARGET)gcc
OBJCOPY := $(TARGET)objcopy

CFLAGS := -fPIC -O2 -g -fno-builtin-printf -fno-builtin-memcmp -fvisibility=hidden -fdata-sections -ffunction-sections -Wall -Werror -Wno-nonnull -Wno-unused-function -I ./ -I src
CFLAGS := $(CFLAGS) -Wno-nonnull-compare -nostdinc -nostdlib -nostartfiles -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule -DCKB_C_STDLIB_PRINTF
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections

BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: build/example_base
	mkdir -p build

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

clean: FORCE
	rm -rf build/*

.PHONY: FORCE
FORCE:

build/example_base: src/example/example_base.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
