ENABLE_RVV=1

ifeq ($(ENABLE_RVV), 1)
# TARGET := riscv64-unknown-elf-
	TARGET := riscv64-unknown-linux-gnu-
endif

CC := $(TARGET)gcc
LD := $(TARGET)gcc
OBJCOPY := $(TARGET)objcopy

CFLAGS := -fPIC -O1 -g -fno-builtin-printf -fno-builtin-memcmp -fvisibility=hidden -fdata-sections -ffunction-sections -Wall -Werror -Wno-nonnull -Wno-unused-function -I ./../ -I ./../src
ifeq ($(ENABLE_RVV), 1)
	CFLAGS := $(CFLAGS) -Wno-nonnull-compare -nostdinc -nostdlib -nostartfiles -I ./../deps/ckb-c-stdlib -I ./../deps/ckb-c-stdlib/libc -I ./../deps/ckb-c-stdlib/molecule -DCKB_C_STDLIB_PRINTF
	LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
endif

ifeq ($(ENABLE_COVERAGE), 1)
	CFLAGS := $(CFLAGS) --coverage
endif

BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: test

all-via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

clean: FORCE
	rm -rf build/*
	rm -rf test_eip712.gcda test_eip712.gcno *.info cover_report
.PHONY: FORCE
FORCE:

test: test_eip712.c
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o build/test $<
