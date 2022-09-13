TARGET := riscv64-unknown-elf-
# TARGET := riscv64-unknown-linux-gnu-

CC := $(TARGET)gcc
LD := $(TARGET)gcc
OBJCOPY := $(TARGET)objcopy


CFLAGS := -fPIC -O0 -g -fno-builtin-printf -fno-builtin-memcmp -fvisibility=hidden -fdata-sections -ffunction-sections -I ./ -I src
CFLAGS := $(CFLAGS)  -nostdinc -nostdlib -nostartfiles -DCKB_C_STDLIB_PRINTF -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule -DCKB_DECLARATION_ONLY
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections


all: build/example_base
	mkdir -p build

clean: FORCE
	rm -rf build/*

.PHONY: FORCE
FORCE:

SRC = $(wildcard src/*.c) \
			$(wildcard src/example/*.c)
OBJ = $(patsubst %.c,build/%.o,$(notdir ${SRC}))

$(info $(SRC))
$(info $(OBJ))


build/%.o: src/%.c
	$(CC) $(CFLAGS) -c  $< -o $@

build/%.o: src/example/%.c
	$(CC) $(CFLAGS) -c  $< -o $@

build/impl.o: deps/ckb-c-stdlib/libc/src/impl.c
	$(CC) -c $(CFLAGS) $(LDFLAGS) -o $@ $^

build/example_base: $(OBJ) build/impl.o
	$(CC) $(LDFLAGS) -o $@ $^
	$(DCKB_DECLARATION_ONLY) --only-keep-debug $@ $@.debug
	# $(OBJCOPY) --strip-debug --strip-all $@


