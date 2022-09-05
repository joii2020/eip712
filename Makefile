# TARGET := riscv64-unknown-linux-gnu-

CC := $(TARGET)gcc
LD := $(TARGET)gcc
OBJCOPY := $(TARGET)objcopy


CFLAGS := -fPIC -O0 -Wall -Werror -Wno-nonnull -Wno-unused-function -g -fno-builtin-printf -fno-builtin-memcmp -fvisibility=hidden -fdata-sections -ffunction-sections
# CFLAGS := $(CFLAGS) -nostdlib -nostdinc -nostartfiles -Wno-nonnull-compare
CFLAGS := $(CFLAGS) -I src
# CFLAGS := $(CFLAGS) -I deps/ckb-c-stdlib -I deps/ckb-c-stdlib/libc -I deps/ckb-c-stdlib/molecule

LDFLAGS :=
# LDFLAGS := $(LDFLAGS) -Wl,--gc-sections -fdata-sections -ffunction-sections  -Wl,-static


all: build/test
	mkdir -p build

clean: FORCE
	rm -rf build/*

.PHONY: FORCE
FORCE:


SRC = $(wildcard src/*.c) \
			$(wildcard src/test/*.c) \
			$(wildcard src/eip712/*.c)
OBJ = $(patsubst %.c,build/%.o,$(notdir ${SRC}))

$(info $(SRC))
$(info $(OBJ))


build/%.o: src/%.c
	$(CC) $(CFLAGS) -c  $< -o $@

build/%.o: src/test/%.c
	$(CC) $(CFLAGS) -c  $< -o $@

build/%.o: src/eip712/%.c
	$(CC) $(CFLAGS) -c  $< -o $@

build/test: $(OBJ)
	
	$(CC) $(LDFLAGS) -o $@ $^	


