
CC := clang

CFLAGS := -O0 -g -fsanitize=fuzzer,address,undefined -fsanitize-recover=address -Wall -Werror -Wno-nonnull -Wno-unused-function -I ./../../ -I ./../../src -I ./../../deps/ckb-c-stdlib/ -I eip712tool/src/sim_include

all: build/fuzz_eip712 build/fuzz_eip712_2 build/fuzz_eip712_compared

build/fuzz_eip712: fuzz_eip712.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/fuzz_eip712_2: fuzz_eip712_2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/fuzz_eip712_compared:
	cd rust_compared && cargo build --release
	rm -rf build/fuzz_eip712_compared
	mv rust_compared/target/release/rust_compared build/fuzz_eip712_compared

clean: FORCE
	rm -rf build/fuzz_eip712 build/fuzz_eip712_compared

.PHONY: FORCE
FORCE:
