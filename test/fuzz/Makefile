
CC := clang

CFLAGS := -O0 -g -fsanitize=fuzzer,address,undefined -fsanitize-recover=address -Wall -Werror -Wno-nonnull -Wno-unused-function -I ./../../ -I ./../../src -I ./../../deps/ckb-c-stdlib/

build/fuzz_eip712:  fuzz_eip712.c
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean: FORCE
	rm -rf build/fuzz_eip712

.PHONY: FORCE
FORCE:
