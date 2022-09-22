
CC := clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov
NPROC?=4

CFLAGS := -O0 -g -fsanitize=fuzzer,address,undefined -fsanitize-recover=address -Wall -Werror -Wno-nonnull -Wno-unused-function -I ./../../ -I ./../../src -I ./../../deps/ckb-c-stdlib/ -I eip712tool/src/sim_include

COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -I ./../../ -I ./../../src -I ./../../deps/ckb-c-stdlib/ -I eip712tool/src/sim_include
ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

CORPUS_DIR=corpus
COVERAGE_DIR=build


all: build/fuzz_eip712 build/fuzz_eip712_2 build/eip712_coverage

build/fuzz_eip712: fuzz_eip712.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/fuzz_eip712_2: fuzz_eip712_2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

build/eip712_coverage: fuzz_eip712_coverage.c fuzz_eip712_2.c
	clang $(COVERAGE_FLAGS) fuzz_eip712_coverage.c fuzz_eip712_2.c -o build/eip712_coverage

start-fuzzer: build/fuzz_eip712
	build/fuzz_eip712 -max_len=800000 -workers=$(NPROC) -jobs=$(NPROC) $(CORPUS_DIR)

start-fuzzer-2: build/fuzz_eip712_2
	build/fuzz_eip712_2 -max_len=800000 -workers=$(NPROC) -jobs=$(NPROC) $(CORPUS_DIR)

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata build/eip712_coverage

%.profraw: build/eip712_coverage
	LLVM_PROFILE_FILE=$@ build/eip712_coverage $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@


clean: FORCE
	rm -rf build/fuzz_eip712 build/fuzz_eip712_2 build/eip712_coverage

.PHONY: FORCE
FORCE:

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata

