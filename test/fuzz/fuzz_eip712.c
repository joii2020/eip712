#include <stdio.h>

#include "eip712.c"

#define FUZZ_BUF_MIN_SIZE 32

void gen_fuzz_eip712_data(eip712_data *data, uint8_t *random_buf,
                          size_t random_size) {}

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  if (size > 1 && size < FUZZ_BUF_MIN_SIZE) {
    return 0;
  }
  eip712_data eip_data = {0};
  if (size >= FUZZ_BUF_MIN_SIZE) {
    gen_fuzz_eip712_data(&eip_data, data, size);
  }

  uint8_t out_hash[EIP712_HASH_SIZE] = {0};
  return get_eip712_hash(&eip_data, out_hash);
}