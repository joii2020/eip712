#define CKB_DECLARATION_ONLY

#include "eip712.h"
#include "eip712_impl.h"

#include <string.h>

int test1() {
  uint8_t hash[EIP712_HASH_SIZE] = {0};
  eip712_data data;
  data.domain.chain_id[31] = 1;

  int ref = get_eip712_hash(&data, hash);
  if (ref) return ref;

  uint8_t real_hash[EIP712_HASH_SIZE] = {
      0xCC, 0xE6, 0x61, 0xE2, 0x49, 0xE0, 0x3E, 0x2E, 0x0C, 0x58, 0x1E,
      0x17, 0x63, 0xFA, 0x14, 0x32, 0x49, 0x18, 0x63, 0xC6, 0x25, 0xA4,
      0x12, 0x8D, 0xD9, 0x66, 0x82, 0x2C, 0xC5, 0xF1, 0xD2, 0xBE};

  ASSERT(memcpy(real_hash, hash, EIP712_HASH_SIZE) == 0);

  return 0;
}

int main() {
  int ref = 0;

  ref = test1();
  if (ref) return ref;
  return 0;
}