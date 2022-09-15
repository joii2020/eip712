#include <string.h>

#include "ckb_syscalls.h"
#include "eip712.c"
// #include "eip712_impl.h"

int example1() {
  uint8_t hash[EIP712_HASH_SIZE] = {0};
  eip712_data data = {0};
  data.domain.chain_id[31] = 1;
  data.domain.name = "da.systems";
  uint8_t verifying_contract[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x20, 0x21, 0x07, 0x22};
  memcpy(data.domain.verifying_contract, verifying_contract, 20);
  data.domain.version = "1";

  data.active.action = "withdraw_from_wallet";
  data.active.params = "0x00";

  data.inputs_capacity = "551.39280335 CKB";
  data.outputs_capacity = "551.39270335 CKB";
  data.fee = "0.0001 CKB";
  data.digest =
      "0xa71c9bf1cb1686b35a6c2ee4593202bc13279aae96e6ea274d919444f1e3749f";

  data.transaction_das_message =
      "TRANSFER FROM 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39280335 "
      "CKB) TO 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39270335 CKB)";

  int ref = get_eip712_hash(&data, hash);
  if (ref) return ref;

  uint8_t real_hash[EIP712_HASH_SIZE] = {
      0xCC, 0xE6, 0x61, 0xE2, 0x49, 0xE0, 0x3E, 0x2E, 0x0C, 0x58, 0x1E,
      0x17, 0x63, 0xFA, 0x14, 0x32, 0x49, 0x18, 0x63, 0xC6, 0x25, 0xA4,
      0x12, 0x8D, 0xD9, 0x66, 0x82, 0x2C, 0xC5, 0xF1, 0xD2, 0xBE};

  if (memcmp(real_hash, hash, EIP712_HASH_SIZE) != 0) {
    return 11;
  }

  return 0;
}

int example2() {
  uint8_t hash[EIP712_HASH_SIZE] = {0};
  eip712_data data = {0};
  data.domain.chain_id[31] = 9;
  data.domain.name = "da.systems";
  uint8_t verifying_contract[20] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x20, 0x21, 0x07, 0x22};
  memcpy(data.domain.verifying_contract, verifying_contract, 20);
  data.domain.version = "1";

  data.active.action = "withdraw_from_wallet";
  data.active.params = "0x00";

  data.inputs_capacity = "551.39280335 CKB";
  data.outputs_capacity = "551.39270335 CKB";
  data.fee = "0.0001 CKB";
  data.digest =
      "0xa71c9bf1cb1686b35a6c2ee4593202bc13279aae96e6ea274d919444f1e3749f";

  data.transaction_das_message =
      "TRANSFER FROM 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39280335 "
      "CKB) TO 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39270335 CKB)";

  eip712_cell inputs[2] = {0};
  inputs[0].capacity = "999.99 CKB";
  inputs[0].lock = "das-lock,0x01,0x0000000000000000000000000000000000000011";
  inputs[0].type = "account-cell-type,0x01,0x";
  inputs[0].data = "{ account: das00001.bit, expired_at: 1642649600 }";
  inputs[0].extra_data =
      "{ status: 0, "
      "records_hash:"
      "55478d76900611eb079b22088081124ed6c8bae21a05dd1a0d197efcc7c114ce }";

  inputs[1].capacity = "9.99 CKB";
  inputs[1].lock = "das-lock,0x01,0x0000000000000000000000000000000000000021";
  inputs[1].type = "account-cell-type,0x01,0x";
  inputs[1].data = "{ account: das00001.bit, expired_at: 1642649600 }";
  inputs[1].extra_data =
      "{ status: 0, "
      "records_hash:"
      "55478d76900611eb079b22088081124ed6c8bae21a05dc1a0d197efcc7c114ce }";

  data.inputs = inputs;
  data.inputs_len = sizeof(inputs) / sizeof(eip712_cell);

  eip712_cell outputs[1] = {0};
  outputs[0].capacity = "119.99 CKB";
  outputs[0].lock = "das-lock,0x02,0x0000000000000000000000000000000000000021";
  outputs[0].type = "account-cell-type,0x01,0x";
  outputs[0].data = "{ account: das00001.bit, expired_at: 1642649600 }";
  outputs[0].extra_data =
      "{ status: 0, "
      "records_hash:"
      "55478d76900711eb079b22088081124ed6c8bae21a05dc1a0d197efcc7c114ce }";

  data.outputs = outputs;
  data.outputs_len = sizeof(outputs) / sizeof(eip712_cell);

  int ref = get_eip712_hash(&data, hash);
  if (ref) return ref;

  uint8_t real_hash[EIP712_HASH_SIZE] = {
      0xBC, 0x85, 0x0A, 0xA7, 0xA7, 0x17, 0x99, 0x31, 0xF9, 0x01, 0x72,
      0x4F, 0x87, 0xF9, 0xA5, 0xCB, 0x17, 0x34, 0x57, 0x20, 0xD9, 0x50,
      0x1F, 0xE7, 0xDD, 0xF4, 0x3B, 0x43, 0x9F, 0x15, 0x36, 0xCE};

  if (memcmp(real_hash, hash, EIP712_HASH_SIZE) != 0) {
    return 11;
  }

  return 0;
}

int main() {
  int ref = 0;

  ref = example1();
  if (ref) return ref;
  ref = example2();
  if (ref) return ref;
  return 0;
}
