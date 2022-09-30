#include <string.h>

#include "eip712.c"

void get_hash(uint8_t *hash, const char *str) {
  size_t count = 0;
  bool suc = true;
  for (size_t i = 2; str[i] != '\0'; i += 2) {
    hash[count] = (uint8_t)((hex_to_int(str[i], &suc) << 4) +
                            hex_to_int(str[i + 1], &suc));
    count += 1;
  }
}

#define PRINT_JSON(data)         \
  {                              \
    char outjs[1024 * 32] = {0}; \
    output_json(data, outjs);    \
    printf("%s\n", outjs);       \
  }

int check_eip712(eip712_data *data, const char *str_hash, int rc_code) {
  uint8_t hash2[EIP712_HASH_SIZE] = {0};
  int rc = get_eip712_hash(data, hash2);
  if (rc != rc_code) {
    ASSERT(false);
    return rc;
  }

  uint8_t hash[EIP712_HASH_SIZE] = {0};
  get_hash(hash, str_hash);

  if (memcmp(hash, hash2, EIP712_HASH_SIZE) != 0) {
    ASSERT(false);
    return 1;
  }

  return 0;
}

int test_base1() {
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

  uint8_t digest_data[32] = {0xa7, 0x1c, 0x9b, 0xf1, 0xcb, 0x16, 0x86, 0xb3,
                             0x5a, 0x6c, 0x2e, 0xe4, 0x59, 0x32, 0x02, 0xbc,
                             0x13, 0x27, 0x9a, 0xae, 0x96, 0xe6, 0xea, 0x27,
                             0x4d, 0x91, 0x94, 0x44, 0xf1, 0xe3, 0x74, 0x9f};
  memcpy(data.digest, digest_data, 32);

  data.transaction_das_message =
      "TRANSFER FROM 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39280335 "
      "CKB) TO 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39270335 CKB)";

  return check_eip712(
      &data,
      "0xcce661e249e03e2e0c581e1763fa1432491863c625a4128dd966822cc5f1d2be",
      EIP712_SUC);
}

int test_base2() {
  eip712_data data = {0};

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

  get_hash(
      data.digest,
      "0xA71C9BF1CB1686B35A6C2EE4593202BC13279AAE96E6EA274D919444F1E3749F");
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

  return check_eip712(
      &data,
      "0xf41ea7c5b04650a912bd528e64aed20fcd611c21a86d52d2314f37d432523b42",
      EIP712_SUC);
}

int test_empty_str() {
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

  uint8_t digest_data[32] = {0xa7, 0x1c, 0x9b, 0xf1, 0xcb, 0x16, 0x86, 0xb3,
                             0x5a, 0x6c, 0x2e, 0xe4, 0x59, 0x32, 0x02, 0xbc,
                             0x13, 0x27, 0x9a, 0xae, 0x96, 0xe6, 0xea, 0x27,
                             0x4d, 0x91, 0x94, 0x44, 0xf1, 0xe3, 0x74, 0x9f};
  memcpy(data.digest, digest_data, 32);

  data.transaction_das_message = "";

  return check_eip712(
      &data,
      "0xa33469b6132ef12964195a935548d6aa90e6525cb3d93b57af52595f31b2f4fa",
      EIP712_SUC);
}

int test_null_str() {
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

  uint8_t digest_data[32] = {0xa7, 0x1c, 0x9b, 0xf1, 0xcb, 0x16, 0x86, 0xb3,
                             0x5a, 0x6c, 0x2e, 0xe4, 0x59, 0x32, 0x02, 0xbc,
                             0x13, 0x27, 0x9a, 0xae, 0x96, 0xe6, 0xea, 0x27,
                             0x4d, 0x91, 0x94, 0x44, 0xf1, 0xe3, 0x74, 0x9f};
  memcpy(data.digest, digest_data, 32);

  data.transaction_das_message = "";

  return check_eip712(&data, "0x00", EIP712ERR_GEN_DATA);
}

int test_check_type() {
  ASSERT(is_def_type("address"));
  ASSERT(is_def_type("bool"));
  ASSERT(is_def_type("bytes1"));
  ASSERT(is_def_type("bytes2"));
  ASSERT(is_def_type("bytes4"));
  ASSERT(is_def_type("bytes8"));
  ASSERT(is_def_type("bytes16"));
  ASSERT(is_def_type("bytes32"));
  ASSERT(is_def_type("bytes"));
  ASSERT(is_def_type("int8"));
  ASSERT(is_def_type("int16"));
  ASSERT(is_def_type("int32"));
  ASSERT(is_def_type("int64"));
  ASSERT(is_def_type("int128"));
  ASSERT(is_def_type("int256"));
  ASSERT(is_def_type("uint8"));
  ASSERT(is_def_type("uint16"));
  ASSERT(is_def_type("uint32"));
  ASSERT(is_def_type("uint64"));
  ASSERT(is_def_type("uint128"));
  ASSERT(is_def_type("uint256"));

  ASSERT(!is_def_type("addres"));
  ASSERT(!is_def_type("sdfse"));
  ASSERT(!is_def_type("sfsefsefsefs"));
  ASSERT(!is_def_type("aa"));
  ASSERT(!is_def_type("int"));
  ASSERT(!is_def_type("insfseft"));
  ASSERT(!is_def_type("ssefsflij"));
  ASSERT(!is_def_type("bbsfs"));
  ASSERT(!is_def_type("bsbsfs"));
  ASSERT(!is_def_type("bssbsfs"));
  ASSERT(!is_def_type("bsssbsfs"));
  ASSERT(!is_def_type("uslkfle"));

  return 0;
}

int test_output_json() {
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

  uint8_t digest_data[32] = {0xa7, 0x1c, 0x9b, 0xf1, 0xcb, 0x16, 0x86, 0xb3,
                             0x5a, 0x6c, 0x2e, 0xe4, 0x59, 0x32, 0x02, 0xbc,
                             0x13, 0x27, 0x9a, 0xae, 0x96, 0xe6, 0xea, 0x27,
                             0x4d, 0x91, 0x94, 0x44, 0xf1, 0xe3, 0x74, 0x9f};
  memcpy(data.digest, digest_data, 32);

  data.transaction_das_message =
      "TRANSFER FROM 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39280335 "
      "CKB) TO 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39270335 CKB)";

  char buffer[1024 * 32] = {0};
  output_json(&data, buffer);
  uint8_t hash1[32] = {0}, hash2[32] = {0};
  keccak_256((const uint8_t *)buffer, strlen(buffer), hash2);
  get_hash(
      hash1,
      "0xdace5b17d26e1f7cae67a6127206d27c2a82f0de533c765a982306a930c62b27");
  CHECK2(memcmp(hash1, hash2, 32) == 0, 1);
  return 0;
}

int test_mem() {
  uint8_t buf[32] = {0};
  e_mem mem = eip712_gen_mem(buf, sizeof(buf));
  for (size_t i = 0; i < sizeof(buf); i++) {
    buf[i] = i;
  }

  eip712_alloc(&mem, 10);
  eip712_alloc(&mem, 20);
  uint8_t *buf3 = eip712_alloc(&mem, 10);
  CHECK2(!buf3, 1);

  return 0;
}

int test_str_to_int() {
  CHECK2(str_to_int("123") == 123, 1);
  CHECK2(str_to_int("123123123123123") == 123123123123123, 1);
  CHECK2(str_to_int("adawdawd") == 0, 1);
  return 0;
}

int main() {
  CHECK(test_base1());
  CHECK(test_base2());
  CHECK(test_empty_str());
  CHECK(test_null_str());
  CHECK(test_check_type());
  CHECK(test_output_json());
  CHECK(test_mem());
  CHECK(test_str_to_int());
  return 0;
}
