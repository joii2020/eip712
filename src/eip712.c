#include "eip712.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eip712/eip712_tools.h"

e_item *gen_eip712_data_types(e_mem *mem, e_item *root) {
  e_item *d_types = gen_item_struct(mem, root, "types", NULL);

  e_item *domain = gen_item_array(mem, d_types, "EIP712Domain");

  e_item *it = NULL;

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "chainId");
  gen_item_string(mem, it, "type", "uint256");

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "name");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "verifyingContract");
  gen_item_string(mem, it, "type", "address");

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "version");
  gen_item_string(mem, it, "type", "string");

  e_item *action = gen_item_array(mem, d_types, "Action");
  it = gen_item_struct(mem, action, NULL, NULL);
  gen_item_string(mem, it, "name", "action");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, action, NULL, NULL);
  gen_item_string(mem, it, "name", "params");
  gen_item_string(mem, it, "type", "string");

  e_item *cell = gen_item_array(mem, d_types, "Cell");
  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "capacity");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "lock");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "type");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "data");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "extraData");
  gen_item_string(mem, it, "type", "string");

  e_item *tran = gen_item_array(mem, d_types, "Transaction");
  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "DAS_MESSAGE");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "inputsCapacity");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "outputsCapacity");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "fee");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "action");
  gen_item_string(mem, it, "type", "Action");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "inputs");
  gen_item_string(mem, it, "type", "Cell[]");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "outputs");
  gen_item_string(mem, it, "type", "Cell[]");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "digest");
  gen_item_string(mem, it, "type", "bytes32");

  return d_types;
}

e_item *gen_eip712_data_domain(e_mem *mem, e_item *root) {
  e_item *d_domain = gen_item_struct(mem, root, "domain", NULL);

  gen_item_num(mem, d_domain, "chainId", "0x01", ETYPE_UINT256);
  gen_item_string(mem, d_domain, "name", "da.systems");
  gen_item_mem_by_str(mem, d_domain, "verifyingContract",
                      "0x0000000000000000000000000000000020210722",
                      ETYPE_ADDRESS);
  gen_item_string(mem, d_domain, "version", "1");

  return d_domain;
}

e_item *gen_eip712_data_message(e_mem *mem, e_item *root) {
  e_item *d_message = gen_item_struct(mem, root, "message", NULL);

  gen_item_string(
      mem, d_message, "DAS_MESSAGE",
      "TRANSFER FROM 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39280335 "
      "CKB) TO 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39270335 CKB)");
  gen_item_string(mem, d_message, "inputsCapacity", "551.39280335 CKB");
  gen_item_string(mem, d_message, "outputsCapacity", "551.39270335 CKB");
  gen_item_string(mem, d_message, "fee", "0.0001 CKB");

  gen_item_num(
      mem, d_message, "digest",
      "0xa71c9bf1cb1686b35a6c2ee4593202bc13279aae96e6ea274d919444f1e3749f",
      ETYPE_BYTES32);

  e_item *action = gen_item_struct(mem, d_message, "action", NULL);
  gen_item_string(mem, action, "action", "withdraw_from_wallet");
  gen_item_string(mem, action, "params", "0x00");

  gen_item_array(mem, d_message, "inputs");
  gen_item_array(mem, d_message, "outputs");

  return d_message;
}

e_item *gen_eip712_data(e_mem *mem) {
  e_item *root = gen_item_struct(mem, NULL, "", NULL);

  gen_eip712_data_types(mem, root);
  gen_item_string(mem, root, "primaryType", "Transaction");
  gen_eip712_data_domain(mem, root);
  gen_eip712_data_message(mem, root);

  return root;
}

int test_eip712_2() {
  uint8_t buffer[1024 * 8];
  e_mem mem = eip712_gen_mem(buffer, sizeof(buffer));

  e_item *root = gen_eip712_data(&mem);

  // output_item(root);
  uint8_t ret_hash[32] = {0};
  return encode_2(root, ret_hash);
}
