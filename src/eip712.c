#include "eip712.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eip712_impl.c"

int gen_eip712_data_types(e_mem *mem, e_item *root) {
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

  return EIP712_SUC;
}

int gen_eip712_data_domain(e_mem *mem, e_item *root,
                           const eip712_domain *domain) {
  ASSERT(domain);
  CHECK2(domain->name, EIP712ERR_GEN_DATA);
  CHECK2(domain->name[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(domain->version, EIP712ERR_GEN_DATA);
  CHECK2(domain->version[0] != '\0', EIP712ERR_GEN_DATA);

  e_item *d_domain = gen_item_struct(mem, root, "domain", NULL);

  gen_item_num(mem, d_domain, "chainId", domain->chain_id,
               sizeof(domain->chain_id), ETYPE_UINT256);
  gen_item_string(mem, d_domain, "name", domain->name);
  gen_item_mem(mem, d_domain, "verifyingContract", domain->verifying_contract,
               20, ETYPE_ADDRESS);
  gen_item_string(mem, d_domain, "version", domain->version);
  return EIP712_SUC;
}

typedef enum {
  EIP712_CELL_INPUT,
  EIP712_CELL_OUTPUT,
} EIP712CellType;

int gen_eip712_cell(e_mem *mem, e_item *root, const eip712_cell *cell) {
  CHECK2(cell->capacity, EIP712ERR_GEN_DATA);
  CHECK2(cell->capacity[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(cell->lock, EIP712ERR_GEN_DATA);
  CHECK2(cell->lock[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(cell->type, EIP712ERR_GEN_DATA);
  CHECK2(cell->type[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(cell->data, EIP712ERR_GEN_DATA);
  CHECK2(cell->data[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(cell->extra_data, EIP712ERR_GEN_DATA);
  CHECK2(cell->extra_data[0] != '\0', EIP712ERR_GEN_DATA);

  e_item *e = gen_item_struct(mem, root, NULL, NULL);
  gen_item_string(mem, e, "capacity", cell->capacity);
  gen_item_string(mem, e, "lock", cell->lock);
  gen_item_string(mem, e, "type", cell->type);
  gen_item_string(mem, e, "data", cell->data);
  gen_item_string(mem, e, "extraData", cell->extra_data);

  return EIP712_SUC;
}

int gen_eip712_data_message(e_mem *mem, e_item *root, const eip712_data *data) {
  ASSERT(data);
  CHECK2(data->transaction_das_message, EIP712ERR_GEN_DATA);
  CHECK2(data->transaction_das_message[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(data->inputs_capacity, EIP712ERR_GEN_DATA);
  CHECK2(data->inputs_capacity[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(data->outputs_capacity, EIP712ERR_GEN_DATA);
  CHECK2(data->outputs_capacity[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(data->fee, EIP712ERR_GEN_DATA);
  CHECK2(data->fee[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(data->digest, EIP712ERR_GEN_DATA);
  CHECK2(data->digest[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(data->active.action, EIP712ERR_GEN_DATA);
  CHECK2(data->active.action[0] != '\0', EIP712ERR_GEN_DATA);
  CHECK2(data->active.params, EIP712ERR_GEN_DATA);
  CHECK2(data->active.params[0] != '\0', EIP712ERR_GEN_DATA);

  // TODO joii
  CHECK2(!(data->inputs_len > 0 && !data->inputs), EIP712ERR_GEN_DATA);
  CHECK2(!(data->outputs_len > 0 && !data->outputs), EIP712ERR_GEN_DATA);

  e_item *d_message = gen_item_struct(mem, root, "message", NULL);

  gen_item_string(mem, d_message, "DAS_MESSAGE", data->transaction_das_message);
  gen_item_string(mem, d_message, "inputsCapacity", data->inputs_capacity);
  gen_item_string(mem, d_message, "outputsCapacity", data->outputs_capacity);
  gen_item_string(mem, d_message, "fee", data->fee);

  gen_item_num(mem, d_message, "digest", data->digest, EIP712_HASH_SIZE, ETYPE_BYTES32);

  e_item *action = gen_item_struct(mem, d_message, "action", NULL);
  gen_item_string(mem, action, "action", data->active.action);
  gen_item_string(mem, action, "params", data->active.params);

  e_item *inputs = gen_item_array(mem, d_message, "inputs");
  for (size_t i = 0; i < data->inputs_len; i++) {
    gen_eip712_cell(mem, inputs, &(data->inputs[i]));
  }

  e_item *outputs = gen_item_array(mem, d_message, "outputs");
  for (size_t i = 0; i < data->outputs_len; i++) {
    gen_eip712_cell(mem, outputs, &(data->outputs[i]));
  }

  return EIP712_SUC;
}

int gen_eip712_data(e_mem *mem, const eip712_data *data, e_item **out_item) {
  e_item *root = gen_item_struct(mem, NULL, "", NULL);

  // Fixed content
  CHECK(gen_eip712_data_types(mem, root));
  gen_item_string(mem, root, "primaryType", "Transaction");

  CHECK(gen_eip712_data_domain(mem, root, &(data->domain)));
  CHECK(gen_eip712_data_message(mem, root, data));

  *out_item = root;
  return EIP712_SUC;
}

int get_eip712_hash(const eip712_data *data, uint8_t *out_hash) {
  uint8_t buffer[1024 * 64] = {0};
  e_mem mem = eip712_gen_mem(buffer, sizeof(buffer));

  e_item *edata = 0;
  CHECK(gen_eip712_data(&mem, data, &edata));
  CHECK2(edata, EIP712ERR_GEN_DATA);

  CHECK(encode_impl(edata, out_hash));

  return EIP712_SUC;
}

void output_json(const eip712_data *data, char *output_json) {
  uint8_t buffer[1024 * 64] = {0};
  e_mem mem = eip712_gen_mem(buffer, sizeof(buffer));

  e_item *edata = 0;
  gen_eip712_data(&mem, data, &edata);
  size_t pos = 0;
  output_eip712_json(edata, output_json, &pos);
}
