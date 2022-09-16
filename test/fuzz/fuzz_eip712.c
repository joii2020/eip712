#include <stdio.h>

#include "eip712.c"

typedef struct _fuzz_eip712_data {
  uint8_t domain_chain_id[EIP712_HASH_SIZE];
  uint16_t domain_name_str_len;
  uint8_t domain_verifying_contract[20];
  uint16_t domain_version_str_len;

  uint16_t active_action_str_len;
  uint16_t active_params_str_len;

  uint16_t transaction_das_message_str_len;
  uint16_t inputs_capacity_str_len;
  uint16_t outputs_capacity_str_len;
  uint16_t fee_str_len;
  uint16_t digest_str_len;

  uint16_t inputs_len;
  uint16_t outputs_len;
} fuzz_eip712_data;

typedef struct _fuzz_eip712_cell_data {
  uint16_t capacity_str_len;
  uint16_t lock_str_len;
  uint16_t type_str_len;
  uint16_t data_str_len;
  uint16_t extra_data_str_len;
} fuzz_eip712_cell_data;

#define FUZZ_BUF_MIN_SIZE sizeof(fuzz_eip712_data)
#define MAX_FUZZ_STRING_SIZE 128
#define MAX_FUZZ_CELLS_SIZE 32

char *gen_fuzz_string(e_mem *mem, size_t str_len) {
  if (str_len == 0) {
    return NULL;
  }
  str_len = str_len % MAX_FUZZ_STRING_SIZE;
  char *buf = eip712_alloc(mem, str_len + 1);
  memset(buf, 'A', str_len);
  return buf;
}

eip712_cell *gen_fuzz_eip712_cell(e_mem *mem, eip712_data *data,
                                  size_t cells_len, uint8_t **random_buf,
                                  size_t *random_len) {
  if (cells_len == 0) {
    return NULL;
  }
  size_t temp_len = 0;
  eip712_cell *cells = eip712_alloc(mem, sizeof(eip712_cell) * cells_len);
  for (size_t i = 0; i < cells_len; i++) {
    fuzz_eip712_cell_data temp_data = {0};
    if (*random_len < sizeof(temp_data)) {
      temp_len = *random_len;
    } else {
      temp_len = sizeof(temp_data);
    }
    if (temp_len != 0) {
      memcpy(&temp_data, *random_buf, temp_len);
      *random_buf += temp_len;
      *random_len -= temp_len;

      cells[i].capacity = gen_fuzz_string(mem, temp_data.capacity_str_len);
      cells[i].lock = gen_fuzz_string(mem, temp_data.lock_str_len);
      cells[i].type = gen_fuzz_string(mem, temp_data.type_str_len);
      cells[i].data = gen_fuzz_string(mem, temp_data.data_str_len);
      cells[i].extra_data = gen_fuzz_string(mem, temp_data.extra_data_str_len);
    }
  }
  return cells;
}

void gen_fuzz_eip712_data(e_mem *mem, eip712_data *data, uint8_t *random_buf,
                          size_t random_len) {
  fuzz_eip712_data temp_data = {0};
  size_t temp_data_len = sizeof(fuzz_eip712_data);
  if (temp_data_len > random_len) {
    temp_data_len = random_len;
  }
  memcpy(&temp_data, random_buf, temp_data_len);

  memcpy(data->domain.chain_id, temp_data.domain_chain_id, EIP712_HASH_SIZE);
  data->domain.name = gen_fuzz_string(mem, temp_data.domain_name_str_len);
  memcpy(data->domain.verifying_contract, temp_data.domain_verifying_contract,
         20);
  data->domain.version = gen_fuzz_string(mem, temp_data.domain_version_str_len);

  data->active.action = gen_fuzz_string(mem, temp_data.active_action_str_len);
  data->active.params = gen_fuzz_string(mem, temp_data.active_params_str_len);

  data->transaction_das_message =
      gen_fuzz_string(mem, temp_data.transaction_das_message_str_len);
  data->inputs_capacity =
      gen_fuzz_string(mem, temp_data.inputs_capacity_str_len);
  data->outputs_capacity =
      gen_fuzz_string(mem, temp_data.outputs_capacity_str_len);
  data->fee = gen_fuzz_string(mem, temp_data.fee_str_len);
  data->digest = gen_fuzz_string(mem, temp_data.digest_str_len);

  // gen cell
  random_buf = random_buf + temp_data_len;
  random_len = random_len - temp_data_len;
  temp_data.inputs_len = temp_data.inputs_len % MAX_FUZZ_CELLS_SIZE;
  temp_data.outputs_len = temp_data.outputs_len % MAX_FUZZ_CELLS_SIZE;
  data->inputs_len = temp_data.inputs_len;
  data->outputs_len = temp_data.outputs_len;

  data->inputs = gen_fuzz_eip712_cell(mem, data, temp_data.inputs_len,
                                      &random_buf, &random_len);
  data->inputs = gen_fuzz_eip712_cell(mem, data, temp_data.inputs_len,
                                      &random_buf, &random_len);
}

uint8_t g_mem_buffer[1024 * 1024] = {0};
int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  memset(g_mem_buffer, 0, sizeof(g_mem_buffer));
  e_mem mem = eip712_gen_mem(g_mem_buffer, sizeof(g_mem_buffer));

  eip712_data eip_data = {0};
  gen_fuzz_eip712_data(&mem, &eip_data, data, size);

  uint8_t out_hash[EIP712_HASH_SIZE] = {0};
  return get_eip712_hash(&eip_data, out_hash);
}