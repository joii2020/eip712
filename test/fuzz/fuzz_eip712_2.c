#include <stdio.h>
#include <unistd.h>

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
  uint8_t digest[EIP712_HASH_SIZE];

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

#define MAX_FUZZ_STRING_SIZE 128
#define MAX_FUZZ_CELLS_SIZE 32

char *gen_fuzz_string(e_mem *mem, size_t str_len) {
  str_len = str_len % (MAX_FUZZ_STRING_SIZE - 2) + 2;

  char *buf = eip712_alloc(mem, str_len);
  memset(buf, 'A', str_len - 1);
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

char *gen_str_from_bytes(e_mem *mem, uint8_t *buf, size_t size) {
  char *out_buf = eip712_alloc(mem, size * 2 + 2 + 1);
  size_t pos = 0;
  output_mem_buf(buf, size, out_buf, &pos);
  return out_buf;
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
  data->digest =
      gen_str_from_bytes(mem, temp_data.digest, sizeof(temp_data.digest));

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

////////////////////////////////////////////////////////////////////////

static char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};

void base64_encode(const unsigned char *data, size_t input_length,
                   char *output_buf) {
  size_t output_length = 4 * ((input_length + 2) / 3);

  for (int i = 0, j = 0; i < input_length;) {
    uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
    uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

    output_buf[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    output_buf[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    output_buf[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    output_buf[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }

  for (int i = 0; i < mod_table[input_length % 3]; i++)
    output_buf[output_length - 1 - i] = '=';
}

char G_OUTPUT_STR[1024 * 1024] = {0};
char G_OUTPUT_STR_BASE64[sizeof(G_OUTPUT_STR) * 2] = {0};
char G_CHECK_CMD[sizeof(G_OUTPUT_STR) * 3] = {0};

void check_eip712tool_hash(const eip712_data *data, uint8_t *ret_hash) {
  memset(G_OUTPUT_STR, 0, sizeof(G_OUTPUT_STR));
  memset(G_OUTPUT_STR_BASE64, 0, sizeof(G_OUTPUT_STR_BASE64));
  output_json(data, G_OUTPUT_STR);
  ASSERT(G_OUTPUT_STR[1] != '}');

  base64_encode((const unsigned char *)G_OUTPUT_STR, strlen(G_OUTPUT_STR),
                G_OUTPUT_STR_BASE64);

  char hash_str[80] = {0};
  size_t pos = 0;
  output_mem_buf(ret_hash, EIP712_HASH_SIZE, hash_str, &pos);

  memset(G_CHECK_CMD, 0, sizeof(G_CHECK_CMD));
  const char *check_cmd_path =
      "/home/joii/code/eip712/test/fuzz/build/fuzz_eip712_compared";
  strcpy(G_CHECK_CMD, check_cmd_path);
  pos = strlen(check_cmd_path);

  G_CHECK_CMD[pos] = ' ';
  pos++;

  strcpy(G_CHECK_CMD + pos, G_OUTPUT_STR_BASE64);
  pos += strlen(G_OUTPUT_STR_BASE64);

  G_CHECK_CMD[pos] = ' ';
  pos++;

  strcpy(G_CHECK_CMD + pos, &hash_str[2]);
  int rc_code = system(G_CHECK_CMD);

  ASSERT(rc_code == 0);

  return;
}

uint8_t G_MEM_BUFFER[1024 * 1024] = {0};
int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  memset(G_MEM_BUFFER, 0, sizeof(G_MEM_BUFFER));
  e_mem mem = eip712_gen_mem(G_MEM_BUFFER, sizeof(G_MEM_BUFFER));

  eip712_data eip_data = {0};
  gen_fuzz_eip712_data(&mem, &eip_data, data, size);

  uint8_t out_hash[EIP712_HASH_SIZE] = {0};
  int ret_val = get_eip712_hash(&eip_data, out_hash);
  ASSERT(ret_val == EIP712_SUC || ret_val == EIP712ERR_GEN_DATA);

  check_eip712tool_hash(&eip_data, out_hash);
  return 0;
}