#include "eip712_impl.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ckb_keccak256.h"
// #include "deps/ckb-c-stdlib/ckb_keccak256.h"
#include "eip712.h"

////////////////////////////////////////////////////////////////
// include

#define EIP712_STRING_TYPE_MAX_SIZE 256
#define EIP712_TYPE_STR_BUF_MAX_SIZE 1024 * 4
#define MEMORY_ALIGNMENT_SIZE 8

typedef struct _eip712_type_deps_item {
  const char *item_type;
  struct _eip712_type_deps_item *next;
} eip712_type_deps_item;

typedef enum {
  EIP712_DOMAIN,
  EIP712_MESSAGE,
} EIP712MessageType;

int parse_vals(e_item *type_info, e_item *data_msg, e_item *types,
               struct SHA3_CTX *ctx);
void keccak_256(const uint8_t *buf, size_t buf_len, uint8_t *result);
void dbg_print_mem(const char *name, const uint8_t *buf, size_t len);

const char *G_EIP712_DEFALUT_TYPE[] = {
    "int8",   "int16",   "int32",  "int64",  "int128",  "int256",
    "uint8",  "uint16",  "uint32", "uint64", "uint128", "uint256",
    "bytes1", "bytes2",  "bytes4", "bytes8", "bytes16", "bytes32",
    "bool",   "address", "string", "bytes",
};

////////////////////////////////////////////////////////////////
// memory manager

e_mem eip712_gen_mem(uint8_t *buffer, size_t len) {
  e_mem m;
  m.buffer = buffer;
  m.buffer_len = len;
  m.pos = 0;
  return m;
}

void *eip712_alloc(e_mem *mem, size_t len) {
  if (len % MEMORY_ALIGNMENT_SIZE != 0) {
    len = (len / MEMORY_ALIGNMENT_SIZE + 1) * MEMORY_ALIGNMENT_SIZE;
  }
  if (mem->buffer_len < len + mem->pos) {
    ASSERT(false);
    return 0;
  }

  void *ret = mem->buffer + mem->pos;
  mem->pos += len;

  memset(ret, 0, len);

  return ret;
}

const char *eip712_alloc_memstr(e_mem *mem, const char *buf) {
  if (!buf) {
    return NULL;
  }
  size_t len = strlen(buf);
  if (len == 0) {
    return "";
  }
  ASSERT(len != 0);

  char *r = (char *)eip712_alloc(mem, len + 1);
  memcpy(r, buf, len);
  return r;
}

////////////////////////////////////////////////////////////////
// eip712_tree

e_item *gen_item_struct(e_mem *mem, e_item *parent, const char *key,
                        e_item *item) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = eip712_alloc_memstr(mem, key);
  it->type = ETYPE_STRUCT;
  it->value.data_struct = item;

  append_item(parent, it);
  return it;
}

void append_item(e_item *parent, e_item *child) {
  if (!parent) return;
  ASSERT(parent->type == ETYPE_STRUCT || parent->type == ETYPE_ARRAY);
  if (!parent->value.data_struct) {
    parent->value.data_struct = child;
  } else {
    e_item *it = parent->value.data_struct;
    while (true) {
      if (!it->sibling) {
        it->sibling = child;
        break;
      }
      it = it->sibling;
    }
  }
}

e_item *gen_item_string(e_mem *mem, e_item *parent, const char *key,
                        const char *val) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = eip712_alloc_memstr(mem, key);
  it->type = ETYPE_STRING;
  it->value.data_string = eip712_alloc_memstr(mem, val);

  append_item(parent, it);
  return it;
}

int hex_to_int(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }

  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 0xa;
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 0xa;
  }

  ASSERT(false);
  return 0;
}

uint64_t str_to_int(const char *c) {
  uint64_t res = 0;
  for (size_t i = 0; c[i] != 0; i++) {
    res = res * 10 + hex_to_int(c[i]);
  }
  return res;
}

size_t hex_to_bytes(const char *d, uint8_t *out) {
  // TODO

  size_t count = 0;
  for (size_t i = 2; d[i] != '\0'; i += 2) {
    out[count] = (uint8_t)((hex_to_int(d[i]) << 4) + hex_to_int(d[i + 1]));
    count += 1;
  }

  return count;
}

e_item *gen_item_mem_by_str(e_mem *mem, e_item *parent, const char *key,
                            const char *val, e_type type) {
  size_t buf_len = strlen(val) / 2 - 1;
  uint8_t *buf = eip712_alloc(mem, buf_len);

  size_t out_len = hex_to_bytes(val, buf);
  ASSERT(out_len == buf_len);

  return gen_item_mem(mem, parent, key, buf, buf_len, type);
}

e_item *gen_item_mem(e_mem *mem, e_item *parent, const char *key,
                     const uint8_t *val, size_t val_size, e_type type) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = eip712_alloc_memstr(mem, key);
  it->type = type;

  it->value.data_bytes.data = (uint8_t *)eip712_alloc(mem, val_size);
  memcpy(it->value.data_bytes.data, val, val_size);
  it->value.data_bytes.len = val_size;

  append_item(parent, it);
  return it;
}

e_item *gen_item_num(e_mem *mem, e_item *parent, const char *key,
                     const uint8_t *val, size_t val_size, e_type type) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = eip712_alloc_memstr(mem, key);
  it->type = type;

  ASSERT(val_size == 32);
  it->value.data_number = (uint8_t *)eip712_alloc(mem, EIP712_HASH_SIZE);
  memcpy(it->value.data_number, val, val_size);

  append_item(parent, it);
  return it;
}

e_item *gen_item_num_by_str(e_mem *mem, e_item *parent, const char *key,
                            const char *val, e_type type) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = eip712_alloc_memstr(mem, key);
  it->type = type;

  uint8_t buf[EIP712_HASH_SIZE] = {0};
  size_t out_len = hex_to_bytes(val, buf);
  ASSERT(out_len);
  it->value.data_number = (uint8_t *)eip712_alloc(mem, EIP712_HASH_SIZE);
  memcpy(it->value.data_number + EIP712_HASH_SIZE - out_len, buf, out_len);

  append_item(parent, it);
  return it;
}

e_item *gen_item_array(e_mem *mem, e_item *parent, const char *key) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = eip712_alloc_memstr(mem, key);
  it->type = ETYPE_ARRAY;

  append_item(parent, it);
  return it;
}

e_item *get_item(e_item *it, const char *name) {
  if (it == NULL) return NULL;
  ASSERT(it->type == ETYPE_STRUCT);

  it = it->value.data_struct;
  while (it) {
    if (strcmp(it->key, name) == 0) {
      return it;
    }
    it = it->sibling;
  }
  return NULL;
}

const char *get_item_tostr(e_item *it, const char *name) {
  it = get_item(it, name);
  if (it == NULL) return NULL;
  if (it->type != ETYPE_STRING) return NULL;
  return it->value.data_string;
}

void output_mem_buf(uint8_t *buf, size_t len) {
  printf("\"0x");
  for (size_t i = 0; i < len; i++) {
    printf("%02x", buf[i]);
  }
  printf("\"");
}

// output e_item to json
void output_item(e_item *it) {
  printf("{");
  if (it) {
    it = it->value.data_struct;
    while (it) {
      if (it->key) printf("\"%s\": ", it->key);

      if (it->type == ETYPE_STRING) {
        printf("\"%s\"", it->value.data_string);
      } else if (it->type == ETYPE_STRUCT) {
        printf("\n");
        output_item(it);
      } else if (it->type == ETYPE_ARRAY) {
        printf("[\n");
        e_item *itt = it->value.data_struct;
        while (itt) {
          output_item(itt);
          if (itt->sibling) printf(",\n");
          itt = itt->sibling;
        }
        printf("]\n");
      } else if (it->type == ETYPE_UINT256) {
        output_mem_buf(it->value.data_number, 32);
      } else if (it->type == ETYPE_BYTES32) {
        output_mem_buf(it->value.data_number, 32);
      } else if (it->type == ETYPE_ADDRESS) {
        output_mem_buf(it->value.data_bytes.data, it->value.data_bytes.len);
      } else {
        // printf("-----------");
      }
      if (it->sibling) printf(",\n");
      it = it->sibling;
    }
  }
  printf("}\n");
}

////////////////////////////////////////////////////////////////S

size_t append_str(char *buf, size_t pos, const char *s) {
  size_t str_len = strlen(s);
  memcpy(buf + pos, s, str_len);
  return pos + str_len;
}
#define APPEND_STR(data) pos = append_str(type_str, pos, data)

bool is_array(const char *s1) {
  size_t len = strlen(s1);
  if (s1[len - 1] == ']') {
    return true;
  } else {
    return false;
  }
}

bool type_cmp(const char *s1, const char *s2) {
  size_t i = 0;
  bool is_eq = false;
  while (true) {
    if (s1[i] == '\0') {
      if (s2[i] == '\0') {
        is_eq = true;
      }
      break;
    }
    if (s2[i] == '\0') {
      if (s1[i] == '[' || (s1[i] >= '0' && s1[i] <= '9')) {
        is_eq = true;
      }
      break;
    }

    if (s1[i] != s2[i]) {
      break;
    }
    i += 1;
  }
  return is_eq;
}

void keccak_256(const uint8_t *buf, size_t buf_len, uint8_t *result) {
  struct SHA3_CTX ctx;
  keccak_init(&ctx);
  keccak_update(&ctx, (unsigned char *)buf, buf_len);
  keccak_final(&ctx, result);
}

////////////////////////////////////////////////////////////////
// encode

bool is_def_type(const char *t) {
  // TODO, can be optimized here
  for (size_t i = 0; i < sizeof(G_EIP712_DEFALUT_TYPE) / sizeof(int *); i++) {
    if (strcmp(t, G_EIP712_DEFALUT_TYPE[i]) == 0) return true;
  }
  return false;
}

bool type_deps_list_has(eip712_type_deps_item *begin, const char *type_name) {
  for (eip712_type_deps_item *it = begin; it; it = begin->next) {
    if (strcmp(type_name, it->item_type) == 0) {
      return true;
    }
  }
  return false;
}

int parse_type(e_item *types, const char *type_name, char *type_str,
               size_t *readed_pos) {
  CHECK2(types->type == ETYPE_STRUCT, EIP712ERR_ENCODE_TYPE);

  e_item *it = get_item(types, type_name);
  CHECK2(it || it->type != ETYPE_ARRAY, EIP712ERR_ENCODE_TYPE);

  size_t pos = 0;

  APPEND_STR(it->key);
  APPEND_STR("(");

  it = it->value.data_struct;

  const char *item_name;
  const char *item_type;
  const char *item_type_name;

  uint8_t mem_buffer[1024 * 2] = {0};  // TODO
  e_mem mem = eip712_gen_mem(mem_buffer, sizeof(mem_buffer));

  eip712_type_deps_item *deps_type = NULL;
  eip712_type_deps_item *cur_deps = NULL;

  CHECK2(it->type == ETYPE_STRUCT, EIP712ERR_ENCODE_TYPE);
  while (it) {
    e_item *itt = it->value.data_struct;

    while (itt) {
      if (strcmp("name", itt->key) == 0)
        item_name = itt->value.data_string;
      else if (strcmp("type", itt->key) == 0) {
        item_type = itt->value.data_string;
        size_t it_type_len = strlen(item_type);

        if (is_array(item_type)) {
          char *t = eip712_alloc(&mem, it_type_len - 1);
          memcpy(t, itt->value.data_string, it_type_len - 2);
          item_type_name = t;
        } else {
          item_type_name = item_type;
        }
      }
      itt = itt->sibling;
    }

    // Get item
    if (!is_def_type(item_type_name) &&
        !type_deps_list_has(deps_type, item_type_name)) {
      // get item for
      eip712_type_deps_item *deps = (eip712_type_deps_item *)eip712_alloc(
          &mem, sizeof(eip712_type_deps_item));
      deps->item_type = item_type_name;

      if (cur_deps) {
        cur_deps->next = deps;
        cur_deps = deps;
      } else {
        cur_deps = deps;
        deps_type = deps;
      }
    }
    APPEND_STR(item_type);
    APPEND_STR(" ");
    APPEND_STR(item_name);
    if (it->sibling) {
      APPEND_STR(",");
    }

    it = it->sibling;
  }

  APPEND_STR(")");

  cur_deps = deps_type;
  while (cur_deps) {
    size_t deps_pos = 0;
    CHECK(parse_type(types, cur_deps->item_type, type_str + pos, &deps_pos));

    pos += deps_pos;
    cur_deps = cur_deps->next;
  }

  *readed_pos = pos;
  return EIP712_SUC;
}

int encode_address(e_item *it, uint8_t *encoded) {
  CHECK2(it->type == ETYPE_ADDRESS, EIP712ERR_ENCODE_ADDRESS);
  CHECK2(it->value.data_bytes.len == 20, EIP712ERR_ENCODE_ADDRESS);

  memset(encoded, 0, 12);  // Before 12 byte is zero
  memcpy(encoded + 12, it->value.data_bytes.data, it->value.data_bytes.len);

  return EIP712_SUC;
}

int parse_address(e_item *val, const char *type, uint8_t *encoded) {
  if (is_array(type)) {
    CHECK2(val->type == ETYPE_ARRAY, EIP712ERR_ENCODE_ADDRESS);

    e_item *it = val->value.data_struct;

    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    while (it) {
      CHECK(encode_address(it, encoded));
      keccak_update(&ctx, encoded, EIP712_HASH_SIZE);
      it = it->sibling;
    }
    keccak_final(&ctx, encoded);
  } else {
    encode_address(val, encoded);
  }

  return EIP712_SUC;
}

int encode_string(e_item *it, uint8_t *encoded) {
  CHECK2(it->type == ETYPE_STRING, EIP712ERR_ENCODE_STRING);
  keccak_256((const uint8_t *)it->value.data_string,
             (size_t)strlen(it->value.data_string), encoded);
  return EIP712_SUC;
}

int parse_string(e_item *val, const char *type, uint8_t *encoded) {
  if (is_array(type)) {
    CHECK2(val->type == ETYPE_ARRAY, EIP712ERR_ENCODE_STRING);

    e_item *it = val->value.data_struct;
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    while (it) {
      CHECK(encode_string(it, encoded));
      keccak_update(&ctx, encoded, EIP712_HASH_SIZE);
      it = it->sibling;
    }
    keccak_final(&ctx, encoded);
  } else {
    encode_string(val, encoded);
  }

  return EIP712_SUC;
}

int parse_int(e_item *val, const char *type, uint8_t *encoded) {
  CHECK2(!is_array(type), EIP712ERR_ENCODE_INT);

  memcpy(encoded, val->value.data_number, EIP712_HASH_SIZE);
  return EIP712_SUC;
}

int parse_bytes(e_item *val, const char *type, uint8_t *encoded) {
  CHECK2(!is_array(type), EIP712ERR_ENCODE_BYTES);
  // TODO need check type

  if (strcmp(type, "bytes") == 0) {
    ASSERT(false);  // TODO temporarily unavailable
    return EIP712ERR_ENCODE_UNKNOW;
  } else {
    size_t wide = str_to_int(type + 5);
    CHECK2(wide <= EIP712_HASH_SIZE, EIP712ERR_ENCODE_BYTES);
    memset(encoded, 0, EIP712_HASH_SIZE);
    memcpy(encoded + EIP712_HASH_SIZE - wide, val->value.data_number, wide);
  }

  return EIP712_SUC;
}

int parse_bool(e_item *val, const char *type, uint8_t *encoded) {
  CHECK2(val->type != ETYPE_BOOL, EIP712ERR_ENCODE_BOOL);
  CHECK2(is_array(type), EIP712ERR_ENCODE_BOOL);

  if (val->value.data_bool) {
    encoded[31] = 0x1;
  }

  return EIP712_SUC;
}

int encode_struct(e_item *val, e_item *types, const char *type,
                  uint8_t *encoded) {
  struct SHA3_CTX val_ctx = {0};
  keccak_init(&val_ctx);
  keccak_update(&val_ctx, encoded, EIP712_HASH_SIZE);
  e_item *type_info = get_item(types, type);
  CHECK2(!type_info, EIP712ERR_ENCODE_STRUCT);

  parse_vals(type_info, val, types, &val_ctx);

  keccak_final(&val_ctx, encoded);
  return EIP712_SUC;
}

int get_type_hash(e_item *types, const char *type, uint8_t *encoded) {
  char enc_sub_type_str[EIP712_TYPE_STR_BUF_MAX_SIZE] = {0};
  size_t out_str_len = sizeof(enc_sub_type_str);
  if (is_array(type)) {
    char real_type[EIP712_STRING_TYPE_MAX_SIZE] = {0};
    memcpy(real_type, type, strlen(type) - 2);
    CHECK(parse_type(types, real_type, enc_sub_type_str, &out_str_len));
  } else {
    CHECK(parse_type(types, type, enc_sub_type_str, &out_str_len));
  }
  printf("------parse struct , type encode: %s\n", enc_sub_type_str);

  keccak_256((const uint8_t *)enc_sub_type_str, out_str_len, encoded);
  return EIP712_SUC;
}

int parse_struct(e_item *val, e_item *types, const char *type,
                 uint8_t *encoded) {
  CHECK(get_type_hash(types, type, encoded));

  if (is_array(type)) {
    uint8_t struct_hash[EIP712_HASH_SIZE] = {0};
    memcpy(struct_hash, encoded, EIP712_HASH_SIZE);

    char real_type[EIP712_STRING_TYPE_MAX_SIZE] = {0};
    memcpy(real_type, type, strlen(type) - 2);
    e_item *it = val->value.data_struct;
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    while (it) {
      struct SHA3_CTX val_ctx = {0};
      keccak_init(&val_ctx);
      keccak_update(&val_ctx, struct_hash, EIP712_HASH_SIZE);
      dbg_print_mem("------update struct hash1", struct_hash, EIP712_HASH_SIZE);

      e_item *type_info = get_item(types, real_type);
      CHECK2(type_info, EIP712ERR_ENCODE_STRUCT);
      parse_vals(type_info, it, types, &val_ctx);

      keccak_final(&val_ctx, encoded);

      // CHECK(encode_struct(it, types, real_type, encoded));
      keccak_update(&ctx, encoded, EIP712_HASH_SIZE);
      dbg_print_mem("------update struct hash2", encoded, EIP712_HASH_SIZE);
      it = it->sibling;
    }

    keccak_final(&ctx, encoded);
  } else {
    struct SHA3_CTX val_ctx = {0};
    keccak_init(&val_ctx);
    keccak_update(&val_ctx, encoded, EIP712_HASH_SIZE);

    e_item *type_info = get_item(types, type);
    CHECK2(type_info, EIP712ERR_ENCODE_STRUCT);

    parse_vals(type_info, val, types, &val_ctx);

    keccak_final(&val_ctx, encoded);
  }

  return EIP712_SUC;
}

int parse_val(e_item *val, e_item *types, const char *type,
              struct SHA3_CTX *ctx) {
  uint8_t encoded[EIP712_HASH_SIZE] = {0};
  if (type_cmp(type, "address")) {
    CHECK(parse_address(val, type, encoded));
  } else if (type_cmp(type, "string")) {
    CHECK(parse_string(val, type, encoded));
  } else if (type_cmp(type, "uint") || type_cmp(type, "int")) {
    CHECK(parse_int(val, type, encoded));
  } else if (type_cmp(type, "bytes")) {
    CHECK(parse_bytes(val, type, encoded));
  } else if (type_cmp(type, "bool")) {
    CHECK(parse_bool(val, type, encoded));
  } else {
    CHECK(parse_struct(val, types, type, encoded));
  }

  keccak_update(ctx, (unsigned char *)encoded, sizeof(encoded));
  printf("----type: %s\n", type);
  dbg_print_mem("----update-hash", encoded, EIP712_HASH_SIZE);

  return EIP712_SUC;
}

e_item *get_types_from_msg(e_item *types, e_item *val) {
  if (strcmp("domain", val->key) == 0) {
    return get_item(types, "EIP712Domain");
  }

  return get_item(types, val->key);
}

int parse_vals(e_item *type_info, e_item *data_msg, e_item *types,
               struct SHA3_CTX *ctx) {
  type_info = type_info->value.data_struct;
  while (type_info) {
    const char *item_type_name = get_item_tostr(type_info, "name");
    const char *item_type_type = get_item_tostr(type_info, "type");

    CHECK2(item_type_name || item_type_type, EIP712ERR_ENCODE_MESSAGE);

    e_item *it = get_item(data_msg, item_type_name);
    CHECK2(it, EIP712ERR_ENCODE_MESSAGE);
    CHECK(parse_val(it, types, item_type_type, ctx));

    type_info = type_info->sibling;
  }

  return EIP712_SUC;
}

int encode_item(e_item *data, EIP712MessageType msg_type, uint8_t *hash_ret) {
  const char *type_name = NULL;
  e_item *data_msg = NULL;
  if (msg_type == EIP712_DOMAIN) {
    type_name = "EIP712Domain";
    data_msg = get_item(data, "domain");
  } else if (msg_type == EIP712_MESSAGE) {
    type_name = get_item_tostr(data, "primaryType");
    data_msg = get_item(data, "message");
  } else {
    CHECK(EIP712EER_INVALID_ARG);
  }
  CHECK2(type_name, EIP712ERR_ENCODE_TYPE);
  CHECK2(data_msg, EIP712ERR_ENCODE_TYPE);
  CHECK2(type_name, EIP712ERR_ENCODE_TYPE);

  e_item *types = get_item(data, "types");

  uint8_t type_hash[EIP712_HASH_SIZE] = {0};
  get_type_hash(types, type_name, type_hash);

  // get hash
  // They typehash must be the first message of the final hash, this is the
  // start
  struct SHA3_CTX keccak_ctx = {0};
  keccak_init(&keccak_ctx);
  keccak_update(&keccak_ctx, (unsigned char *)type_hash, sizeof(type_hash));
  dbg_print_mem("----update-hash1", type_hash, sizeof(type_hash));

  e_item *type_info = get_item(types, type_name);
  CHECK2((type_info && type_info->type == ETYPE_ARRAY),
         EIP712ERR_ENCODE_MESSAGE);

  parse_vals(type_info, data_msg, types, &keccak_ctx);

  keccak_final(&keccak_ctx, hash_ret);

  return EIP712_SUC;
}

int encode(e_item *data, uint8_t *hash_ret) {
  uint8_t hash_buffer[2 + EIP712_HASH_SIZE + EIP712_HASH_SIZE] = {0x19, 0x01,
                                                                  0};

  CHECK(encode_item(data, EIP712_DOMAIN, hash_buffer + 2));
  dbg_print_mem("--domain data hash", hash_buffer + 2, EIP712_HASH_SIZE);
  CHECK(encode_item(data, EIP712_MESSAGE, hash_buffer + 2 + EIP712_HASH_SIZE));
  dbg_print_mem("--message data hash", hash_buffer + 2 + EIP712_HASH_SIZE,
                EIP712_HASH_SIZE);

  keccak_256(hash_buffer, sizeof(hash_buffer), hash_ret);

  dbg_print_mem("--befor data hash", hash_ret, EIP712_HASH_SIZE);
  return EIP712_SUC;
}

#undef APPEND_STR

////////////////////////////////////////////////////////////////
// debug

char i_to_str(uint8_t d) {
  if (d >= 0 && d <= 9) {
    return '0' + d;
  } else {
    return 'A' + d - 0xa;
  }
}

void uint8_to_hex(uint8_t d, char *out) {
  out[0] = i_to_str(d >> 4);
  out[1] = i_to_str(d & 0xF);
}

void dbg_print_mem(const char *name, const uint8_t *buf, size_t len) {
  char output_buf[1024 * 4] = {0};
  size_t buf_pos = 0;

  buf_pos = append_str(output_buf, buf_pos, name);
  buf_pos = append_str(output_buf, buf_pos, ":\n");

  for (size_t i = 0; i < len; i++) {
    buf_pos = append_str(output_buf, buf_pos, "0x");
    uint8_to_hex(buf[i], output_buf + buf_pos);
    buf_pos += 2;
    buf_pos = append_str(output_buf, buf_pos, ", ");

    if (i % 16 == 15) {
      buf_pos = append_str(output_buf, buf_pos, "\n");
    }
  }

  printf("%s", output_buf);
}
