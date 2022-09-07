

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "eip712/sim_include/keepkey/firmware/eip712_tools.h"

// memory manager

e_mem eip712_gen_mem(uint8_t *buffer, size_t len) {
  e_mem m;
  m.buffer = buffer;
  m.buffer_len = len;
  m.pos = 0;
  return m;
}

void *eip712_alloc(e_mem *mem, size_t len) {
  if (mem->buffer_len < len + mem->pos) {
    assert(false);
  }

  void *ret = mem->buffer + mem->pos;
  mem->pos += len;

  memset(ret, 0, len);

  return ret;
}

// eip712_tree

e_item *gen_item_struct(e_mem *mem, e_item *parent, const char *key,
                        e_item *item) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = key;
  it->type = ETYPE_STRUCT;
  it->value.data_struct = item;

  append_item(parent, it);
  return it;
}

void append_item(e_item *parent, e_item *child) {
  if (!parent) return;
  assert(parent->type == ETYPE_STRUCT || parent->type == ETYPE_ARRAY);
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
  it->key = key;
  it->type = ETYPE_STRING;
  it->value.data_string = val;

  append_item(parent, it);
  return it;
}

e_item *gen_item_array(e_mem *mem, e_item *parent, const char *key) {
  e_item *it = eip712_alloc(mem, sizeof(e_item));
  it->key = key;
  it->type = ETYPE_ARRAY;

  append_item(parent, it);
  return it;
}

e_item *get_item(e_item *it, const char *name) {
  if (it == NULL) return NULL;
  assert(it->type == ETYPE_STRUCT);

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

void output_item(e_item *it) {
  printf("{");
  if (it) {
    it = it->value.data_struct;
    while (it) {
      if (it->key) printf("\"%s\": ", it->key);

      if (it->type == ETYPE_STRING) {
        printf("\"%s\"", it->value.data_string);
      }
      if (it->type == ETYPE_STRUCT) {
        printf("\n");
        output_item(it);
      }
      if (it->type == ETYPE_ARRAY) {
        printf("[\n");
        e_item *itt = it->value.data_struct;
        while (itt) {
          output_item(itt);
          if (itt->sibling) printf(",\n");
          itt = itt->sibling;
        }
        printf("]\n");
      }
      if (it->sibling) printf(",\n");
      it = it->sibling;
    }
  }
  printf("}\n");
}

size_t append_str(char *buf, size_t pos, const char *s) {
  size_t str_len = strlen(s);
  memcpy(buf + pos, s, str_len);
  return pos + str_len;
}

// encode

const char *G_EIP712_DEFALUT_TYPE[] = {
    "int8",   "int16",   "int32",  "int64",  "int128",  "int256",
    "uint8",  "uint16",  "uint32", "uint64", "uint128", "uint256",
    "bytes1", "bytes2",  "bytes4", "bytes8", "bytes16", "bytes32",
    "bool",   "address", "string", "bytes",
};

bool is_def_type(const char *t) {
  for (size_t i = 0; i < sizeof(G_EIP712_DEFALUT_TYPE) / sizeof(int *); i++) {
    if (strcmp(t, G_EIP712_DEFALUT_TYPE[i]) == 0) return true;
  }
  return false;
}

typedef struct _eip712_type_deps_item {
  const char *item_type;
  struct _eip712_type_deps_item *next;
} eip712_type_deps_item;

bool type_deps_list_has(eip712_type_deps_item *begin, const char *type_name) {
  for (eip712_type_deps_item *it = begin; it; it = begin->next) {
    if (strcmp(type_name, it->item_type) == 0) {
      return true;
    }
  }
  return false;
}

int parse_type_2(e_item *types, const char *type_name, char *type_str,
                 size_t *readed_pos) {
  if (types->type != ETYPE_STRUCT) {
    return 1;  // TODO ret err
  }
  e_item *it = get_item(types, type_name);
  if (!it || it->type != ETYPE_ARRAY) {
    return 1;  // TODO
  }

  size_t pos = 0;

#define APPEND_STR(data) pos = append_str(type_str, pos, data)

  APPEND_STR(it->key);
  APPEND_STR("(");

  it = it->value.data_struct;

  const char *item_name;
  const char *item_type;
  const char *item_type_name;

  uint8_t mem_buffer[1024 * 2] = {0};
  e_mem mem = eip712_gen_mem(mem_buffer, sizeof(mem_buffer));

  eip712_type_deps_item *deps_type = NULL;
  eip712_type_deps_item *cur_deps = NULL;

  assert(it->type == ETYPE_STRUCT);
  while (it) {
    e_item *itt = it->value.data_struct;

    while (itt) {
      if (strcmp("name", itt->key) == 0)
        item_name = itt->value.data_string;
      else if (strcmp("type", itt->key) == 0) {
        item_type = itt->value.data_string;
        size_t it_type_len = strlen(item_type);

        if (item_type[it_type_len - 1] == ']') {
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
    if (parse_type_2(types, cur_deps->item_type, type_str + pos, &deps_pos) !=
        0) {
      return 1;  // TODO
    }
    pos += deps_pos;
    cur_deps = cur_deps->next;
  }

  *readed_pos = pos;
  return 0;
#undef APPEND_STR
}

int encode_item(e_item *types, e_item *data, const char *type_name,
                uint8_t *hash_ret) {
  char enc_type_str[STRBUFSIZE + 1] = {0};
  int errRet;

  size_t type_str_out_len = 0;
  if (0 != (errRet = parse_type_2(types, type_name, enc_type_str,
                                  &type_str_out_len))) {
    return errRet;
  }
  uint8_t type_hash[32] = {0};
  keccak_256((const uint8_t *)enc_type_str, (size_t)strlen(enc_type_str),
             type_hash);
  printf("TypeName: %s\nTypeEncode:%s\n", type_name, enc_type_str);

  // get hash
  // They typehash must be the first message of the final hash, this is the
  // start

  // keccak_init(&finalCtx);
  // keccak_update(&finalCtx, (unsigned char *)typeHash,
  // (size_t)sizeof(typeHash));

  if (0 == strncmp(type_name, "EIP712Domain", sizeof("EIP712Domain"))) {
    confirmProp = DOMAIN;
    domOrMsgStr = "domain";
  } else {
    // This is the message value encoding
    confirmProp = MESSAGE;
    domOrMsgStr = "message";
  }
  if (NULL == (domainOrMessageProp = json_getProperty(
                   jsonVals, domOrMsgStr))) {  // "message" or "domain" property
    if (confirmProp == DOMAIN) {
      errRet = JSON_DPROPERR;
    } else {
      errRet = JSON_MPROPERR;
    }
    return errRet;
  }
  if (NULL ==
      (valsProp = json_getChild(
           domainOrMessageProp))) {  // "message" or "domain" property values
    if (confirmProp == MESSAGE) {
      errRet = NULL_MSG_HASH;  // this is legal, not an error.
      return errRet;
    }
  }

  if (SUCCESS !=
      (errRet = parseVals(typesProp, typeSprop, valsProp, &finalCtx))) {
    return errRet;
  }

  keccak_final(&finalCtx, hashRet);
  // clear typeStr
  memzero(encTypeStr, sizeof(encTypeStr));

  return 0;
}

int encode_2(e_item *data, uint8_t *hash_ret) {
  e_item *types = get_item(data, "types");
  e_item *domain = get_item(data, "domain");
  e_item *message = get_item(data, "message");
  const char *primary_type = get_item_tostr(data, "primaryType");

  uint8_t hash_buffer[2 + 32 + 32] = {0};
  hash_buffer[0] = 0x19;
  hash_buffer[1] = 0x01;

  int ret = encode_item(types, domain, "EIP712Domain", hash_buffer + 2);
  if (ret) return ret;

  ret = encode_item(types, message, primary_type, hash_buffer + 2 + 32);
  if (ret) return ret;

  keccak_256(hash_buffer, sizeof(hash_buffer), hash_ret);
  return 0;
}
