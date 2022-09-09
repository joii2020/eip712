
#ifndef EIP712_H
#define EIP712_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(err)                                                        \
  {                                                                       \
    int _err = err;                                                       \
    if (_err) {                                                           \
      printf("--CHECK ERR, code: %d, %s:%d\n", _err, __FILE__, __LINE__); \
      return _err;                                                        \
    }                                                                     \
  }

#define CHECK2(cond, rc_code)                                                 \
  {                                                                           \
    bool flag = cond;                                                         \
    if (flag) {                                                               \
      printf("--CHECK2 ERR, code: %d, %s:%d\n", rc_code, __FILE__, __LINE__); \
      return rc_code;                                                         \
    }                                                                         \
  }

#define ASSERT(cond)                                 \
  if (!(cond)) {                                     \
    printf("--Assert, %s:%d\n", __FILE__, __LINE__); \
    (void)0;                                         \
  }

typedef enum {
  ETYPE_BYTES1,
  ETYPE_BYTES2,
  ETYPE_BYTES4,
  ETYPE_BYTES8,
  ETYPE_BYTES16,
  ETYPE_BYTES32,

  ETYPE_UINT8,
  ETYPE_UINT16,
  ETYPE_UINT32,
  ETYPE_UINT64,
  ETYPE_UINT128,
  ETYPE_UINT256,

  ETYPE_INT8,
  ETYPE_INT16,
  ETYPE_INT32,
  ETYPE_INT64,
  ETYPE_INT128,
  ETYPE_INT256,

  ETYPE_BOOL,
  ETYPE_ADDRESS,
  ETYPE_BYTES,
  ETYPE_STRING,
  ETYPE_STRUCT,
  ETYPE_ARRAY,
} e_type;

typedef union _e_item_value {
  uint8_t *data_number;  // bytesx, uintx, intx, address,
  bool data_bool;
  struct {
    uint8_t *data;
    size_t len;
  } data_bytes;
  const char *data_string;
  struct _e_item *data_struct;
} e_item_value;

typedef struct _e_item {
  const char *key;
  e_item_value value;
  e_type type;

  struct _e_item *sibling;
} e_item;

typedef struct _e_mem {
  uint8_t *buffer;
  size_t buffer_len;
  size_t pos;
} e_mem;

e_mem eip712_gen_mem(uint8_t *buffer, size_t len);
void *eip712_alloc(e_mem *mem, size_t len);

e_item *gen_item_struct(e_mem *mem, e_item *parent, const char *key,
                        e_item *item);
void append_item(e_item *parent, e_item *child);
e_item *gen_item_string(e_mem *mem, e_item *parent, const char *key,
                        const char *val);
e_item *gen_item_mem_by_str(e_mem *mem, e_item *parent, const char *key,
                            const char *val, e_type type);
e_item *gen_item_mem(e_mem *mem, e_item *parent, const char *key,
                     const uint8_t *val, size_t val_size, e_type type);
e_item *gen_item_num(e_mem *mem, e_item *parent, const char *key,
                     const char *val, e_type type);

e_item *gen_item_array(e_mem *mem, e_item *parent, const char *key);

e_item *get_item(e_item *it, const char *name);
const char *get_item_tostr(e_item *it, const char *name);

// eip712 struct to json string
void output_item(e_item *it);

// eip712 encode to hash
int encode(e_item *data, uint8_t *hashRet);

#endif
