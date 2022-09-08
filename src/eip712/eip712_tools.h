
/*
 * Copyright (c) 2022 markrypto  (cryptoakorn@gmail.com)
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
    Produces hashes based on the metamask v4 rules. This is different from the
   EIP-712 spec in how arrays of structs are hashed but is compatable with
   metamask. See https://github.com/MetaMask/eth-sig-util/pull/107

    eip712 data rules:
    Parser wants to see C strings, not javascript strings:
        requires all complete json message strings to be enclosed by braces,
   i.e., { ... } Cannot have entire json string quoted, i.e., "{ ... }" will not
   work. Remove all quote escape chars, e.g., {"types":  not  {\"types\": int
   values must be hex. Negative sign indicates negative value, e.g., -5, -8a67
        Note: Do not prefix ints or uints with 0x
    All hex and byte strings must be big-endian
    Byte strings and address should be prefixed by 0x
*/
#ifndef EIP712_H
#define EIP712_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STRBUFSIZE 511

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

void keccak_256(const uint8_t *buf, size_t buf_len, uint8_t *result);

void output_item(e_item *it);

int encode_2(e_item *data, uint8_t *hashRet);

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
// assert(cond);

typedef enum {
  EIP712_SUC = 0,
  EIP712EER_INVALID_ARG,
  EIP712ERR_ENCODE_TYPE,
  EIP712ERR_ENCODE_ADDRESS,
  EIP712ERR_ENCODE_STRING,
  EIP712ERR_ENCODE_INT,
  EIP712ERR_ENCODE_BOOL,
  EIP712ERR_ENCODE_STRUCT,
  EIP712ERR_ENCODE_BYTES,
  EIP712ERR_ENCODE_MESSAGE,

  EIP712ERR_ENCODE_UNKNOW,
} EIP712RcCode;

void dbg_print_mem(const char *name, const uint8_t *buf, size_t len);

#endif
