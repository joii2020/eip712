
#ifndef _SRC_EIP712_H_
#define _SRC_EIP712_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct _eip712_domain {
  uint8_t chain_id[32];
  char* name;
  uint8_t* verifying_contract;
  char* version;
} eip712_domain;

typedef struct _eip712_active {
  char* action;
  char* params;
} eip712_active;

typedef struct _eip712_data {
  eip712_domain doamin;
  eip712_active active;
  char* cell_extra_data;
  char* transaction_das_message;
} eip712_data;

int get_eip712_hash(eip712_data* data, uint8_t* out_hash);

// Get eip712 template
//    out_data      : buffer of output data; the data is json
//    out_data_len  : input out_data length, and output it length
//    Result        : if success is 0
int get_eip712_template(char* out_data, size_t* out_data_len);

// Get hash of domain
int get_eip712_domain_hash(const char* data, size_t len, uint8_t* hash);

// Get hash of message
int get_eip712_message_hash(const char* data, size_t len, uint8_t* hash);

#endif  // _SRC_EIP712_H_
