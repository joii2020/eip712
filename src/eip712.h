
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

// Test inc
int test_eip712();

int test_eip712_2();

#endif  // _SRC_EIP712_H_
