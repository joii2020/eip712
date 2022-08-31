
#ifndef _SRC_EIP712_H_
#define _SRC_EIP712_H_

typedef struct _eip712_data {
} eip712_data;

void init_eip712(eip712_data *data);

#define GEN_EIP712_DATA(data, type, primary_type, domain, message) \
  eip712_data ##data;                                               \
  init_eip712(&(##data));

#define GEN_EIP712_TYPE()

#define GEN_EIP712_DOMAIN()

#define GEN_EIP712_MESSAGE()

#endif  // _SRC_EIP712_H_
