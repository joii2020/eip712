#include "eip712.h"


void test() {
  GEN_EIP712_DATA(ddd, GEN_EIP712_TYPE(), "Mail", GEN_EIP712_DOMAIN(),
                  GEN_EIP712_MESSAGE());
}