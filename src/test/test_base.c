// #include <assert.h>

#include "eip712.h"

int test_base() {
  return test_eip712();
  // return test_eip712_2();
}

int main() {
  int ref = test_base();
  if (ref) return ref;
  return 0;
}