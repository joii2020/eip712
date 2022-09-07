#include <assert.h>

#include "eip712.h"

int test_base() {
#if 0
  return test_eip712();
#else
  return test_eip712_2();
#endif
}

int main() {
  int ref = test_base();
  if (ref) return ref;
  return 0;
}