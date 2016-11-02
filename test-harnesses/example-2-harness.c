#include <stdlib.h>
void __VERIFIER_error(void) { exit(EXIT_FAILURE); }
void __VERIFIER_assume(int cond) { if (!(cond)) { exit(EXIT_SUCCESS); }}
unsigned int __VERIFIER_nondet_int_index__ = 0;
int __VERIFIER_nondet_int() {
  int retval;
  switch (__VERIFIER_nondet_int_index__) {
    case 0: retval = 2; break;
    case 1: retval = 524800; break;
    case 2: retval = 40; break;
  }
  ++__VERIFIER_nondet_int_index__;
  return retval;
}
