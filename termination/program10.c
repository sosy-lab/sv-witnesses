extern void __assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern void __assert_perror_fail (int __errnum, const char *__file,
      unsigned int __line, const char *__function)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));
extern void __assert (const char *__assertion, const char *__file, int __line)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__noreturn__));

extern int __VERIFIER_nondet_int();
void main()
{
  int x;
  int y;
  if(x<=0)
  {
    return;
  }
  while(x>10)
  {
    x=__VERIFIER_nondet_int();
    y=x;
    if(x<2)
    {
      exit(0);
    }
    while(y>0)
    {
      y--;
    }
    ((y==0) ? (void) (0) : __assert_fail ("y==0", "nontermination_witness_test/program10.c", 30, __PRETTY_FUNCTION__));
  }
}

