## Violation Witnesses as Declarative Test Harnesses

A test vector is a sequence of input values provided to a system in order to test that system.
A verification tool that detects a feasible concrete path through a system to a specification violation often can provide a test vector such that testing the system with these input values triggers the dected bug.
The exchange format for witnesses can be used to express test vectors in the form of declarative test harnesses.
A witness validator may transform such a declarative test harness into an imperative test harness in the input language, and then compile and link the original source code against it.
If running the resulting executable triggers the bug, the witness is valid.
This executable can then directly be inspected by the developers using a debugger to reproduce and understand the bug in their own system.

### Requirements

A violation witness must fulfill the following requirement to qualify as a test vector:
For each input into the system along the path to be tested, the witness must provide a concrete value.

### Examples

The following examples conform to the format used in the [International Competition on Software Verification (SV-COMP)](https://sv-comp.sosy-lab.org/), where the function ``extern int __VERIFIER_nondet_int(void)`` is used to obtain nondeterministic input values and the specification ``CHECK( init(main()), LTL(G ! call(__VERIFIER_error())) )`` states that a correct program must never call the function ``extern int __VERIFIER_error(void)``.

## Example 1

As a first example, consider the following [C program](example-1.i) (``example-1.i``):

```C
extern void __VERIFIER_error(void);
extern int __VERIFIER_nondet_int(void);
int main() {
  unsigned int x = 1;
  while(__VERIFIER_nondet_int()) {
    x = x + 2;
  }
  if (x >= 1) __VERIFIER_error();
}
```
Obviously, ``x`` is always greater than or equal to ``1``, and the shortest path to the violation of the specification skips the loop immediately if the first call to the input function ``extern int __VERIFIER_nondet_int(void)`` evaluates to ``0``.
The following [violation witness](example-1-witness.graphml) (``example-1-witness.graphml``) for this verification task qualifies as a declarative test harness by providing the test vector for the shortest error path:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <key attr.name="isEntryNode" attr.type="boolean" for="node" id="entry">
  <default>false</default>
 </key>
 <key attr.name="isViolationNode" attr.type="boolean" for="node" id="violation">
  <default>false</default>
 </key>
 <key attr.name="witness-type" attr.type="string" for="graph" id="witness-type"/>
 <key attr.name="sourcecodelang" attr.type="string" for="graph" id="sourcecodelang"/>
 <key attr.name="producer" attr.type="string" for="graph" id="producer"/>
 <key attr.name="specification" attr.type="string" for="graph" id="specification"/>
 <key attr.name="programFile" attr.type="string" for="graph" id="programfile"/>
 <key attr.name="programHash" attr.type="string" for="graph" id="programhash"/>
 <key attr.name="memoryModel" attr.type="string" for="graph" id="memorymodel"/>
 <key attr.name="architecture" attr.type="string" for="graph" id="architecture"/>
 <key attr.name="startline" attr.type="int" for="edge" id="startline"/>
 <key attr.name="assumption" attr.type="string" for="edge" id="assumption"/>
 <key attr.name="assumption.scope" attr.type="string" for="edge" id="assumption.scope"/>
 <key attr.name="assumption.resultfunction" attr.type="string" for="edge" id="assumption.resultfunction"/>
<graph edgedefault="directed">
  <data key="witness-type">violation_witness</data>
  <data key="sourcecodelang">C</data>
  <data key="producer">CPAchecker 1.6.1-svn</data>
  <data key="specification">CHECK( init(main()), LTL(G ! call(__VERIFIER_error())) )</data>
  <data key="programfile">example-1.i</data>
  <data key="programhash">1776ed2413d170f227b69d8c79ba700d31db6f75</data>
  <data key="memorymodel">precise</data>
  <data key="architecture">32bit</data>
  <node id="entry">
   <data key="entry">true</data>
  </node>
  <node id="error">
   <data key="violation">true</data>
  </node>
  <edge source="entry" target="error">
   <data key="startline">5</data>
   <data key="assumption">\result == 0</data>
   <data key="assumption.scope">main</data>
   <data key="assumption.resultfunction">__VERIFIER_nondet_int</data>
  </edge>
 </graph>
</graphml>
```

A witness validator may now produce a test harness.
For example, you can use [CPAchecker](http://cpachecker.sosy-lab.org) to produce the test harness:

``scripts/cpa.sh -generate-test-harness -spec test/programs/benchmarks/PropertyERROR.prp -spec example-1-witness.graphml example-1.i``

CPAchecker produces the following [test harness](example-1-harness.c) (``example-1-harness.c``) for this example:

```C
#include <stdlib.h>
void __VERIFIER_error(void) { exit(EXIT_FAILURE); }
void __VERIFIER_assume(int cond) { if (!(cond)) { exit(EXIT_SUCCESS); }}
int __VERIFIER_nondet_int() {
  int retval;
  retval = 0;
  return retval;
}
```

Now, an executable can be produced by running ``gcc example-1.i example-1-harness.c -o example-1``.
Running ``./example-1 || echo 'Failure'`` immediately shows that the executable returns the status code ``EXIT_FAILURE``:

``Failure``

If the validator is trusted, this indicates that even if the witness ``example-1-witness.graphml`` is valid even if was obtained from an untrusted source.
If the executable ``example-1`` or the imperative test harness ``example-1-harness.c`` were obtained directly from the untrusted source, no such guarantee about the validity would be possible without laborious manual inspection, because the executable may have been produced from altered source code, or imperative the test harness may itself violate the specification.

## Example 2

As a second example, consider the following [C program](example-2.i) (``example-2.i``):

```C
extern void __VERIFIER_error(void);
extern int __VERIFIER_nondet_int(void);
int main() {
  unsigned int x = 1;
  if (__VERIFIER_nondet_int()) {
    x++;
  }
  if (__VERIFIER_nondet_int()) {
    x += __VERIFIER_nondet_int();
  }
  if (x == 42) __VERIFIER_error();
}
```
For the call to the ``__VERIFIER_error`` function in line 11 to be executed, ``x`` must be equal to ``42`` at that location.
There are two possible paths that satisfy this condition:

1. The first input value is non-zero, and the condition in line 5 holds and ``x`` is incremented from ``1`` to ``2`` in line 6. Then, the second input value must be non-zero so that the condition in line 8 holds, and the third input value in line 9 must be ``40`` to increase ``x`` from ``2`` to ``42``.
2. The first input value is zero, and the condition in line 5 does not hold. Then, the second input value must be non-zero so that the condition in line 8 holds, and the third input value in line 9 must be ``41`` to increase ``x`` from ``1`` to ``42``.

The following [violation witness](example-2-witness.graphml) (``example-2-witness.graphml``) for this verification task qualifies as a declarative test harness by providing the test vector for the error path described in scenario 1):

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <key attr.name="isViolationNode" attr.type="boolean" for="node" id="violation">
  <default>false</default>
 </key>
 <key attr.name="isEntryNode" attr.type="boolean" for="node" id="entry">
  <default>false</default>
 </key>
 <key attr.name="witness-type" attr.type="string" for="graph" id="witness-type"/>
 <key attr.name="sourcecodeLanguage" attr.type="string" for="graph" id="sourcecodelang"/>
 <key attr.name="producer" attr.type="string" for="graph" id="producer"/>
 <key attr.name="specification" attr.type="string" for="graph" id="specification"/>
 <key attr.name="programFile" attr.type="string" for="graph" id="programfile"/>
 <key attr.name="programHash" attr.type="string" for="graph" id="programhash"/>
 <key attr.name="memoryModel" attr.type="string" for="graph" id="memorymodel"/>
 <key attr.name="architecture" attr.type="string" for="graph" id="architecture"/>
 <key attr.name="startline" attr.type="int" for="edge" id="startline"/>
 <key attr.name="assumption" attr.type="string" for="edge" id="assumption"/>
 <key attr.name="assumption.scope" attr.type="string" for="edge" id="assumption.scope"/>
 <key attr.name="assumption.resultfunction" attr.type="string" for="edge" id="assumption.resultfunction"/>
 <graph edgedefault="directed">
  <data key="witness-type">violation_witness</data>
  <data key="sourcecodelang">C</data>
  <data key="producer">CPAchecker 1.6.1-svn</data>
  <data key="specification">CHECK( init(main()), LTL(G ! call(__VERIFIER_error())) )</data>
  <data key="programfile">/home/dangl/markdown-playground/example-2.i</data>
  <data key="programhash">cc0781266d4318110314aec0622d0a968991daaf</data>
  <data key="memorymodel">precise</data>
  <data key="architecture">32bit</data>
  <node id="entry">
   <data key="entry">true</data>
  </node>
  <node id="error">
   <data key="violation">true</data>
  </node>
  <node id="q1"/>
  <edge source="entry" target="q1">
   <data key="startline">5</data>
   <data key="assumption">\result == 2</data>
   <data key="assumption.scope">main</data>
   <data key="assumption.resultfunction">__VERIFIER_nondet_int</data>
  </edge>
  <node id="q2"/>
  <edge source="q1" target="q2">
   <data key="startline">8</data>
   <data key="assumption">\result == 524800</data>
   <data key="assumption.scope">main</data>
   <data key="assumption.resultfunction">__VERIFIER_nondet_int</data>
  </edge>
  <edge source="q2" target="error">
   <data key="startline">9</data>
   <data key="assumption">\result == 40</data>
   <data key="assumption.scope">main</data>
   <data key="assumption.resultfunction">__VERIFIER_nondet_int</data>
  </edge>
 </graph>
</graphml>
```

A witness validator may now produce a test harness.
For example, you can use [CPAchecker](http://cpachecker.sosy-lab.org) to produce the test harness:

``scripts/cpa.sh -generate-test-harness -spec test/programs/benchmarks/PropertyERROR.prp -spec example-2-witness.graphml example-2.i``

CPAchecker produces the following [test harness](example-2-harness.c) (``example-2-harness.c``) for this example:

```C
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
```

Now, an executable can be produced by running ``gcc example-2.i example-2-harness.c -o example-2``.
Running ``./example-2 || echo 'Failure'`` immediately shows that the executable returns the status code ``EXIT_FAILURE``:

``Failure``

