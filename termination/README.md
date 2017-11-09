## Violation Witnesses for Termination

A violation witness for termination describes an infinite execution path of the program. However, it needs not be precise and may represent more paths than the single infinite execution path. A violation witness consists of two connected parts: the *stem* and the *loop*. The stem outlines how to reach the loop. The loop characterizes which program statements are executed infinitely often. Note that the loop need not, but of course may, correspond to a loop in the program. The simplest form of the loop is a lasso, a sequence of program statements executed repeatedly infinitely often. More complex loop descriptions may also contain branching structures or nested loops. To substantiate the infiniteness of the loop, the witness contains a description of a *recurrent set* for the loop's entry point (visited infinitely often). The recurrent set should ensure that when an execution reaches the loop entry point being in a state of the recurrent set than every future visit of the loop entry point of that execution also belongs to the recurrent set.

### Exchange Format
The witness exchange format is similar to the [standard violation witness format](../README.md). In the following, we explain the differences and give some examples.

#### Graph Data and Edge Data for Witness Automata

The graph and edge data is the same as in the [standard violation witness format](../README.md). The typical value for the specification key is ``CHECK( init(main()), LTL(F end) )``. Furthermore, note that assumptions on loop edges are only allowed to restrict non-determinism---currently in case of a variable declaration ``var`` without initialization or when assigning the result of a call to an external function to variable ``var``---and the assumption must be a single, valid C expression of the form ``var==expr``.  However, our witness parser does not enforce this restriction. Instead, the validator will fail to confirm such witnesses.

#### Node Data for Witness Automata

Next to the node data in the [standard violation witness format](../README.md), termination violation witnesses require additional node data. First, the node separating stem and loop must be marked in the witness by the ``cyclehead`` key. Second, we allow invariants, which are not allowed for standard violation witnesses. The most use case for invariants is the description of the recurrent set. Thus, a node for which the cyclehead key is set, must also contain an invariant description.

"Description of additional node data"

| key | Meaning |
| --- | --- |
| cyclehead | *Valid values*: ``false`` (default) or ``true``</br> This state connects stem and loop, i.e., the key marks the separation of stem and loop. It should be reachable from every non-sink node in the loop. Only exactly one such state is allowed.| 
| invariant | *Valid values*: as in the standard format </br> The recurrent set is described an invariant. Additionally, it may be used in the loop part of the witness to provide invariants for program loops. Invariants provided for the stem are likely ignored. |

For the description of the remaining node data, we refer to the [standard violation witness format](../README.md).

#### Example 1
We start with a simple example, the program ``Ex02_false-termination_true-no-overflow.c`` shown below.

```C
extern int __VERIFIER_nondet_int(void);

int main() 
{
    int i;
    i = __VERIFIER_nondet_int();
    
    while (i > 0) 
		{
        if (i != 5) 
				{
            i = i-1;
        }
    }
    
    return 0;
}
```

The following witness ``Ex02_false-termination_true-no-overflow.c_witness.graphml`` is created manually and demonstrates the mandatory concepts of a termination violation witness. It starts with the witness metadata (the graph data of the exchange format). The stem starts in the entry node A1, enters the main function, and ends at the loop head (graph node A5). To mark the end of the stem and the beginning of the loop node A5 sets the cyclehead key to true. Additionally, the invariant at node A5 describes the recurrent set. The loop part of the witness corresponds to the while loop (body). 

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 [...]
 <graph edgedefault="directed">
  <data key="witness-type">violation_witness</data>
  <data key="sourcecodelang">C</data>
  <data key="producer">HUMAN</data>
  <data key="specification">CHECK( init(main()), LTL(F end) )</data>
  <data key="programfile">Ex02_false-termination_true-no-overflow.c</data>
  <data key="programhash">415986e62fd4d8c762d30906d2737401bd104fcd</data>
  <data key="architecture">32bit</data>
  <data key="creationtime">2017-11-08T08:11:33+01:00</data>
  <node id="A1">
   <data key="label">A1</data>
   <data key="entry">true</data>
  </node>
  <node id="A5_4_1">
   <data key="label">A5_4_1</data>
  </node>
  <edge source="A1" target="A5_4_1">
   <data key="enterFunction">main</data>
  </edge>
  <node id="A5">
   <data key="label">A5</data>
   <data key="cyclehead">true</data>
   <data key="invariant">i == (5)</data>
  </node>
  <edge source="A5_4_1" target="A5">
   <data key="enterLoopHead">true</data>
  </edge>
  <node id="A16">
   <data key="label">A16</data>
  </node>
  <edge source="A5" target="A16">
   <data key="control">condition-true</data>
  </edge>
  <edge source="A16" target="A5">
   <data key="enterLoopHead">true</data>
  </edge>
 </graph>
</graphml>
```

The witness produced by CPAchecker for the same program can be found in the file ``Ex02_false-termination_true-no-overflow.c_witness_CPAchecker.graphml``. In contrast to the example above, the stem contains one loop unrolling and the loop description models the branching in the loop body explicitly. Additionally, the edges do not only use control keys, but also refer to where the control belongs to in the program. This restricts the applicability of the edges to specific statements in the program and makes the witness more precise. 



#### Example 2

Our second example looks at the more complex program ``program10.c`` (shown below). In this example, the witness has to deal with a nested loop, non-determinism in stem and loop part, and statements which cause the program to terminate when executed.
 
```C
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
```

The following witness, again manually written, defines the beginning of the outer while-loop as start of the witness's loop part. It needs to restrict the non-determinism of the external function call ``__VERIFIER_nondet_int()`` by assume data. Furthermore, it claims that from the recurrent set the if branch is not reachable when the non-determinism restriction is taken into account. Additionally, it provides an invariant candidate for the inner while-loop, since such invariants are not recomputed by the validator.

```xml
<graphml>
  <graph edgedefault="directed">
    <data key="witness-type">violation_witness</data>
    <data key="sourcecodelang">C</data>
    <data key="producer">HUMAN</data>
    <data key="specification">CHECK( init(main()), LTL(F end) )</data>
    <data key="programfile">program10.c</data>
    <data key="programhash">8e6bfda56fedb3679396ee32ec98e7b030f7f596</data>
    <data key="architecture">32bit</data>
    
    <node id="A0">
      <data key="entry">true</data>
    </node>
    <node id="A1"/>
    <edge source="A0" target="A1">
      <data key="enterFunction">main</data>
      <data key="startline">11</data>
      <data key="endline">11</data>
    </edge>
    <node id="A2"/>
    <edge source="A1" target="A2">
      <data key="control">condition-false</data>
    </edge>
    <node id="sink">
      <data key="sink">true</data>
    </node>
    <edge source="A2" target="sink">
      <data key="control">condition-true</data>
    </edge>
    <node id="A3">
      <!-- definition where stem ends and (infinite) loop starts -->
      <data key="cyclehead">true</data> 
      <!-- description of recurrent set -->
      <data key="invariant">x&gt;11</data> 
    </node>
    <edge source="A2" target="A3">
       <data key="enterLoopHead">true</data>
    </edge>     
    <node id="A4"/>
    <edge source="A3" target="A4">
      <data key="control">condition-true</data>
      <data key="startline">19</data>
      <data key="endline">19</data>
    </edge>
    <edge source="A3" target="sink">
      <data key="control">condition-false</data>
      <data key="startline">19</data>
      <data key="endline">19</data>
    </edge>
    <node id="A5"/>    
    <edge source="A4" target="A5">
      <data key="startline">21</data>
      <data key="endline">21</data>
      <!-- restrict value of nondeterministic function, if not given assume that loop nonterminates for any returned value -->
      <data key="assumption">x=12</data> 
    </edge>
    <node id="A6"/>
    <!-- if branch in while loop not part of the infinite execution -->
    <edge source="A5" target="sink">
      <data key="control">condition-true</data>
      <data key="startline">23</data>
      <data key="endline">23</data>
    </edge>
    <edge source="A5" target="A6">
      <data key="control">condition-false</data>
      <data key="startline">23</data>
      <data key="endline">23</data>
    </edge>
    <node id="A7">
      <!-- program loop invariant -->
      <data key="invariant">y>=0</data>
    </node>
    <edge source="A6" target="A7">
       <data key="enterLoopHead">true</data>    
    </edge>
    <node id="A8"/>
    <edge source="A7" target="A8">
      <data key="control">condition-true</data>
      <data key="startline">27</data>
      <data key="endline">27</data>
    </edge>
    <edge source="A8" target="A7">
       <data key="enterLoopHead">true</data>
    </edge>
    <node id="A9"/>
    <edge source="A7" target="A9">
      <data key="control">condition-false</data>
      <data key="startline">27</data>
      <data key="endline">27</data>
    </edge>
    <edge source="A9" target="A3">
       <data key="enterLoopHead">true</data>
    </edge>
  </graph>
</graphml>  
```

### Validating Termination Violation Witnesses in CPAchecker

The following command will start CPAchecker to validate the termination violation witness ``witness.graphml`` for program ``prog.c``.

<pre>
./scripts/cpa.sh -witnessValidation \
-witness witness.graphml \
-spec Termination.prp \
prog.c
</pre>

Optionally, you may configure the machine model to 32 bit (64 bit) by adding the parameter ``-32`` (``-64``).

The output of the command should look similar to the following.

<pre>
Running CPAchecker with default heap size (1200M). Specify a larger value with -heap if you have more RAM.
Running CPAchecker with default stack size (1024k). Specify a larger value with -stack if needed.
Using the following resource limits: CPU-time limit of 900s (ResourceLimitChecker.fromConfiguration, INFO)

CPAchecker 1.6.1-svn (OpenJDK 64-Bit Server VM 1.8.0_131) started (CPAchecker.run, INFO)

[...]

Starting analysis ... (CPAchecker.runAlgorithm, INFO)

Search for program location at which infinite path(s) split into stem and looping part (NonTerminationWitnessValidator.findStemEndLocation, INFO)

Check that recurrent set is reachable (NonTerminationWitnessValidator.run, INFO)

Prepare check for reachability of recurrent set. (NonTerminationWitnessValidator.checkReachabilityOfRecurrentSet, INFO)

[...]

Recurrent set is reachable. (NonTerminationWitnessValidator.checkReachabilityOfRecurrentSet, INFO)

Check that recurrent set is valid (NonTerminationWitnessValidator.run, INFO)

Check that assumptions in witnesses only restrict nondeterministic choices (NonTerminationWitnessValidator.confirmThatRecurrentSetIsProper, INFO)

[...]

Checking infinite part of non-termination witness, often the loop part (NonTerminationWitnessValidator.confirmThatRecurrentSetIsProper, INFO)

[...]

Non-termination witness confirmed. (NonTerminationWitnessValidator.run, INFO)

Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: FALSE. Property violation (termination) found by chosen configuration.
More details about the verification run can be found in the directory "./output".
Graphical representation included in the file "./output/Report.html".
</pre>

The verification result "FALSE" means that the termination violation witness was successfully inspected, i.e., the validation confirmed that there exists an execution of the program which does not terminate. Since the validator is incomplete and may fail to detect valid witnesses, verification result "UNKNOWN" is returned whenever the validation of the witness fails.

### Producing Termination Violation Witnesses in CPAchecker
To run the termination analysis in CPAchecker to (dis)prove termination of a program ``prog.c`` run the following command, optionally extended with either ``-32`` or ``-64`` to set the bit width.

<pre>
./scripts/cpa.sh -terminationAnalysis -noout \
-spec Termination.prp \
-setprop termination.violation.witness=witness.graphml \
prog.c  
</pre>

The command produces the following output, when disproving termination.

<pre>
Running CPAchecker with default heap size (1200M). Specify a larger value with -heap if you have more RAM.
Running CPAchecker with default stack size (1024k). Specify a larger value with -stack if needed.
Using the following resource limits: CPU-time limit of 900s (ResourceLimitChecker.fromConfiguration, INFO)

CPAchecker 1.6.1-svn (OpenJDK 64-Bit Server VM 1.8.0_131) started (CPAchecker.run, INFO)

[...]

Starting analysis ... (CPAchecker.runAlgorithm, INFO)

Starting termination algorithm. (TerminationAlgorithm.run0, INFO)

Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: FALSE. Property violation (termination) found by chosen configuration.
More details about the verification run can be found in the directory "./output".
</pre>

The violation witness, which is produced when the termination analysis returns "FALSE" (i.e., disproves termination), can be found in ``output/witness.graphml``. Note that the violation witness produced by the analysis sometimes does not contain enough information to be validated successfully by CPAchecker's validator. For example, it does not restrict non-determinism.
