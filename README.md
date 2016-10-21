## Exchange Format for Violation Witnesses and Correctness Witnesses

### Basics

We formally represent witnesses as witness automata. Since an automaton is a graph, we decided to extend an existing exchange format (GraphML) for graphs and apply it to witness automata. [GraphML](http://graphml.graphdrawing.org/) is an XML-based format for exchanging graphs that was designed with extensibility in mind. (This [primer](http://graphml.graphdrawing.org/primer/graphml-primer.html) gives a good introduction.)

The idea is that a violation-witness automaton guides the verifier for a finite number of steps through the program along an error path in order to find a violation of the safety property,
and that a correctness-witness automaton gives invariants as hints that guide the verifier towards the proof.

Note that a violation-witness automaton might represent several possible paths. In particular, the automaton might represent several infeasible error paths and feasible error paths. Ideally, the error path is very short and contains concrete values (test case).

### Data Elements

In order to represent the witness automaton in GraphML, the edges and nodes of the graph are enriched with (XML) ``data`` elements of different types. The ``key`` attribute of a data element defines its type, the child elements of the element (usually a single XML text node) represent its value.

#### Graph Data for Witness Automata

These annotations are used for the ``graph`` GraphML tag,
i.e. for ``data`` tags that are direct children of the ``graph`` tag.
All of the annotations are required.

| key | Meaning |
| --- | --- |
| witness-type | *Valid values:* ``correctness_witness`` or ``violation_witness`` <br /> Specifies the witness type. A correctness witness is identified by the value ``correctness_witness``, a violation witness is identified by the value ``violation_witness``. |
| sourcecodelang | *Valid values:* Currently, only ``C`` is supported. <br /> The name of the programming language. |
| producer | *Valid values:* Any <br /> The name of the tool that produced the witness automaton, e.g. ``CPAchecker 1.6.8`` |
| specification | *Valid values:* The specification text <br /> The specification text used to verify the program, e.g. ``CHECK( init(main()), LTL(G ! call(__VERIFIER_error())) )`` |
| programfile | *Valid values:* The program file path as passed to the verifier <br /> The path to the program file, e.g. ``/scratch/dangl/sv-benchmarks/c/ldv-linux-3.4-simple/32_1_cilled_true-unreach-call_ok_nondet_linux-3.4-32_1-drivers--acpi--ec_sys.ko-ldv_main0_sequence_infinite_withcheck_stateful.cil.out.c`` |
| programhash | *Valid values:* SHA-1-Hashsum <br /> The SHA-1-Hashsum of the verified program, e.g. ``bec44c8c30d753a31070dd280c7a98510270704c``. |
| memorymodel | *Valid values:* ``simple`` or ``precise`` <br /> The memory model assumed for the verification task. |
| architecture | *Valid values:* ``32bit`` or ``64bit`` <br /> The architecture assumed for the verification task. |

#### Node Data for Automata States

These annotations are used for the ``node`` GraphML tags,
i.e. for ``data`` tags that are direct children of the ``node`` tags.

| key | Meaning | Allowed in Violation Witnesses | Allowed in Correctness Witnesses |
| --- | --- | ---- | ---- |
| entry | *Valid values:* ``false`` (default) or ``true`` <br /> This node represents the initial state of the automata (entry node of the graph). Only one initial state (entry node) is allowed. | Yes | Yes |
| sink | *Valid values:* ``false`` (default) or ``true`` <br />  This node is a sink. All paths that lead to this node end here and should not be further explored by the witness validator. Nodes where this flag is set must not have any leaving edges | Yes | No |
| violation | *Valid values:* ``false`` (default) or ``true`` <br /> The witness claims that paths that reach this state violate the specification. A witness is only accepted if the witness validator detects a specification violation and the witness automaton is in a state where this flag is set. | Yes | No |
| invariant | *Valid values:* A C expression that must evaluate to the C type ``int`` (used as boolean) and **may** consist of conjunctions or disjunctions, but not function calls. Local variables that have the same name as global variables or local variables of other functions can be qualified by using a data tag with the ``invariant.scope`` key. | No | Yes |
| invariant.scope | *Valid values:* Function name <br /> The witness validator must map the variables in the given invariants to the variables in the C code. Due to scopes in C, there may be name conflicts. The witness validator will first look for a variable with a matching name in the scope of the provided function name before checking the global scope. This tag applies to the invariant as a whole. It is not possible to specify invariants about local variables of different functions. There is currently no support for different variables with the same name within different scopes of the same function. | No | Yes |

#### Edge Data for Automata Transitions

These annotations are used for the ``edge`` GraphML tags,
i.e. for ``data`` tags that are direct children of the ``edge`` tags.

| key | Meaning | Allowed in Violation Witnesses | Allowed in Correctness Witnesses |
| --- | --- | ---- | ---- |
| assumption | *Valid values:* Sequence of C expressions separated by semicolons. Each of the expressions must evaluate to the C type ``int`` (used as boolean) and **may not** consist of function calls, conjunctions, or disjunctions. <br /> One or more assignment statements representing assumptions about the current state. Local variables that have the same name as global variables or local variables of other functions can be qualified by using the ``assumption.scope`` tag. All variables used in the C expressions must appear in the program source code, with the exception of the variable ``\result``, which represents the return value of the function identified by the data tag with key ``assumption.resultfunction`` after a function call in the control-flow represented by this edge. If you use the ``\result`` variable, you must provide a corresponding function name using a tag with the ``assumption.resultfunction`` key. | Yes | No |
| assumption.scope | *Valid values:* Function name <br /> The witness validator must map the variables in the given assumptions to the variables in the C code. Due to scopes in C, there may be name conflicts. The witness validator will first look for a variable with a matching name in the scope of the provided function name before checking the global scope. This tag applies to the assumption as a whole. It is not possible to specify assumptions about local variables of different functions. There is currently no support for different variables with the same name within different scopes of the same function. | Yes | No |
| assumption.resultfunction | *Valid values:* Function name <br /> A data tag with this key can be used to qualify the function of the ``\result`` variable used in an ``assumption`` data tag within the same transition, meaning that ``\result`` represents the return value of the given function. This tag applies to the assumption as a whole, it is therefore not possible to refer to multiple function-return values within the same transition. If you use the ``\result`` variable, you must use this tag. Otherwise, it is superfluous. | Yes | No |
| control | *Valid values:* ``condition-true`` or ``condition-false`` <br /> A branching in source code is always labeled with a condition, thus there are two branches: one that is taken if the condition evaluates to true, the other if it evaluates to false; this is represented by the values ``condition-true``, respectively, ``condition-false``. An automaton transition is allowed if the current control-flow edge is a control-statement, e.g. ``if (...)``, and the value matches the case of the control-flow edge. | Yes | No |
| startline | *Valid values:* Valid line number of the program <br /> Each statement, or expression, on a control-flow edge was derived from a line (or multiple lines - see ``endline``) in the source code. The ``startline`` corresponds to the line number on that a statement, or expression, of a control-flow edge started | Yes | Yes |
| endline | *Valid values:* Valid line number of the program <br /> A statement, or expression, can be written across multiple lines. The value of ``endline`` represents the line number on that the statement, or expression, of a matching control-flow edge ends. | Yes | Yes |
| startoffset | *Valid values:* Offset of a specific character in the program from the program start. <br /> Matches the character offset on that the expression or statement represented by the control-flow edge starts. It is important that witness consumer (validator) and witness producer agree on the encoding of the C program. | Yes | Yes |
| endoffset | *Valid values:* Offset of a specific character in the program from the program start. <br /> Matches the character offset on that the expression or statement represented by the control-flow edge ends. It is important that witness checker and witness producer agree on the encoding of the C program. | Yes | Yes |
| enterLoopHead | *Valid values:* ``false`` (default) or ``true`` <br /> Signifies that an witness-automaton transition annotated with this guard only matches if the observed analysis takes a control-flow edge into a loop head. | Yes | Yes | 
| enterFunction | *Valid values:* Function name <br /> The name of the function that is entered via this edge. Assuming a function stack, this pushes the function onto the stack. If you use this data node type, you also must use the type ``returnFromFunction``. When ``assumption.scope`` is not given, the witness validator may use this information to qualify  variable names used in ``assumption`` data tags. The path is considered to stay in the specified function until another edge is annotated with this data node for another function or an edge annotated with ``returnFromFunction``, telling the validator that the path continues in the previous function on the stack.  | Yes | Yes |
| returnFromFunction | *Valid values:* Function name <br /> The name of the function is exited via this edge. Assuming a function stack, this name must match the name of the function popped from the function stack. If you use this data node type, you also must use the type ``enterFunction``. See ``enterFunction`` for more information. | Yes | Yes |

Tools may introduce their own data nodes with custom keys and values. Other tools should ignore data nodes they do not know or are unable to handle.

This witness specification is a work in progress and will be subject to modifications.

## Validating Violation Witnesses

Witnesses can be validated by CPAchecker or UltimateAutomizer. To validate a witness, you need to provide the specification the witness was produced with and the witness itself as an additional specification to the tool, as well as any other parameter required by the tool to check the specific type of program, if any.

In the following, we present the violation-witness validation service followed by listing examples of available witness checkers (in alphabetic order).

### Validating a Violation Witness using a Violation-Witness Validation Service

The violation-witness validation service is designed to be as simple to use as possible. Therefore you will not not need to manually select the specification, machine model, and architecture the witness was produced for, but may instead include it within the witness file itself. See the XML ``data`` tags with the keys ``specification``, ``memorymodel``, and ``architecture`` in the [linked witness](service-example.graphml) as an example. Accpeted values for the memory model are ``simple`` and ``precise`` (default). Accepted values for the architecture are ``32bit`` (default) and ``64bit``. If you would rather keep the original specification separate, you can still use the witness validators manually, as described further down.

Submit the witness validation job here: [http://vcloud.sosy-lab.org/webclient/runs/witness_validation](http://vcloud.sosy-lab.org/webclient/runs/witness_validation)

Once the job finishes, a result page will appear.

This page provides data like the CPU time, also the log file, a zip file with all output files, and a link to an error-path report that makes it easy to inspect and understand error paths.

This service can also be used via the command line:

<pre>scripts/witness_validation_web_cloud.py --program source.i --witness witness.graphml</pre>

using the [provided python script](witness-validation.zip).

### Validating a Violation Witness with CPAchecker

The following command will start CPAchecker to validate an violation witness for ``test.c``. We assume that the violation witnesses is stored in the file ``witness-to-validate.graphml``.

An easy way to validate witnesses with CPAchecker that should be able to handle most scenarios is provided by a predifined configuration:

<pre>./scripts/cpa.sh -witness-validation \
    -spec witness-to-validate.graphml \
    -spec PropertyERROR.prp \
    test.c
</pre>

There may be cases where you want to use different analyses. It is therefore possible to derive a custom configuration. The following example shows how to configure CPAchecker to use linear arithmetic predicate analysis to consume a witness:

<pre>./scripts/cpa.sh -noout -heap 10000M -predicateAnalysis \
    -setprop cfa.useMultiEdges=false \
    -setprop cfa.simplifyCfa=false \
    -setprop cfa.allowBranchSwapping=false \
    -setprop cpa.predicate.ignoreIrrelevantVariables=false \
    -setprop counterexample.export.assumptions.assumeLinearArithmetics=true \
    -setprop analysis.traversal.byAutomatonVariable=__DISTANCE_TO_VIOLATION \
    -setprop cpa.automaton.treatErrorsAsTargets=false \
    -setprop WitnessAutomaton.cpa.automaton.treatErrorsAsTargets=true \
    -setprop parser.transformTokensToLines=false \
    -skipRecursion \
    -spec witness-to-validate.graphml \
    -spec PropertyERROR.prp \
    test.c
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to add the parameter ``-64`` to the command line. For tasks where the simple memory model is assumed, you also need to add the option ``-setprop cpa.predicate.handlePointerAliasing=false``.

The output of the command should look similar to the following:

<pre>Using the following resource limits: CPU-time limit of 900s (ResourceLimitChecker.fromConfiguration, INFO)

CPAchecker 1.4-svn (OpenJDK 64-Bit Server VM 1.7.0_79) started (CPAchecker.run, INFO)

Using predicate analysis with MathSAT5 version 5.3.7 (073c3b224db1)
  (Jul  7 2015 15:45:01, gmp 5.0.2, gcc 4.6.3, 64-bit) and JFactory 1.21.
  (PredicateCPA:PredicateCPA.init, INFO)

Using refinement for predicate analysis with PredicateAbstractionRefinementStrategy strategy.
  (PredicateCPA:PredicateCPARefiner.init, INFO)

[..]

Starting analysis ... (CPAchecker.runAlgorithm, INFO)

[..]

Automaton going to ErrorState on edge "__VERIFIER_error();"
  (WitnessAutomaton:AutomatonTransferRelation.getFollowStates, INFO)

[..]

Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: FALSE. Property violation (__VERIFIER_error();
  called in line 751,__VERIFIER_error(); called in line 751) found by chosen configuration.
More details about the verification run can be found in the directory "./output".
</pre>

The verification result *"FALSE"* means that the violation witness was successfully validated, i.e., one of the paths that is described by the witness automaton leads to a violation of the specification. The result *"TRUE"* would mean that none of the paths described by the witness automaton lead to a violation of the specification, or in other words, that the witness was rejected. A witness is also rejected if the witness validation does not terminate normally.

### Validating a Violation Witness with Ultimate Automizer

The following command will start Ultimate Automizer to validate an violation witness for ``test.c``. We assume that the violation witnesses is stored in the file ``witness-to-validate.graphml``.

<pre>cd UltimateAutomizer
python3 UltimateWitnessChecker.py \
    PropertyERROR.prp \
    test.c \
    32bit precise \
    witness-to-validate.graphml
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to use the parameter ``64bit`` instead of ``32bit``. For tasks where the simple memory model is assumed, you also need to replace the option ``precise`` by ``simple``.

The output of the command should look similar to the following:

<pre>Calling Ultimate Automizer with: ./Ultimate ./Automizer.xml
   test.c
   witness-to-validate.graphml
   --settings ./svComp-32bit-precise-Automizer.epf
[...]
Execution finished normally
Writing output log to file Ultimate.log
Writing human readable error path to file UltimateCounterExample.errorpath
Result:
FALSE
LineCoverage:404.58015267175574
</pre>

The verification result *"FALSE"* means that the violation witness was successfully validated, i.e., one of the paths that is described by the witness automaton leads to a violation of the specification. The result *"TRUE"* would mean that none of the paths described by the witness automaton lead to a violation of the specification, in other words, the witness was rejected. A witness is also rejected if the witness validation does not terminate normally.

### Writing a Violation Witness with CPAchecker

In the following example, we assume that the current directory is the CPAchecker directory, ``PropertyERROR.prp`` is the specification that was used to produce the witness, ``witness.graphml`` is the witness file and ``test.c`` is the verification task. The following command shows how to use CPAchecker to verify the task and produce a witness:

<pre>scripts/cpa.sh -noout -heap 10000M -predicateAnalysis \
    -setprop cfa.useMultiEdges=false \
    -setprop cpa.predicate.solver=MATHSAT5 \
    -setprop cfa.simplifyCfa=false \
    -setprop cfa.allowBranchSwapping=false \
    -setprop cpa.predicate.ignoreIrrelevantVariables=false \
    -setprop counterexample.export.assumptions.assumeLinearArithmetics=true \
    -setprop coverage.enabled=false \
    -setprop coverage.mode=TRANSFER \
    -setprop coverage.export=true \
    -setprop coverage.file=coverage.info \
    -setprop parser.transformTokensToLines=false \
    -setprop counterexample.export.assumptions.includeConstantsForPointers=false \
    -setprop cpa.arg.errorPath.graphml=witness.graphml \
    -spec PropertyERROR.prp \
    test.c
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to add the parameter ``-64`` to the command line. For tasks where the simple memory model is assumed, you also need to add the option ``-setprop cpa.predicate.handlePointerAliasing=false``.

The output of the command should look similar to the following:

<pre>Running CPAchecker with Java heap of size 10000M.
Using the following resource limits: CPU-time limit of 900s (ResourceLimitChecker.fromConfiguration, INFO)

CPAchecker 1.4-svn (OpenJDK 64-Bit Server VM 1.7.0_79) started (CPAchecker.run, INFO)

Using predicate analysis with MathSAT5 version 5.3.7 (073c3b224db1)
  (Jul  7 2015 15:45:01, gmp 5.0.2, gcc 4.6.3, 64-bit) and JFactory 1.21.
  (PredicateCPA:PredicateCPA.init, INFO)

Using refinement for predicate analysis with PredicateAbstractionRefinementStrategy strategy.
  (PredicateCPA:PredicateCPARefiner.init, INFO)

[...]

Starting analysis ... (CPAchecker.runAlgorithm, INFO)

Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: FALSE. Property violation (__VERIFIER_error(); called in line 751)
  found by chosen configuration.
More details about the verification run can be found in the directory "./output".
</pre>

The violation-witness automaton is written to ``output/witness.graphml``. If the verification is applied to the task ``ssh-simplified/s3_clnt_1_false-unreach-call.cil.c`` from the SV-COMP benchmark set, the witness should look similar to [this witness](s3_cln1_false.witness.cpachecker.graphml). Note that this task assumes the simple memory model.

### Writing a Violation Witness with UltimateAutomizer

From the UltimateAutomizer directory, the following command will start UltimateAutomizer to verify a task for which it will come up with a feasible counterexample:

<pre>python3 Ultimate.py \
    PropertyERROR.prp \
    test.c \
    32bit precise
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to use the parameter ``64bit`` instead of ``32bit``. For tasks where the simple memory model is assumed, you also need to replace the option ``precise`` by ``simple``.

The output of the command should look similar to the following:

<pre>Checking for ERROR reachability
Rev 14553
Calling Ultimate with: ./Ultimate ./Automizer.xml
  test.c
  --settings ./svComp-32bit-precise-Automizer.epf
[...]
Execution finished normally
Writing output log to file Ultimate.log
Writing human readable error path to file UltimateCounterExample.errorpath
Result:
FALSE
</pre>

The violation-witness automaton is written to ``witness.graphml``. If the verification is applied to the task ``ssh-simplified/s3_clnt_1_false-unreach-call.cil.c`` from the SV-COMP benchmark set, the witness should look similar to [this witness](s3_cln1_false.witness.ultimateautomizer.graphml). Again, note that this task assumes the simple memory model.

## Validating Correctness Witnesses

As a running example, we use the verification task [multivar_true-unreach-call1.i](multivar_true-unreach-call1.i) from the SV-COMP'17 benchmark set.

We assume that the two tool directories of CPAchecker and UltimateAutomizer are placed alongside each other in the same parent directory.

### Producing Correctness Witnesses with CPAchecker

To produce a witness for the example task with CPAchecker, simply execute the following commands:

<pre>  cd CPAchecker/
  scripts/cpa.sh \
    -correctness-witnesses-k-induction \
    -spec ../svcomp16/c/loop-acceleration/ALL.prp \
    ../svcomp16/c/loop-acceleration/multivar_true-unreach-call1.i
  cd ..
</pre>

The output of CPAchecker should be similar to the following listing:

<pre>Running CPAchecker with default heap size (1200M). Specify a larger value with -heap if you have more RAM.
Running CPAchecker with default stack size (1024k). Specify a larger value with -stack if needed.
CPAchecker 1.6.1-svn 22870M (Java HotSpot(TM) 64-Bit Server VM 1.8.0_101) started (CPAchecker.run, INFO)

The following configuration options were specified but are not used:
 properties 
 (CPAchecker.printConfigurationWarnings, WARNING)

Starting analysis ... (CPAchecker.runAlgorithm, INFO)

Using predicate analysis with MathSAT5 version 5.3.12 (fd820dac73f2) (Aug  8 2016 11:12:19, gmp 5.1.3, gcc 5.3.0, 64-bit).
  (Parallel analysis 1:PredicateCPA:PredicateCPA.init, INFO)

Using predicate analysis with MathSAT5 version 5.3.12 (fd820dac73f2) (Aug  8 2016 11:12:19, gmp 5.1.3, gcc 5.3.0, 64-bit).
  (Parallel analysis 1:InductionStepCase:PredicateCPA:PredicateCPA.init, INFO)

config/invariantGeneration-no-out-no-typeinfo.properties finished successfully.
  (ParallelAlgorithm.handleFutureResults, INFO)

Analysis was terminated (Parallel analysis 1:ParallelAlgorithm.runParallelAnalysis, INFO)

Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: TRUE. No property violation found by chosen configuration.
More details about the verification run can be found in the directory "./output".
Run scripts/report-generator.py to show graphical report.
</pre>

You will find the correctness witness produced by CPAchecker for the example task  
at ``CPAchecker/output/correctness-witness.graphml``.

### Producing Correctness Witnesses with UltimateAutomizer

To produce a witness for the example task with UltimateAutomizer, simply execute the following commands:

<pre>  cd UAutomizer-linux/
  ./Ultimate.py \
    ../svcomp16/c/loop-acceleration/ALL.prp \
    32bit precise \
    ../svcomp16/c/loop-acceleration/multivar_true-unreach-call1.i
  cd ..
</pre>

The output of UltimateAutomizer should look similar to the following listing:

<pre>Checking for ERROR reachability
Using default analysis
Version c3312191
Calling Ultimate with: ./Ultimate --console "./Automizer.xml"
  "../svcomp16/c/loop-acceleration/multivar_true-unreach-call1.i"
  "--settings" "/hard-disk/dangl/tmp/UAutomizer-linux/svcomp-Reach-32bit-Automizer_Default.epf"
...............................................................................................
...............................................................................................
.....................................................................
Execution finished normally
Writing output log to file Ultimate.log
Result:
TRUE
</pre>

You will find the correctness witness produced by UltimateAutomizer for the example task  
at ``UAutomizer-linux/witness.graphml``.

### Validating Correctness Witnesses with CPAchecker

For the validation, we assume that one of the previously obtained witnesses for the example task has been named ``correctness-witness.graphml`` and moved to the parent directory of the two tool directories. To validate the correctness witness with CPAchecker, simply execute the following commands:

<pre>  cd CPAchecker/
  scripts/cpa.sh \
    -correctness-witness-validation \
    -setprop invariantGeneration.kInduction.invariantsAutomatonFile=../correctness-witness.graphml \
    -spec ../svcomp16/c/loop-acceleration/ALL.prp \
    ../svcomp16/c/loop-acceleration/multivar_true-unreach-call1.i
  cd ..
</pre>

If the witness is valid, the output of CPAchecker should end in the following lines:

<pre>Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: TRUE. No property violation found by chosen configuration.
More details about the verification run can be found in the directory "./output".
</pre>

Because the CPAchecker-based validator is actually even a correctness-witness testifier, the validation will produce another (usually more abstract) correctness witness  
in ``CPAchecker/output/correctness-witness.graphml``.

### Validating Correctness Witnesses with UltimateAutomizer

For the validation, we assume that one of the previously obtained witnesses for the example task has been named ``correctness-witness.graphml`` and moved to the parent directory of the two tool directories. To validate the correctness witness with UltimateAutomizer, simply execute the following commands:

<pre>  cd UAutomizer-linux/
  ./Ultimate.py \
    ../svcomp16/c/loop-acceleration/ALL.prp \
    32bit precise \
    ../svcomp16/c/loop-acceleration/multivar_true-unreach-call1.i \
    ../correctness-witness.graphml
  cd ..
</pre>

A successful validation will result in an output similar to the following:

<pre>Checking for ERROR reachability
Using default analysis
Version c3312191
Calling Ultimate with: ./Ultimate --console
  "/hard-disk/dangl/tmp/UAutomizer-linux/AutomizerWitnessValidation.xml"
  "../svcomp16/c/loop-acceleration/multivar_true-unreach-call1.i"
  "../correctness-witness.graphml"
  "--settings" "/hard-disk/dangl/tmp/UAutomizer-linux/svcomp-Reach-32bit-Automizer_Default.epf"
...............................................................................................
...............................................................................................
...............................................................................................
...............................................................................................
.............................................................................................
Execution finished normally
Writing output log to file Ultimate.log
Result:
TRUE
</pre>

### Further Reading

1. Dirk Beyer, Matthias Dangl, Daniel Dietsch, and Matthias Heizmann. **Correctness Witnesses: Exchanging Verification Results between Verifiers**. In J. Cleland-Huang and Z. Su, editors, *Proceedings of the 24th ACM SIGSOFT International Symposium on the Foundations of Software Engineering (FSE 2016, Seattle, WA, USA, November 13-18)*, 2016. ACM, New York.
2. Dirk Beyer and Matthias Dangl. **Verification-Aided Debugging: An Interactive Web-Service for Exploring Error Witnesses**. In S. Chaudhuri and A. Farzan, editors, *Proceedings of the 28th International Conference on Computer Aided Verification (CAV 2016, Toronto, ON, Canada, July 17-23), Part II*, LNCS 9780, pages 502-509, 2016. Springer-Verlag, Heidelberg.
3. Dirk Beyer. **Reliable and Reproducible Competition Results with BenchExec and Witnesses (Report on SV-COMP 2016)**. In M. Chechik and J.-F. Raskin, editors, *Proceedings of the 22nd International Conference on Tools and Algorithms for the Construction and of Analysis Systems (TACAS 2016, Eindhoven, The Netherlands, April 2-8)*, pages 887-904, 2016. Springer-Verlag, Heidelberg.
4. Dirk Beyer, Matthias Dangl, Daniel Dietsch, Matthias Heizmann, and Andreas Stahlbauer. **Witness Validation and Stepwise Testification across Software Verifiers**. In E. Di Nitto, M. Harman, and P. Heymans, editors, *Proceedings of the 2015 10th Joint Meeting of the European Software Engineering Conference and the ACM SIGSOFT Symposium on Foundations of Software Engineering (ESEC/FSE 2015, Bergamo, Italy, August 31 - September 4)*, pages 721-733, 2015. ACM, New York.
5. Dirk Beyer. **Software Verification and Verifiable Witnesses (Report on SV-COMP 2015)**. In C. Baier and C. Tinelli, editors, *Proceedings of the 21st International Conference on Tools and Algorithms for the Construction and of Analysis Systems (TACAS 2015, London, UK, April 13-17)*, LNCS 9035, pages 401-416, 2015. Springer-Verlag, Heidelberg.
