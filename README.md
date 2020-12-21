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

| key | Meaning | Required |
| --- | --- | --- |
| witness-type | *Valid values:* ``correctness_witness`` or ``violation_witness`` <br /> Specifies the witness type. A correctness witness is identified by the value ``correctness_witness``, a violation witness is identified by the value ``violation_witness``. | Yes |
| sourcecodelang | *Valid values:* Currently, only ``C`` and ``Java`` are supported. <br /> The name of the programming language. | Yes |
| producer | *Valid values:* Any <br /> The name of the tool that produced the witness automaton, e.g., ``CPAchecker 1.6.8`` | Yes |
| specification | *Valid values:* The specification text <br /> The specification text used to verify the program, e.g., ``CHECK( init(main()), LTL(G ! call(__VERIFIER_error())) )`` | Yes |
| programfile | *Valid values:* The program file path as passed to the verifier <br /> The path to the program file, e.g., ``/home/me/benchmarks/c/loop-acceleration/multivar_true-unreach-call1_true-termination.i`` | Yes |
| programhash | *Valid values:* SHA-256 hash <br /> The SHA-256 hash of the verified program, e.g., ``e2d5365a863c1c57fbe2870942676040efc3aea2d9bb085092800d6e256daf06``. | Yes |
| architecture | *Valid values:* An identifier for the assumed architecture <br /> The architecture assumed for the verification task, e.g., ``32bit`` or ``64bit`` | Yes |
| creationtime | *Valid values:* Date and time of creation in ISO 8601 format. <br /> The date and time the witness was created in ISO 8601 format. The date must contain the year, the month, and the day, separated by dashes ('-'). The date is separated from the time using the capital letter 'T'. The time must be given in hours, minutes, and seconds, separated by colons (':'). If the timestamp is not given in UTC time, a positive ('+') or negative ('-') time offset consisting of hours and minutes separated by a colon (':') can be appended. Example: ``2016-12-24T13:15:32+02:00``. | Yes |

#### Node Data for Automata States

These annotations are used for the ``node`` GraphML tags,
i.e. for ``data`` tags that are direct children of the ``node`` tags.
In witness automata, the GraphML nodes represent states.

| key | Meaning | Allowed in Violation Witnesses | Allowed in Correctness Witnesses |
| --- | --- | ---- | ---- |
| entry | *Valid values:* ``false`` (default) or ``true`` <br /> This state represents the initial state of the automata (entry state of the graph). Only exactly one initial state (entry state) is allowed. | Yes | Yes |
| sink | *Valid values:* ``false`` (default) or ``true`` <br />  This state is a sink. All paths that lead to this state end here and should not be further explored by the witness validator. Nodes where this flag is set must not have any leaving transitions | Yes | No |
| violation | *Valid values:* ``false`` (default) or ``true`` <br /> The witness claims that paths that reach this state violate the specification. A violation witness is only accepted if the witness validator detects a specification violation and the witness automaton is in a state where this flag is set. | Yes | No |
| invariant | *Valid values:* A C expression that must evaluate to the C type ``int`` (used as boolean) and **may** consist of conjunctions or disjunctions, but not function calls. Local variables that have the same name as global variables or local variables of other functions can be qualified by using a data tag with the ``invariant.scope`` key. | No | Yes |
| invariant.scope | *Valid values:* Function name <br /> The witness validator must map the variables in the given invariants to the variables in the C code. Due to scopes in C, there may be name conflicts. The witness validator will first look for a variable with a matching name in the scope of the provided function name before checking the global scope. This tag applies to the invariant as a whole. It is not possible to specify invariants about local variables of different functions. There is currently no support for different variables with the same name within different scopes of the same function. | No | Yes |

#### Edge Data for Automata Transitions

These annotations are used for the ``edge`` GraphML tags,
i.e. for ``data`` tags that are direct children of the ``edge`` tags.
In witness automata, the GraphML edges represent state transitions.

| key | Meaning | Allowed in Violation Witnesses | Allowed in Correctness Witnesses |
| --- | --- | ---- | ---- |
| assumption | *Valid values:* Sequence of C expressions separated by semicolons. Each of the expressions must evaluate to the C type ``int`` (used as boolean) and **may not** consist of function calls, conjunctions, or disjunctions. <br /> C expressions representing assumptions about the current state. Local variables that have the same name as global variables or local variables of other functions can be qualified by using the ``assumption.scope`` tag. All variables used in the C expressions must appear in the program source code, with the exception of the variable ``\result``, which represents the return value of the function identified by the data tag with key ``assumption.resultfunction`` after a function call in the control-flow represented by this transition. If you use the ``\result`` variable, you must provide a corresponding function name using a tag with the ``assumption.resultfunction`` key. | Yes | No |
| assumption.scope | *Valid values:* Function name <br /> The witness validator must map the variables in the given assumptions to the variables in the C code. Due to scopes in C, there may be name conflicts. The witness validator will first look for a variable with a matching name in the scope of the provided function name before checking the global scope. This tag applies to the assumption as a whole. It is not possible to specify assumptions about local variables of different functions. There is currently no support for different variables with the same name within different scopes of the same function. | Yes | No |
| assumption.resultfunction | *Valid values:* Function name <br /> A data tag with this key can be used to qualify the function of the ``\result`` variable used in an ``assumption`` data tag within the same transition, meaning that ``\result`` represents the return value of the given function. This tag applies to the assumption as a whole, it is therefore not possible to refer to multiple function-return values within the same transition. If you use the ``\result`` variable, you must use this tag. Otherwise, it is superfluous. | Yes | No |
| control | *Valid values:* ``condition-true`` or ``condition-false`` <br /> A branching in source code is always labeled with a condition, thus there are two branches: one that is taken if the condition evaluates to true, the other if it evaluates to false; this is represented by the values ``condition-true``, respectively, ``condition-false``. An automaton transition is allowed if the current control-flow edge is a control-statement, e.g. ``if (...)``, and the value matches the case of the control-flow edge. | Yes | Yes |
| startline | *Valid values:* Valid line number of the program <br /> Each statement, or expression, on a control-flow edge was derived from a line (or multiple lines - see ``endline``) in the source code. The ``startline`` corresponds to the line number on that a statement, or expression, of a control-flow edge started | Yes | Yes |
| endline | *Valid values:* Valid line number of the program <br /> A statement, or expression, can be written across multiple lines. The value of ``endline`` represents the line number on that the statement, or expression, of a matching control-flow edge ends. | Yes | Yes |
| startoffset | *Valid values:* Offset of a specific character in the program from the program start. <br /> Matches the character offset on that the expression or statement represented by the control-flow edge starts. It is important that witness consumer (validator) and witness producer agree on the encoding of the C program. | Yes | Yes |
| endoffset | *Valid values:* Offset of a specific character in the program from the program start. <br /> Matches the character offset on that the expression or statement represented by the control-flow edge ends. It is important that witness checker and witness producer agree on the encoding of the C program. | Yes | Yes |
| enterLoopHead | *Valid values:* ``false`` (default) or ``true`` <br /> Signifies that an witness-automaton transition annotated with this guard only matches if the observed analysis takes a control-flow edge into a loop head. | Yes | Yes |
| enterFunction | *Valid values:* Function name <br /> The name of the function that is entered via this transition. Assuming a function stack, this pushes the function onto the stack. If you use this data node type, you also must use the type ``returnFromFunction``. When ``assumption.scope`` is not given, the witness validator may use this information to qualify  variable names used in ``assumption`` data tags. The path is considered to stay in the specified function until another transition is annotated with this data node for another function or a transition annotated with ``returnFromFunction``, telling the validator that the path continues in the previous function on the stack.  | Yes | Yes |
| returnFromFunction | *Valid values:* Function name <br /> The name of the function is exited via this transition. Assuming a function stack, this name must match the name of the function popped from the function stack. If you use this data node type, you also must use the type ``enterFunction``. See ``enterFunction`` for more information. | Yes | Yes |

Tools may introduce their own data nodes with custom keys and values. Other tools should ignore data nodes they do not know or are unable to handle.

This witness specification is a work in progress and will be subject to modifications.


### Additional Edge Data for Concurrent Programs

Validating concurrent programs is a complex task,
because it is necessary to determine possible interleavings of thread operations and when a thread is started or exited.
The following information should additionally be available in the witness:

| key | Meaning | Allowed in Violation Witnesses | Allowed in Correctness Witnesses |
| --- | --- | ---- | ---- |
| threadId | Represents the currently active thread for the transition. If no ``threadId`` is given, any thread can be active. The value should be a unique identifer for a thread as long as this thread is active. A thread identifier can be used several times to identify different threads in the program, as long as their execution traces do not interfere. The program trace of a thread can branch or merge along its execution, just the corresponding control flow. | Yes | Yes |
| createThread | The currently active thread (value of ``threadId``) creates a new thread (value of ``createThread``) . In general, using a ``threadId`` is only allowed after creating a matching thread (except for the main thread). The new thread's function can be entered on a transition following the current transition (either directly following or also several transitions later), such that the transition with the ``enterFunction`` key has the ``threadId`` of the created thread. The same thread identifier in ``createThread``can be used at several transitions, e.g., if the same thread can be created via different branches. When the function of the thread is exited, the thread is assumed to be terminated. The corresponding ``threadId`` becomes available again and can be used for a new thread. A thread needs to terminate before a transition using the same identifier for ``createThread`` can be applied by a validator. | Yes | Yes |

CPAchecker partially supports the validation of violation witnesses for concurrent programs.
This witness specification and the validator are a work in progress and will be subject to modifications.


### Witnessing Program Termination
Termination is a liveness property and, in contrast to safety properties, its violation cannot be witnessed by a finite number of program execution steps.
The witness format proposed so far is designed for witnessing safety properties.
Due to the conceputal differences, some termination witness validators may require additional elements.

The description of the termination witness format required by CPAchecker and how to validate and construct termination witnesses with CPAchecker can be found [here](termination/README.md). Currently, only violation witnesses are supported.

Ultimate Automizer supports termination witnesses as specified by this document. No additional information is necessary. The extensions specified in [the termination witness format required by CPAchecker](termination/README.md) will not lead to rejections, but are currently not used. Currently, Ultimate Automizer supports only violation witnesses.

## Validating Violation Witnesses

Witnesses can be validated by CPAchecker or Ultimate Automizer. To validate a witness, you need to provide the specification the witness was produced with and the witness itself as an additional specification to the tool, as well as any other parameter required by the tool to check the specific type of program, if any.

In the following, we present the violation-witness validation service followed by listing examples of available witness checkers (in alphabetic order).

## Validating Witnesses using a Witness Validation Service

The witness-validation service is designed to be as simple to use as possible. Therefore you will not not need to manually select the specification and architecture the witness was produced for, but may instead include this information within the witness file itself. See the XML ``data`` tags with the keys ``specification`` and ``architecture`` in the [example violation witness](minepump_spec1_product33_false-unreach-call_false-termination.cil.graphml) the assumed [specification](PropertyUnreachCall.prp) and [buggy program](minepump_spec1_product33_false-unreach-call_false-termination.cil.c). Accepted values for the architecture are ``32bit`` (default) and ``64bit``. If you would rather keep the original specification separate, you can still use the witness validators manually, as described further down.
In addition to the [example violation witness](minepump_spec1_product33_false-unreach-call_false-termination.cil.graphml) above, we also provide an [example correctness witness](multivar_true-unreach-call1.graphml) corresponding to a [correct program](multivar_true-unreach-call1.i) for the same [specification](PropertyUnreachCall.prp).

Submit the witness validation job here: [http://vcloud.sosy-lab.org/webclient/runs/witness_validation](http://vcloud.sosy-lab.org/webclient/runs/witness_validation)

Once the job finishes, a result page will appear.

This page provides data like the CPU time, also the log file, a zip file with all output files, and, in case you successfully validated a violation-witness, a link to an error-path report that makes it easy to inspect and understand the confirmed error paths.

This service can also be used via the command line:

<pre>./witness_validation_web_cloud.py --program source.i --witness witness.graphml</pre>

using the [provided python script](witness_validation_web_cloud.py).

### Validating a Violation Witness with CPAchecker

The following command will start CPAchecker to validate an violation witness for ``test.c``. We assume that the violation witnesses is stored in the file ``witness-to-validate.graphml``.

An easy way to validate violation witnesses with CPAchecker that should be able to handle most scenarios is provided by a predifined configuration:

<pre>./scripts/cpa.sh -witnessValidation \
-witness witness-to-validate.graphml \
-spec PropertyUnreachCall.prp \
test.c
</pre>

There may be cases where you want to use different analyses. It is therefore possible to derive a custom configuration.
Because choosing an analysis yourself requires some basic knowledge of CPAchecker anyway, we assume for this section of the paragraph that you are familiar with CPAchecker's configuration mechanism.

The easiest way to obtain a new witness-validation configuration is by creating a new configuration file.
As an example, we recommend looking at the configuration file for CPAchecker's default witness-validation analysis used above in ``config/witnessValidation.properties`` and the subconfigurations included from there.

Configuring a new witness-validation analysis directly on the command-line prompt is a bit more involved, because you first need to find the ``.spc`` file corresponding to the ``.prp`` specification file you want to use. For ``PropertyUnreachCall.prp``, this would be ``config/specification/sv-comp-reachability.spc``.
The following example shows how to configure CPAchecker to use linear-arithmetic predicate analysis to consume a witness:

<pre>./scripts/cpa.sh -noout -heap 10000M -predicateAnalysis-linear \
-setprop cpa.composite.aggregateBasicBlocks=false \
-setprop cfa.simplifyCfa=false \
-setprop cpa.predicate.ignoreIrrelevantVariables=false \
-setprop counterexample.export.assumptions.assumeLinearArithmetics=true \
-setprop analysis.traversal.byAutomatonVariable=__DISTANCE_TO_VIOLATION \
-setprop cpa.automaton.treatErrorsAsTargets=false \
-setprop WitnessAutomaton.cpa.automaton.treatErrorsAsTargets=true \
-setprop parser.transformTokensToLines=false \
-skipRecursion \
-setprop specification=witness-to-validate.graphml,config/specification/sv-comp-reachability.spc \
test.c
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to add the parameter ``-64`` to the command line.

The output of the command should look similar to the following:

<pre>Running CPAchecker with Java heap of size 10000M.
Running CPAchecker with default stack size (1024k). Specify a larger value with -stack if needed.
Using the following resource limits: CPU-time limit of 900s (ResourceLimitChecker.fromConfiguration, INFO)

CPAchecker 1.6.1-svn (OpenJDK 64-Bit Server VM 1.8.0_111) started (CPAchecker.run, INFO)

[...]

line 193: Function pointer *__cil_tmp10 with type int (*)(int, int) is called,
 but no possible target functions were found. (CFunctionPointerResolver.replaceFunctionPointerCall, WARNING)

Using predicate analysis with SMTInterpol 2.1-327-g92cafef and JFactory 1.21. (PredicateCPA:PredicateCPA.<init>, INFO)

Using refinement for predicate analysis with PredicateAbstractionRefinementStrategy strategy.
 (PredicateCPA:PredicateCPARefiner.<init>, INFO)

Starting analysis ... (CPAchecker.runAlgorithm, INFO)

[..]

Automaton going to ErrorState on edge "__VERIFIER_error();"
(WitnessAutomaton:AutomatonTransferRelation.getFollowStates, INFO)

[..]

Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: FALSE. Property violation (WitnessAutomaton) found by chosen configuration.
More details about the verification run can be found in the directory "./output".
</pre>

The verification result *"FALSE"* means that the violation witness was successfully validated, i.e., one of the paths that is described by the witness automaton leads to a violation of the specification. The result *"TRUE"* would mean that none of the paths described by the witness automaton lead to a violation of the specification, or in other words, that the witness was rejected. A witness is also rejected if the witness validation does not terminate normally.

### Validating a Violation Witness with Ultimate Automizer
Download a current version of Ultimate Automizer from [Ultimate Automizer's GitHub page](https://github.com/ultimate-pa/ultimate/releases) or use the [latest SVCOMP release](http://ultimate.informatik.uni-freiburg.de/downloads/svcomp2018/UltimateAutomizer-linux.zip) (supports only Linux platforms).

The following command will start Ultimate Automizer to validate an violation witness for ``test.c``. We assume that the violation witnesses is stored in the file ``witness-to-validate.graphml``.

<pre>./Ultimate.py \
--spec PropertyUnreachCall.prp \
--file test.c \
--architecture 32bit \
--validate witness-to-validate.graphml
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to use the parameter ``--architecture 64bit`` instead of ``--architecture 32bit``.
You can use the additional parameter ``--full-output`` to get the complete log of the validation run.

The output of the command should look similar to the following:

<pre>
# ./Ultimate.py --spec PropertyUnreachCall.prp --file test.c --architecture 32bit --validate witness-to-validate.graphml

Checking for ERROR reachability
Using default analysis
Version 2f4433ab
Calling Ultimate with: java -Xmx12G -Xms1G -jar [...] -data [...] -tc [...] -i test.c witness-to-validate.graphml -s [...] --cacsl2boogietranslator.entry.function main
.......
Execution finished normally
Writing output log to file Ultimate.log
Writing human readable error path to file UltimateCounterExample.errorpath
Result:
FALSE
</pre>

The verification result *"FALSE"* means that the violation witness was successfully validated, i.e., one of the paths that is described by the witness automaton leads to a violation of the specification. The result *"TRUE"* would mean that none of the paths described by the witness automaton lead to a violation of the specification, in other words, the witness was rejected. A witness is also rejected if the witness validation does not terminate normally.

If you are having trouble using the witness validation, contact the Ultimate team by [creating an issue on GitHub](https://github.com/ultimate-pa/ultimate).

### Writing a Violation Witness with CPAchecker

In the following example, we assume that the current directory is the CPAchecker directory, ``PropertyUnreachCall.prp`` is the specification that was used to produce the witness, ``witness.graphml`` is the witness file and ``test.c`` is the verification task. The following command shows how to use CPAchecker to verify the task and produce a witness:

<pre>scripts/cpa.sh -noout -heap 10000M -predicateAnalysis \
-setprop cpa.composite.aggregateBasicBlocks=false \
-setprop cfa.simplifyCfa=false \
-setprop cfa.allowBranchSwapping=false \
-setprop cpa.predicate.ignoreIrrelevantVariables=false \
-setprop counterexample.export.assumptions.assumeLinearArithmetics=true \
-setprop counterexample.export.assumptions.includeConstantsForPointers=false \
-setprop counterexample.export.graphml=violation-witness.graphml \
-setprop counterexample.export.compressErrorWitness=false \
-spec PropertyUnreachCall.prp \
test.c
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to add the parameter ``-64`` to the command line.

The output of the command should look similar to the following:

<pre>Running CPAchecker with Java heap of size 10000M.
Running CPAchecker with default stack size (1024k). Specify a larger value with -stack if needed.
Using the following resource limits: CPU-time limit of 900s (ResourceLimitChecker.fromConfiguration, INFO)

CPAchecker 1.6.1-svn (OpenJDK 64-Bit Server VM 1.8.0_111) started (CPAchecker.run, INFO)

[...]

Using predicate analysis with SMTInterpol 2.1-327-g92cafef and JFactory 1.21. (PredicateCPA:PredicateCPA.<init>, INFO)

Using refinement for predicate analysis with PredicateAbstractionRefinementStrategy strategy. (PredicateCPA:PredicateCPARefiner.<init>, INFO)

Starting analysis ... (CPAchecker.runAlgorithm, INFO)

Error path found, starting counterexample check with CPACHECKER. (CounterexampleCheckAlgorithm.checkCounterexample, INFO)

Using the following resource limits: CPU-time limit of 900s (CounterexampleCheck:ResourceLimitChecker.fromConfiguration, INFO)

Repeated loading of Eclipse source parser (CounterexampleCheck:EclipseParsers.getClassLoader, INFO)

Error path found and confirmed by counterexample check with CPACHECKER. (CounterexampleCheckAlgorithm.checkCounterexample, INFO)

Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: FALSE. Property violation (__VERIFIER_error(); called in line 410) found by chosen configuration.
More details about the verification run can be found in the directory "./output".

Using refinement for predicate analysis with PredicateAbstractionRefinementStrategy strategy.
(PredicateCPA:PredicateCPARefiner.init, INFO)
</pre>

The violation-witness automaton is written to ``output/witness.graphml``. If the verification is applied an [example program](minepump_spec1_product33_false-unreach-call_false-termination.cil.c) and [specification](PropertyUnreachCall.prp) from the SV-COMP'17 benchmark set, the witness should look similar to [this witness](minepump_spec1_product33_false-unreach-call_false-termination.cil.graphml).

### Writing a Violation Witness with Ultimate Automizer
From the Ultimate Automizer directory, the following command will start Ultimate Automizer to verify a task for which it will come up with a feasible counterexample:

<pre>./Ultimate.py \
--spec PropertyUnreachCall.prp \
--file test.c \
--architecture 32bit
</pre>

For tasks where a 64 bit linux machine model is assumed, you also need to use the parameter ``--architecture 64bit`` instead of ``--architecture 32bit``.
You can use the additional parameter ``--full-output`` to get the complete log of the verification run.

The output of the command should look similar to the following:

<pre>
# ./Ultimate.py --spec PropertyUnreachCall.prp --file test.c --architecture 32bit
Checking for ERROR reachability
Using default analysis
Version 2f4433ab
Calling Ultimate with: java -Xmx12G -Xms1G -jar [...] -data [...] -tc [...] -i test.c -s [...] --cacsl2boogietranslator.entry.function main --witnessprinter.witness.directory [...] --witnessprinter.witness.filename witness.graphml --witnessprinter.write.witness.besides.input.file false --witnessprinter.graph.data.specification [...] --witnessprinter.graph.data.producer Automizer --witnessprinter.graph.data.architecture 32bit --witnessprinter.graph.data.programhash [...]
.............
Execution finished normally
Writing output log to file Ultimate.log
Writing human readable error path to file UltimateCounterExample.errorpath
Result:
FALSE
</pre>

The violation-witness automaton is written to ``witness.graphml``. If the verification is applied an [example program](minepump_spec1_product33_false-unreach-call_false-termination.cil.c) and [specification](PropertyUnreachCall.prp) from the SV-COMP'17 benchmark set, the witness should look similar to [this witness](minepump_spec1_product33_false-unreach-call_false-termination.cil.ultimateautomizer.graphml).

## Validating Correctness Witnesses

As a running example, we use the verification task [multivar_true-unreach-call1.i](multivar_true-unreach-call1.i) from the SV-COMP'17 benchmark set.

We assume that the program as well as its [specification](PropertyUnreachCall.prp) have been placed in the desired tool's directory.

### Producing Correctness Witnesses with CPAchecker

To produce a witness for the example task with CPAchecker, simply execute the following commands:

<pre>scripts/cpa.sh \
-correctness-witnesses-k-induction \
-spec PropertyUnreachCall.prp \
multivar_true-unreach-call1.i
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
at ``output/correctness-witness.graphml``.

### Producing Correctness Witnesses with Ultimate Automizer
The procedure for producing a correctness witness with Ultimate Automizer does not differ from producing a violation witness.
To produce a witness for the example task, simply execute the following commands:

<pre>./Ultimate.py \
--spec PropertyUnreachCall.prp \
--file multivar_true-unreach-call1.i \
--architecture 32bit
</pre>

The output of Ultimate Automizer should look similar to the following listing:

For tasks where a 64 bit linux machine model is assumed, you also need to use the parameter ``--architecture 64bit`` instead of ``--architecture 32bit``.
You can use the additional parameter ``--full-output`` to get the complete log of the verification run.

The output of the command should look similar to the following:

<pre>
# ./Ultimate.py --spec PropertyUnreachCall.prp --file multivar_true-unreach-call1.i --architecture 32bit
Checking for ERROR reachability
Using default analysis
Version 2f4433ab
Calling Ultimate with: java -Xmx12G -Xms1G -jar [...] -data [...] -tc [...] -i multivar_true-unreach-call1.i -s [...] --cacsl2boogietranslator.entry.function main --witnessprinter.witness.directory [...] --witnessprinter.witness.filename witness.graphml --witnessprinter.write.witness.besides.input.file false --witnessprinter.graph.data.specification [...] --witnessprinter.graph.data.producer Automizer --witnessprinter.graph.data.architecture 32bit --witnessprinter.graph.data.programhash [...]
.............
Execution finished normally
Writing output log to file Ultimate.log
Result:
TRUE
</pre>

You will find the correctness witness produced by Ultimate Automizer for the example task
at ``witness.graphml``.

### Validating Correctness Witnesses with CPAchecker

For the validation, we assume that one of the previously obtained witnesses for the example task has been named ``correctness-witness.graphml`` and placed in the desired tool directory. To validate the correctness witness with CPAchecker, simply execute the following commands:

<pre>scripts/cpa.sh \
-witnessValidation \
    -witness invariantGeneration.kInduction.invariantsAutomatonFile=correctness-witness.graphml \
    -spec PropertyUnreachCall.prp \
    multivar_true-unreach-call1.i
</pre>

If the witness is valid, the output of CPAchecker should end in the following lines:

<pre>Stopping analysis ... (CPAchecker.runAlgorithm, INFO)

Verification result: TRUE. No property violation found by chosen configuration.
More details about the verification run can be found in the directory "./output".
</pre>

Because the CPAchecker-based validator is actually even a correctness-witness testifier, the validation will produce another (usually more abstract) correctness witness
in ``output/correctness-witness.graphml``.

### Validating Correctness Witnesses with Ultimate Automizer
Again, the procedure for validating a correctness witness with Ultimate Automizer does not differ from validating a violation witness.
For the validation example, we assume that one of the previously obtained witnesses for the example task has been named ``correctness-witness.graphml`` and placed in the desired tool directory. To validate the correctness witness with Ultimate Automizer, simply execute the following commands:

<pre>./Ultimate.py \
--spec PropertyUnreachCall.prp \
--file multivar_true-unreach-call1.i \
--architecture 32bit \
--validate correctness-witness.graphml
</pre>

A successful validation will result in an output similar to the following:

<pre>
# ./Ultimate.py --spec PropertyUnreachCall.prp --file multivar_true-unreach-call1.i --architecture 32bit --validate correctness-witness.graphml
Checking for ERROR reachability
Using default analysis
Version 2f4433ab
Calling Ultimate with: java -Xmx12G -Xms1G -jar [...] -data [...] -tc [...] -i multivar_true-unreach-call1.i correctness-witness.graphml -s [...] --cacsl2boogietranslator.entry.function main
.......
Execution finished normally
Writing output log to file Ultimate.log
Writing human readable error path to file UltimateCounterExample.errorpath
Result:
TRUE
</pre>

### Further Reading

1. Dirk Beyer, Matthias Dangl, Thomas Lemberger, and Michael Tautschnig.
**Tests from Witnesses: Execution-Based Validation of Verification Results.**
In Catherine Dubois and Burkhart Wolff, editors,
*Proceedings of the 12th International Conference on Tests and Proofs (TAP 2018, Toulouse, France, June 27-29)*,
pages 3-23, 2018. Springer.
[DOI: 10.1007/978-3-319-92994-1_1](https://doi.org/10.1007/978-3-319-92994-1_1),
[Preprint](https://www.sosy-lab.org/research/pub/2018-TAP.Tests_from_Witnesses_Execution-Based_Validation_of_Verification_Results.pdf)

2. Dirk Beyer, Matthias Dangl, Daniel Dietsch, and Matthias Heizmann. **Correctness Witnesses: Exchanging Verification Results between Verifiers**. In J. Cleland-Huang and Z. Su, editors, *Proceedings of the 24th ACM SIGSOFT International Symposium on the Foundations of Software Engineering (FSE 2016, Seattle, WA, USA, November 13-18)*, pages 326-337, 2016. ACM, New York.
[DOI: 10.1145/2950290.2950351](https://doi.org/10.1145/2950290.2950351),
[Preprint](https://www.sosy-lab.org/research/pub/2016-FSE.Correctness_Witnesses_Exchanging_Verification_Results_between_Verifiers.pdf)

3. Dirk Beyer and Matthias Dangl. **Verification-Aided Debugging: An Interactive Web-Service for Exploring Error Witnesses**. In S. Chaudhuri and A. Farzan, editors, *Proceedings of the 28th International Conference on Computer Aided Verification (CAV 2016, Toronto, ON, Canada, July 17-23), Part II*, LNCS 9780, pages 502-509, 2016. Springer-Verlag, Heidelberg.
[DOI: 10.1007/978-3-319-41540-6_28](https://doi.org/10.1007/978-3-319-41540-6_28),
[Preprint](https://www.sosy-lab.org/research/pub/2016-CAV.Verification-Aided_Debugging_An_Interactive_Web-Service_for_Exploring_Error_Witnesses.pdf)

4. Dirk Beyer. **Reliable and Reproducible Competition Results with BenchExec and Witnesses (Report on SV-COMP 2016)**. In M. Chechik and J.-F. Raskin, editors, *Proceedings of the 22nd International Conference on Tools and Algorithms for the Construction and Analysis of Systems (TACAS 2016, Eindhoven, The Netherlands, April 2-8)*, pages 887-904, 2016. Springer-Verlag, Heidelberg.
[DOI: 10.1007/978-3-662-49674-9_55](https://doi.org/10.1007/978-3-662-49674-9_55),
[Preprint](https://www.sosy-lab.org/research/pub/2016-TACAS.Reliable_and_Reproducible_Competition_Results_with_BenchExec_and_Witnesses.pdf)

5. Dirk Beyer, Matthias Dangl, Daniel Dietsch, Matthias Heizmann, and Andreas Stahlbauer. **Witness Validation and Stepwise Testification across Software Verifiers**. In E. Di Nitto, M. Harman, and P. Heymans, editors, *Proceedings of the 2015 10th Joint Meeting of the European Software Engineering Conference and the ACM SIGSOFT Symposium on Foundations of Software Engineering (ESEC/FSE 2015, Bergamo, Italy, August 31 - September 4)*, pages 721-733, 2015. ACM, New York.
[DOI: 10.1145/2786805.2786867](https://doi.org/10.1145/2786805.2786867),
[Preprint](https://www.sosy-lab.org/research/pub/2015-FSE15.Witness_Validation_and_Stepwise_Testification_across_Software_Verifiers.pdf)

6. Dirk Beyer. **Software Verification and Verifiable Witnesses (Report on SV-COMP 2015)**. In C. Baier and C. Tinelli, editors, *Proceedings of the 21st International Conference on Tools and Algorithms for the Construction and of Analysis Systems (TACAS 2015, London, UK, April 13-17)*, LNCS 9035, pages 401-416, 2015. Springer-Verlag, Heidelberg.
[DOI: 10.1007/978-3-662-46681-0_31](https://doi.org/10.1007/978-3-662-46681-0_31),
[Preprint](https://www.sosy-lab.org/research/pub/2015-TACAS.Software_Verification_and_Verifiable_Witnesses.pdf)

7. Dirk Beyer, Karlheinz Friedberger. **Violation Witnesses and Result Validation for Multi-Threaded Programs - Implementation and Evaluation with CPAchecker**.
In T. Margaria and B. Steffen, editors, *Proceedings of the 9th International Symposium on Leveraging Applications of Formal Methods
(ISoLA 2020, Rhodes, Greece, October 20-30)*, LNCS 12476, pages 449-470, 2020. Springer-Verlag, Heidelberg.
[DOI: 10.1007/978-3-030-61362-4_26](https://doi.org/10.1007/978-3-030-61362-4_26),
[Print (OpenAccess)](https://link.springer.com/content/pdf/10.1007%2F978-3-030-61362-4_26.pdf)
