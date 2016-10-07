# sv-witnesses: An Exchange Format for Violation Witnesses

## Basics

We formally represent violation witnesses as violation-witness automata. Since a violation-witness automaton is a graph, we decided to extend an existing exchange format (GraphML) for graphs and apply it to witness automata. [GraphML](http://graphml.graphdrawing.org/) is an XML-based format for exchanging graphs that was designed with extensibility in mind. (This [primer](http://graphml.graphdrawing.org/primer/graphml-primer.html) gives a good introduction.)

The idea is that a violation-witness automaton guides the verifier for a finite number of steps through the program along an error path in order to find a violation of the safety property.

Note that a violation-witness automaton might represent several possible paths. In particular, the automaton might represent several infeasible error paths and feasible error paths. Ideally, the error path is very short and contains concrete values (test case).

To match witness-automaton states to the C source code, we use token numbers.
The token numbers are the line numbers in the token-normalized format of the program (each token using an own line). The token-normalized version of a program can be produced ---for example--- by the [tokenizer](http://sv-comp.sosy-lab.org/2015/witnesses/c-tokenizer-x86_64-linux.zip) created from the [sparse project](http://git.kernel.org/cgit/devel/sparse/sparse.git/tree/tokenize.c).

## Data Elements

In order to represent the witness automaton in GraphML, the edges and nodes of the graph are enriched with (XML) ``data`` elements of different types. The ``key`` attribute of a data element defines its type, the child elements of the element (usually a single XML text node) represent its value.

### Node Data for Automata States

| key | Meaning |
| --- | --- |
| entry | *Valid values:* ``false`` (default) or ``true`` <br /> This node represents the initial state of the automata (entry node of the graph). Only one initial state (entry node) is allowed. |
| sink | *Valid values:* ``false`` (default) or ``true`` <br />  This node is a sink. All paths that lead to this node end here and should not be further explored by the witness validator. Nodes where this flag is set must not have any leaving edges |

### Edge Data for Automata Transitions

| key | Meaning |
| --- | --- |
| assumption | *Valid values:* Sequence of C assignment statements separated by semicolons. The right-hand side of these assignments **may not** consist of function calls, conjunctions, or disjunctions. <br /> One or more assignment statements representing assumptions about the current state. Local variables that have the same name as global variables or local variables of other functions can be qualified by tracking the call stack the ``enterFunction`` and ``returnFromFunction`` tags. |
| sourcecode | The source code at the edge in token-normalized format. |
| tokenSet | The set of tokens at the edge in token-normalized format. |
| negativeCase | *Valid values:* ``false``(default) or ``true`` <br />  For branching in the code, ``true`` means that the negative branch is taken, while ``false`` means the positive branch is used. |
| lineNumberInOrigin | *Valid values:* Valid line number of the program <br /> Each statement, or expression, on a control-flow edge was derived from a line (or multiple lines - see ``endline``) in the source code. The ``startline`` corresponds to the line number on that a statement, or expression, of a control-flow edge started |
| originFileName | The file name of the program corresponding to the edge. |
| enterFunction | *Valid values:* Function name <br /> The name of the function that is entered via this edge. Assuming a function stack, this pushes the function onto the stack. If you use this data node type, you also must use the type ``returnFromFunction``. The witness validator may use this information to qualify  variable names used in ``assumption`` data tags. The path is considered to stay in the specified function until another edge is annotated with this data node for another function or an edge annotated with ``returnFromFunction``, telling the validator that the path continues in the previous function on the stack. |
| returnFromFunction | *Valid values:* Function name <br /> The name of the function is exited via this edge. Assuming a function stack, this name must match the name of the function popped from the function stack. If you use this data node type, you also must use the type ``enterFunction``. See ``enterFunction`` for more information. |

Tools may introduce their own data nodes with custom keys and values. Other tools should ignore data nodes they do not know or are unable to handle.

This witness specification is a work in progress and will be subject to modifications.
