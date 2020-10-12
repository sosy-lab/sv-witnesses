## Linter for checking witnesses

The witness linter can be used to make sure that a given witness conforms to the exchange format.

### Requirements

The following modules are necessary to use the witness linter:

- lxml
- zlib

### Usage

In order to use the witness linter you can run

```
python3 witnesslint.py [<options>] <path_to_witness>
```

For information on available options use

```
python3 witnesslint.py -h
```

Currently supported options are:

```
  -h, --help           show this help message and exit
  --version            show program's version number and exit
  --loglevel LOGLEVEL  Desired verbosity of logging output. Only log messages
                       at or above the specified level are displayed.
  --program PROGRAM    The program for which the witness was created.
  --checkProgram       Perform some additional checks involving the program
                       file. Better left disabled for big witnesses. This
                       option is implicitly used when a program is given via
                       the --program option.
  --checkCallstack     Check whether transitions specified via enterFunction
                       and returnFromFunction are consistent. Better left
                       disabled for big witnesses.
  --ignoreSelfLoops    Produce no warnings when encountering edges that
                       represent a self-loop.
```

### Output

For every inconsistency the linter detects a message is logged. The format of these messages is as follows:

```
<severity_level> : (<position> :) <description>
```

The severity level is one of ``debug``, ``info``, ``warning``, ``error`` or ``critical``. By default only inconsistencies with a severity level of ``warning`` and higher are logged but this behavior can be changed via the ``--loglevel`` option.
The logged position is the line number where the inconsistency was found in the witness. This information is usually present but can be omitted e.g. when the inconsistency can not be attributed to a single line in the witness.
The description contains information about the inconsistency.

In addition to these messages, the linter provides a machine-readable pass-fail-verdict via its return code. The given witness adheres to the exchange format only if the linter exits with code 0 which is equivalent to no inconsistencies of severity ``warning`` or higher being found, regardless of whether they are logged or not.

#### Example

Consider the following witness ``faulty-witness-2.graphml``:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<graphml>
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
  <data key="programfile">example-2.i</data>
  <data key="programhash">38a09cb40577ff27f33504302e5bf6fedcac610c6128114db6fbf6c2967c47de</data>
  <data key="memorymodel">precise</data>
  <data key="architecture">32bit</data>
  <node id="entry">
   <data key="entry">true</data>
  </node>
  <node id="error">
   <data key="violation">true</data>
   <data key="sink">maybe</data>
  </node>
  <node/>
  <node id="q1">
   <data key="invariant">x > 0</data>
  </node>
  <edge target="q1">
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
  <edge source="q2" target="q3">
   <data key="startline">9</data>
   <data key="assumption">\result == 40</data>
   <data key="assumption.scope">main</data>
   <data key="assumption.resultfunction">__VERIFIER_nondet_int</data>
  </edge>
 </graph>
</graphml>
```

Running the linter with this witness as input produces the following output:

```
WARNING : line 35: Invalid value for key 'sink': maybe
WARNING : line 37: Expected node element to have attribute 'id'
WARNING : line 41: Edge is missing attribute 'source'
WARNING : line 2: Missing default namespace
WARNING : line 2: Missing xml schema namespace or namespace prefix is not called 'xsi'
WARNING : Key 'sink' has been used but not defined
WARNING : Key 'invariant' has been used but not defined
WARNING : Creationtime has not been specified
WARNING : Key 'invariant' is not allowed in violation witness
WARNING : Node q3 has not been declared
```
