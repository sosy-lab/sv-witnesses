# YAML-Based Exchange Format for Correctness Witnesses


## Introduction to Verification Entries

Verification entries represent verification results, including invariants at various program locations.
Their YAML-based, flexible exchange format is designed to be easy to understand by humans
and easy to process by tools.

Each information record is called *verification entry*.
There can be several entries in one file of verification entries.
Loop invariants are an example of an *entry type*.
The format can be extended by other entry types to support exchange of other verification artifacts.

The design goal of this format is to simplify cooperation between tools
that participate in the verification process.

Identification of entries is a major concern: we use UUIDs for references between entries.


## Format Description

Each file of verification entries is formatted in [YAML](http://yaml.org/).

A valid file of verification entries contains an array, even if there is only a single entry.
Files of verification entries are UTF-8 encoded.

Each file of verification entries contains an array of entries.
The format of an entry depends on its entry type.
Currently, we have the following entry types:
- `loop_invariant`
- `loop-invariant_certification`

Entry types are use-case specific and independent.
Each producer and consumer of entries can filter those entry types that it supports.

The following sections describe the format of a verification entry for each entry-type.


### Loop Invariant

Loop invariants are important building blocks in software verification.
There are many verification approaches that use loop invariants as lemmata
to construct a proof of correctness.

In the following, we provide an example, and then a detailed description of the various components.

#### Example

We consider the file [multivar_1-1.c.invariant_witness.yaml](multivar_1-1.c.invariant_witness.yaml),
which is a file of verification entries that contains a verification entry of type
loop invariant.
The verification entries where produced for the verification task
[multivar_1-1.yml](https://github.com/sosy-lab/sv-benchmarks/tree/master/c/loop-acceleration/multivar_1-1.yml)
for program file
[multivar_1-1.c](https://github.com/sosy-lab/sv-benchmarks/tree/master/c/loop-acceleration/multivar_1-1.c).

The verification entry has four parts:
the entry type,
the metadata to describe the provenance of the entry,
the location that this entry talks about, and
the invariant at that location.

```yaml
- entry_type: loop_invariant
  metadata:
    format_version: 0.1
    uuid: 91023a0f-9f45-4385-88c4-1152ade45537
    creation_time: 2021-05-05T15:18:43+02:00
    producer: 
      name: CPAchecker 
      version: 2.0.1-svn
      configuration: (Optional) svcomp21--04-kInduction
      description: (Optional)
      command_line: (Optional)
    task:
      input_files: multivar_1-1.c
      input_file_hashes:
        multivar_1-1.c: 511f45a8d763ef520f6d92e4135c8572805994a66531c6216b17157d0dde2f9c
      specification: CHECK( init(main()), LTL(G ! call(reach_error())) )
      data_model: 32bit
      language: C
  location:
    file_name: multivar_1-1.c
    file_hash: 511f45a8d763ef520f6d92e4135c8572805994a66531c6216b17157d0dde2f9c
    line: 22
    column: 0
    function: main
  loop_invariant: 
    string: (x >= 1024U) && (x <= 4294967295U) && (y == x)
    type: assertion
    format: C
```

#### Description

The following tables describe the format in more detail.

##### entry
| Property          | Data Type     | Format                        | Description   |
|---                | ---           | ---                           | ---           |
| `entry_type`      | string        | "loop_invariant"              | The type of this entry. The format is specific to the entry type. In this case, the entry type declares that the entry contains a loop invariant that holds at some location in a program. |
| `metadata`        | assoc. array  | [see below](#metadata)        | Additional information about the "environment" in which the entry was produced. |
| `location`        | assoc. array  | [see below](#location)        | Location in the source code to which the entry refers, i.e., at which the loop invariant holds. |
| `loop_invariant`  | assoc. array  | [see below](#loop_invariant)  | Actual loop invariant. |

##### metadata
| Property          | Data Type     | Format                  | Description  |
|---                | ---           | ---                     | ---          |
| `format_version`  | string        | "0.1"                   | Version of the verification-entries format that the entry is formatted in. |
| `uuid`            | string        | UUID                    | Unique identifier of the entry ([RFC4122](https://www.ietf.org/rfc/rfc4122.txt) defines the UUID format).  |
| `creation_time`   | string        | ISO 8601                | Date and time when the entry (not the file) was created. |
| `producer`        | assoc. array  | [see below](#producer)  | Tool that produced the entry. |
| `task`            | assoc. array  | [see below](#task)      | Verification task during which the entry was produced. |

##### producer
| Property        | Data Type         | Format                  | Description  |
|---              | ---               | ---                     | ---          |
| `name`          | string            | Any                     | Name of the tool that produced the invariant. |
| `version`       | string            | Any                     | Version of the tool. |
| `configuration` | (optional) string | Any                     | Configuration in which the tool ran. Consider using this property if there are substantially different configurations of the tool. |
| `command_line`  | (optional) string | Bash-compliant command  | Command line with which the tool ran. Specifying the exact command possibly increases reproducibility. |
| `description`   | (optional) string | Any                     | Additional description. Use this property for any information that does not fit into any of the above properties. |

##### task
| Property            | Data Type             | Format                                                        | Description  |
|---                  | ---                   | ---                                                           | ---          |
| `input_files`       | string *or* string[]  | Bash-compliant file-name pattern                              | File(s) that were given as input to the verfier. Each file pattern must represent exactly one input file. |
| `input_file_hashes` | assoc. array          |`<file-pattern> : <file-hash>`                                 | Mapping of each input file to its SHA-256 hash. Every file-name pattern listed in `input_files` must appear in this property. |
| `specification`     | string                | [SV-COMP format](https://sv-comp.sosy-lab.org/2021/rules.php) | Specification against which the program was analyzed for producing the entry. |
| `data_model`        | string                | "32bit" *or* "64bit"                                          | Data model that was assumed for the input program. |
| `language`          | string                | "C"                                                           | Source language of the input files. |

##### location
| Property    | Data Type     | Format                            | Description  |
|---          | ---           | ---                               | ---          |
| `file_name` | string        | Bash-compliant file-name pattern  | Name of the file containing the loop where the invariant holds. Must be present in `task.input_files` |
| `file_hash` | string        | SHA-256 hash                      | Hash of the file containing the loop where the invariant holds. |
| `line`      | integer       | natural number > 1                | Line where the invariant holds (starting with 1). |
| `column`    | integer       | natural number >= 0               | Column where the invariant holds in that line. For example, if `column` has value `0` then the invariant holds *before* the first source-code token of the line. |
| `function`  | string        | func. name in the source language | Name of the function in which the invariant holds. |

##### loop_invariant
| Property    | Data Type | Format              | Description  |
|---          | ---       | ---                 | ---          |
| `string`    | string    | defined in `format` | The actual invariant formula. |
| `type`      | string    | "assertion"         | How to interpret `string`. The following values are supported: <ul><li><em>assertion:</em> Has the C semantics of `assert(<string>)` inserted at the specified `location`.</li></ul> |
| `format`    | string    | "C"                 | Format of the string. The following values are supported: <ul><li><em>C:</em> Expression in C language.</li></ul> |

#### Schema

A [json-schema](http://json-schema.org/) of the format can be found in file
[loop-invariant-schema.json](loop-invariant-schema.json).
This schema can be used for validation and for code generation.


### Loop-Invariant Certification

TODO


