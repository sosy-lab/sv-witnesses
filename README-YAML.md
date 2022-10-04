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
Entry types are use-case specific and independent.
Each producer and consumer of entries can filter those entry types that it supports.

### Schema

All entry types and their formats are specified using
a [json-schema](http://json-schema.org/):
[witness.schema.json](witness.schema.json).

This schema can be used for documentation generation, validation and code generation.


## Examples

The schema itself contains some examples.

### multivar_1-1

Consider the verification task
[multivar_1-1.yml](https://github.com/sosy-lab/sv-benchmarks/tree/master/c/loop-acceleration/multivar_1-1.yml)
with the input program
[multivar_1-1.c](https://github.com/sosy-lab/sv-benchmarks/tree/master/c/loop-acceleration/multivar_1-1.c).

The file
[multivar_1-1.c.invariant_witness.yaml](multivar_1-1.c.invariant_witness.yaml)
contains two verification entries:
1. A `loop_invariant`
2. and a `loop_invariant_certificate` that confirms the `loop_invariant`.
