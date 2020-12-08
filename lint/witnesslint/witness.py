# This file is part of sv-witnesses repository: https://github.com/sosy-lab/sv-witnesses
#
# SPDX-FileCopyrightText: 2020 Dirk Beyer <https://www.sosy-lab.org>
#
# SPDX-License-Identifier: Apache-2.0

"""
This module contains a class for representing witnesses for a linter.
"""

import gzip
import re

DATA = "data"
DEFAULT = "default"
KEY = "key"
NODE = "node"
EDGE = "edge"
GRAPH = "graph"
GRAPHML = "graphml"

WITNESS_TYPE = "witness-type"
SOURCECODELANG = "sourcecodelang"
PRODUCER = "producer"
SPECIFICATION = "specification"
PROGRAMFILE = "programfile"
PROGRAMHASH = "programhash"
ARCHITECTURE = "architecture"
CREATIONTIME = "creationtime"
ENTRY = "entry"
SINK = "sink"
VIOLATION = "violation"
INVARIANT = "invariant"
INVARIANT_SCOPE = "invariant.scope"
CYCLEHEAD = "cyclehead"
ASSUMPTION = "assumption"
ASSUMPTION_SCOPE = "assumption.scope"
ASSUMPTION_RESULTFUNCTION = "assumption.resultfunction"
CONTROL = "control"
STARTLINE = "startline"
ENDLINE = "endline"
STARTOFFSET = "startoffset"
ENDOFFSET = "endoffset"
ENTERLOOPHEAD = "enterLoopHead"
ENTERFUNCTION = "enterFunction"
RETURNFROMFUNCTION = "returnFromFunction"
THREADID = "threadId"
CREATETHREAD = "createThread"

COMMON_KEYS = {
    WITNESS_TYPE: GRAPH,
    SOURCECODELANG: GRAPH,
    PRODUCER: GRAPH,
    SPECIFICATION: GRAPH,
    PROGRAMFILE: GRAPH,
    PROGRAMHASH: GRAPH,
    ARCHITECTURE: GRAPH,
    CREATIONTIME: GRAPH,
    ENTRY: NODE,
    SINK: NODE,
    VIOLATION: NODE,
    INVARIANT: NODE,
    INVARIANT_SCOPE: NODE,
    CYCLEHEAD: NODE,
    ASSUMPTION: EDGE,
    ASSUMPTION_SCOPE: EDGE,
    ASSUMPTION_RESULTFUNCTION: EDGE,
    CONTROL: EDGE,
    STARTLINE: EDGE,
    ENDLINE: EDGE,
    STARTOFFSET: EDGE,
    ENDOFFSET: EDGE,
    ENTERLOOPHEAD: EDGE,
    ENTERFUNCTION: EDGE,
    RETURNFROMFUNCTION: EDGE,
    THREADID: EDGE,
    CREATETHREAD: EDGE,
}

TERMINATION_PROPERTY_PATTERN = (
    r"CHECK[(]\s*init[(]\s*\w+[(][)]\s*[)]\s*,\s*LTL[(]\s*F\s+end\s*[)]\s*[)]"
)


class Witness:
    def __init__(self, witness_file):
        self.witness_file = witness_file
        with gzip.open(witness_file) as unzipped_witness:
            try:
                unzipped_witness.read(1)
                zipped = True
            except OSError:
                zipped = False
        if zipped:
            self.witness_file = gzip.open(witness_file)
        self.witness_type = None
        self.sourcecodelang = None
        self.producer = None
        self.specifications = set()
        self.programfile = None
        self.programhash = None
        self.architecture = None
        self.creationtime = None
        self.entry_node = None
        self.cyclehead = None
        self.node_ids = set()
        self.sink_nodes = set()
        self.defined_keys = {}
        self.used_keys = set()
        self.threads = {}
        self.thread_creations = set()
        self.thread_ids = set()
        self.transition_sources = set()
        self.transitions = {}

    def is_termination_witness(self):
        if self.cyclehead is not None:
            return True
        termination_pattern = re.compile(TERMINATION_PROPERTY_PATTERN)
        for spec in self.specifications:
            if re.match(termination_pattern, spec):
                return True
        return False
