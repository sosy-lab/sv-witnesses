#!/usr/bin/env python3

# This file is part of sv-witnesses repository: https://github.com/sosy-lab/sv-witnesses
#
# SPDX-FileCopyrightText: 2020 Dirk Beyer <https://www.sosy-lab.org>
#
# SPDX-License-Identifier: Apache-2.0

"""
This module contains a linter that can check witnesses for consistency
with the witness format [1].

[1]: github.com/sosy-lab/sv-witnesses/blob/master/README.md
"""

__version__ = "1.0"

import argparse
import collections
import hashlib
import re
import sys
import time

from lxml import etree as ET

sys.dont_write_bytecode = True  # prevent creation of .pyc files

import lint.logger as logging
import lint.witness as witness

CREATIONTIME_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([+-]\d{2}:\d{2})?$"

WITNESS_VALID = 0
WITNESS_FAULTY = 1
INTERNAL_ERROR = 7


def create_linter(argv):
    arg_parser = create_arg_parser()
    parsed_args = arg_parser.parse_args(argv)
    logging.create_logger(parsed_args.loglevel)
    program = parsed_args.program
    if program is not None:
        program = program.name
    parsed_args.checkProgram = parsed_args.checkProgram or program is not None
    return WitnessLinter(
        witness.Witness(parsed_args.witness.name), program, parsed_args
    )


def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--version",
        action="version",
        version="This is version {} of the witness linter.".format(__version__),
    )
    parser.add_argument(
        "witness",
        help="GraphML file containing a witness.",
        type=argparse.FileType("r"),
        metavar="WITNESS",
    )
    parser.add_argument(
        "--loglevel",
        default="warning",
        choices=["critical", "error", "warning", "info", "debug"],
        help="Desired verbosity of logging output. Only log messages at or above "
        "the specified level are displayed.",
        metavar="LOGLEVEL",
    )
    parser.add_argument(
        "--program",
        help="The program for which the witness was created.",
        type=argparse.FileType("r"),
        metavar="PROGRAM",
    )
    parser.add_argument(
        "--checkProgram",
        help="Perform some additional checks involving the program file. "
        "Better left disabled for big witnesses. This option is "
        "implicitly used when a program is given via the --program option.",
        action="store_true",
    )
    parser.add_argument(
        "--checkCallstack",
        help="Check whether transitions specified via enterFunction "
        "and returnFromFunction are consistent. "
        "Better left disabled for big witnesses.",
        action="store_true",
    )
    parser.add_argument(
        "--ignoreSelfLoops",
        help="Produce no warnings when encountering "
        "edges that represent a self-loop.",
        action="store_true",
    )
    return parser


def determine_exit_code():
    if logging.critical.counter or logging.error.counter or logging.warning.counter:
        return WITNESS_FAULTY
    return WITNESS_VALID


class WitnessLinter:
    """
    Contains methods that check different parts of a witness for consistency
    with the witness format as well as some utility methods for this purpose.
    The lint() method checks the whole witness.
    """

    def __init__(self, witness, program, options):
        self.witness = witness
        self.program_info = None
        if program is not None:
            self.collect_program_info(program)
        self.options = options
        self.violation_witness_only = set()
        self.correctness_witness_only = set()
        self.check_existence_later = set()
        self.check_later = list()

    def collect_program_info(self, program):
        """
        Collects and stores some data about the program for later usage.

        This method assumes that the given program can be accessed.
        """
        with open(program, "r") as source:
            content = source.read()
            num_chars = len(content)
            num_lines = len(content.split("\n"))
            # TODO: Collect all function names
            function_names = list()
        with open(program, "rb") as source:
            content = source.read()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
        self.program_info = {
            "name": program,
            "num_chars": num_chars,
            "num_lines": num_lines,
            "sha1_hash": sha1_hash,
            "sha256_hash": sha256_hash,
            "function_names": function_names,
        }

    def check_functionname(self, name, pos):
        if not self.options.checkProgram:
            return
        if self.program_info is None:
            self.check_later.append(lambda: self.check_functionname(name, pos))
        elif name not in self.program_info["function_names"]:
            logging.warning(
                "'{}' is not a functionname of the program".format(name), pos
            )

    def check_linenumber(self, line, pos):
        if not self.options.checkProgram:
            return
        if self.program_info is None:
            self.check_later.append(lambda: self.check_linenumber(line, pos))
        elif int(line) < 1 or int(line) > self.program_info["num_lines"]:
            logging.warning("{} is not a valid linenumber".format(line), pos)

    def check_character_offset(self, offset, pos):
        if not self.options.checkProgram:
            return
        if self.program_info is None:
            self.check_later.append(lambda: self.check_character_offset(offset, pos))
        elif int(offset) < 0 or int(offset) >= self.program_info["num_chars"]:
            logging.warning("{} is not a valid character offset".format(offset), pos)

    def check_function_stack(self, transitions, start_node):
        """
        Performs DFS on the given transitions to make sure that all
        possible paths have a consistent order of function entries and exits.
        """
        to_visit = [(start_node, [])]
        visited = set()
        while to_visit:
            current_node, current_stack = to_visit.pop()
            if current_node in visited:
                continue
            visited.add(current_node)
            if current_node not in transitions and current_stack:
                logging.warning(
                    "No leaving transition for node {} but not all "
                    "functions have been left".format(current_node)
                )
            for outgoing in transitions.get(current_node, list()):
                function_stack = current_stack[:]
                if outgoing[2] is not None and outgoing[2] != outgoing[1]:
                    if not function_stack:
                        logging.warning(
                            "Trying to return from function '{0}' in transition "
                            "{1} -> {2} but currently not in a function".format(
                                outgoing[2], current_node, outgoing[0]
                            )
                        )
                    elif outgoing[2] == current_stack[-1]:
                        function_stack.pop()
                    else:
                        logging.warning(
                            "Trying to return from function '{0}' in transition "
                            "{1} -> {2} but currently in function {3}".format(
                                outgoing[2],
                                current_node,
                                outgoing[0],
                                function_stack[-1],
                            )
                        )
                if outgoing[1] is not None and outgoing[1] != outgoing[2]:
                    function_stack.append(outgoing[1])
                to_visit.append((outgoing[0], function_stack))

    def handle_data(self, data, parent):
        """
        Performs checks that are common to all data elements and invokes appropriate
        specialized checks.

        A data element must have a 'key' attribute specifying
        the kind of data it holds.

        Data elements in a witness are currently not supposed have any children.
        """
        if len(data) > 0:
            logging.warning(
                "Expected data element to not have any children but has {}".format(
                    len(data)
                ),
                data.sourceline,
            )
        if len(data.attrib) > 1:
            logging.warning(
                "Expected data element to have exactly one attribute "
                "but has {}".format(len(data.attrib)),
                data.sourceline,
            )
        key = data.attrib.get(witness.KEY)
        if key is None:
            logging.warning(
                "Expected data element to have attribute 'key'", data.sourceline
            )
        else:
            self.witness.used_keys.add(key)
            _, _, tag = parent.tag.rpartition("}")
            if tag == witness.NODE:
                self.handle_node_data(data, key, parent)
            elif tag == witness.EDGE:
                self.handle_edge_data(data, key, parent)
            elif tag == witness.GRAPH:
                self.handle_graph_data(data, key)
            else:
                raise AssertionError("Invalid parent element of type " + parent.tag)

    def handle_node_data(self, data, key, parent):
        """
        Performs checks for data elements that are direct children of a node element.
        """
        if key == witness.ENTRY:
            if data.text == "true":
                if self.witness.entry_node is None:
                    self.witness.entry_node = parent.attrib.get("id", "")
                else:
                    logging.warning("Found multiple entry nodes", data.sourceline)
            elif data.text == "false":
                logging.info(
                    "Specifying value 'false' for key 'entry' is unnecessary",
                    data.sourceline,
                )
            else:
                logging.warning(
                    "Invalid value for key 'entry': {}".format(data.text),
                    data.sourceline,
                )
        elif key == witness.SINK:
            if data.text == "false":
                logging.info(
                    "Specifying value 'false' for key 'sink' is unnecessary",
                    data.sourceline,
                )
            elif data.text == "true":
                node_id = parent.attrib.get("id")
                if node_id is not None:
                    if (
                        node_id in self.witness.transition_sources
                        or node_id in self.witness.transitions
                    ):
                        logging.warning(
                            "Sink node should have no leaving edges", data.sourceline
                        )
                    self.witness.sink_nodes.add(node_id)
            else:
                logging.warning(
                    "Invalid value for key 'sink': {}".format(data.text),
                    data.sourceline,
                )
            self.violation_witness_only.add(key)
        elif key == witness.VIOLATION:
            if data.text == "false":
                logging.info(
                    "Specifying value 'false' for key 'violation' is unnecessary",
                    data.sourceline,
                )
            elif not data.text == "true":
                logging.warning(
                    "Invalid value for key 'violation': {}".format(data.text),
                    data.sourceline,
                )
            self.violation_witness_only.add(key)
        elif key == witness.INVARIANT:
            self.correctness_witness_only.add(key)
            # TODO: Check whether data.text is a valid invariant
        elif key == witness.INVARIANT_SCOPE:
            self.correctness_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif self.witness.defined_keys.get(key) == witness.NODE:
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.warning(
                "Unknown key for node data element: {}".format(key), data.sourceline
            )

    def handle_edge_data(self, data, key, parent):
        """
        Performs checks for data elements that are direct children of an edge element.
        """
        if key == witness.ASSUMPTION:
            self.violation_witness_only.add(key)
            # TODO: Check whether all expressions from data.text are valid assumptions
            if "\\result" in data.text:
                resultfunction_present = False
                for child in parent:
                    if (
                        child.tag.rpartition("}")[2] == witness.DATA
                        and child.attrib.get(witness.KEY)
                        == witness.ASSUMPTION_RESULTFUNCTION
                    ):
                        resultfunction_present = True
                        break
                if not resultfunction_present:
                    logging.warning(
                        "Found assumption containing '\\result' but "
                        "no resultfunction was specified",
                        data.sourceline,
                    )
        elif key == witness.ASSUMPTION_SCOPE:
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == witness.ASSUMPTION_RESULTFUNCTION:
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == witness.CONTROL:
            if data.text not in ["condition-true", "condition-false"]:
                logging.warning(
                    "Invalid value for key 'control': {}".format(data.text),
                    data.sourceline,
                )
            self.violation_witness_only.add(key)
        elif key == witness.STARTLINE:
            self.check_linenumber(data.text, data.sourceline)
        elif key == witness.ENDLINE:
            self.check_linenumber(data.text, data.sourceline)
        elif key == witness.STARTOFFSET:
            self.check_character_offset(data.text, data.sourceline)
        elif key == witness.ENDOFFSET:
            self.check_character_offset(data.text, data.sourceline)
        elif key == witness.ENTERLOOPHEAD:
            if data.text == "false":
                logging.info(
                    "Specifying value 'false' for key 'enterLoopHead' is unnecessary",
                    data.sourceline,
                )
            elif not data.text == "true":
                logging.warning(
                    "Invalid value for key 'enterLoopHead': {}".format(data.text),
                    data.sourceline,
                )
        elif key == witness.ENTERFUNCTION:
            for child in parent:
                if (
                    child.tag.rpartition("}")[2] == witness.DATA
                    and child.attrib.get(witness.KEY) == witness.THREADID
                    and self.witness.threads[child.text] is None
                ):
                    self.witness.threads[child.text] = data.text
                    break
            self.check_functionname(data.text, data.sourceline)
        elif key in ["returnFrom", witness.RETURNFROMFUNCTION]:
            for child in parent:
                if (
                    child.tag.rpartition("}")[2] == witness.DATA
                    and child.attrib.get(witness.KEY) == witness.THREADID
                    and self.witness.threads[child.text] == data.text
                ):
                    del self.witness.threads[child.text]
                    break
            self.check_functionname(data.text, data.sourceline)
        elif key == witness.THREADID:
            if data.text not in self.witness.threads:
                logging.warning(
                    "Thread with id {} doesn't exist".format(data.text),
                    data.sourceline,
                )
        elif key == witness.CREATETHREAD:
            if data.text in self.witness.threads:
                logging.warning(
                    "Thread with id {} has already been created".format(data.text),
                    data.sourceline,
                )
            else:
                self.witness.threads[data.text] = None
        elif self.witness.defined_keys.get(key) == witness.EDGE:
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.warning(
                "Unknown key for edge data element: {}".format(key), data.sourceline
            )

    def handle_graph_data(self, data, key):
        """
        Performs checks for data elements that are direct children of a graph element.
        """
        if key == witness.WITNESS_TYPE:
            if data.text not in ["correctness_witness", "violation_witness"]:
                logging.warning(
                    "Invalid value for key 'witness-type': {}".format(data.text),
                    data.sourceline,
                )
            elif self.witness.witness_type is None:
                self.witness.witness_type = data.text
            else:
                logging.warning(
                    "Found multiple definitions of witness-type", data.sourceline
                )
        elif key == witness.SOURCECODELANG:
            if data.text not in ["C", "Java"]:
                logging.warning(
                    "Invalid value for key 'sourcecodelang': {}".format(data.text),
                    data.sourceline,
                )
            elif self.witness.sourcecodelang is None:
                self.witness.sourcecodelang = data.text
            else:
                logging.warning(
                    "Found multiple definitions of sourcecodelang", data.sourceline
                )
        elif key == witness.PRODUCER:
            if self.witness.producer is None:
                self.witness.producer = data.text
            else:
                logging.warning(
                    "Found multiple definitions of producer", data.sourceline
                )
        elif key == "specification":
            self.witness.specifications.add(data.text)
        elif key == witness.PROGRAMFILE:
            if self.witness.programfile is None:
                self.witness.programfile = data.text
                try:
                    source = open(self.witness.programfile)
                    source.close()
                    if self.program_info is None:
                        self.collect_program_info(self.witness.programfile)
                except FileNotFoundError:
                    logging.info(
                        "Programfile specified in witness could not be accessed",
                        data.sourceline,
                    )
            else:
                logging.warning(
                    "Found multiple definitions of programfile", data.sourceline
                )
        elif key == witness.PROGRAMHASH:
            if (
                self.program_info is not None
                and data.text.lower() != self.program_info.get("sha256_hash")
                and data.text.lower() != self.program_info.get("sha1_hash")
            ):
                logging.warning(
                    "Programhash does not match the hash specified in the witness",
                    data.sourceline,
                )
            if self.witness.programhash is None:
                self.witness.programhash = data.text
            else:
                logging.warning(
                    "Found multiple definitions of programhash", data.sourceline
                )
        elif key == witness.ARCHITECTURE:
            if self.witness.architecture is not None:
                logging.warning(
                    "Found multiple definitions of architecture", data.sourceline
                )
            elif data.text in ["32bit", "64bit"]:
                self.witness.architecture = data.text
            else:
                logging.warning("Invalid architecture identifier", data.sourceline)
        elif key == witness.CREATIONTIME:
            if self.witness.creationtime is not None:
                logging.warning(
                    "Found multiple definitions of creationtime", data.sourceline
                )
            elif re.match(CREATIONTIME_PATTERN, data.text.strip()):
                self.witness.creationtime = data.text
            else:
                logging.warning("Invalid format for creationtime", data.sourceline)
        elif self.witness.defined_keys.get(key) == witness.GRAPH:
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.warning(
                "Unknown key for graph data element: {}".format(key), data.sourceline
            )

    def handle_key(self, key):
        """
        Checks a key definition for validity.

        Should the key definition contain the mandatory 'id' and 'for'
        attributes the defined key may be used in the appropriate
        data elements of any following graph definitions, even if
        the key definition is faulty for other reasons.

        Appropriate are all data elements that are direct children
        of an element of type key_domain, which is the value of the 'for' attribute.

        Key definitions in a witness may have a child element of type 'default'
        specifying the default value for this key, but are currently expected
        to have no other children.
        """
        key_id = key.attrib.get("id")
        key_domain = key.attrib.get("for")
        if key_id and key_domain:
            if key_id in self.witness.defined_keys:
                logging.warning(
                    "Found multiple key definitions with id '{}'".format(key_id),
                    key.sourceline,
                )
            else:
                if witness.COMMON_KEYS.get(key_id, key_domain) != key_domain:
                    logging.warning(
                        "Key '{0}' should be used for '{1}' elements but "
                        "was defined for '{2}' elements".format(
                            key_id, witness.COMMON_KEYS[key_id], key_domain
                        ),
                        key.sourceline,
                    )
                self.witness.defined_keys[key_id] = key_domain
        else:
            if key_id is None:
                logging.warning("Key is missing attribute 'id'", key.sourceline)
            if key_domain is None:
                logging.warning("Key is missing attribute 'for'", key.sourceline)
        if len(key) > 1:
            logging.warning(
                "Expected key to have at most one child but has {}".format(len(key)),
                key.sourceline,
            )
        for child in key:
            if child.tag.rpartition("}")[2] == witness.DEFAULT:
                if len(child.attrib) != 0:
                    logging.warning(
                        "Expected no attributes for 'default'"
                        "element but found {0} ({1})".format(
                            len(child.attrib), list(child.attrib)
                        ),
                        key.sourceline,
                    )
                if key_id in [
                    witness.ENTRY,
                    witness.SINK,
                    witness.VIOLATION,
                    witness.ENTERLOOPHEAD,
                ]:
                    if not child.text == "false":
                        logging.warning(
                            "Default value for {} should be 'false'".format(key_id),
                            key.sourceline,
                        )
            else:
                logging.warning(
                    "Invalid child for key element: {}".format(child.tag),
                    child.sourceline,
                )

    def handle_node(self, node):
        """
        Checks a node element for validity.

        Nodes must have an unique id but should not have any other attributes.

        Nodes in a witness are currently not supposed have any non-data children.
        """
        if len(node.attrib) > 1:
            logging.warning(
                "Expected node element to have exactly one attribute "
                "but has {}".format(len(node.attrib)),
                node.sourceline,
            )
        node_id = node.attrib.get("id")
        if node_id is None:
            logging.warning(
                "Expected node element to have attribute 'id'", node.sourceline
            )
        elif node_id in self.witness.node_ids:
            logging.warning(
                "Found multiple nodes with id '{}'".format(node_id), node.sourceline
            )
        else:
            self.witness.node_ids.add(node_id)
        for child in node:
            if child.tag.rpartition("}")[2] == witness.DATA:
                self.handle_data(child, node)
            else:
                logging.warning(
                    "Node has unexpected child element of type '{}'".format(child.tag),
                    child.sourceline,
                )

    def handle_edge(self, edge):
        """
        Checks an edge element for validity.

        Edges must have attributes 'source' and 'target', each referencing
        a different existing node by its id.

        Other attributes are allowed but no checks are currently performed for them.

        Edges in a witness are currently not supposed to have any non-data children.
        """
        source = edge.attrib.get("source")
        if source is None:
            logging.warning("Edge is missing attribute 'source'", edge.sourceline)
        else:
            if source in self.witness.sink_nodes:
                logging.warning(
                    "Sink node should have no leaving edges", edge.sourceline
                )
            if not self.options.checkCallstack:
                # Otherwise this information is stored in self.witness.transitions
                self.witness.transition_sources.add(source)
            if source not in self.witness.node_ids:
                self.check_existence_later.add(source)
        target = edge.attrib.get("target")
        if target is None:
            logging.warning("Edge is missing attribute 'target'", edge.sourceline)
        else:
            if source == target and not self.options.ignoreSelfLoops:
                logging.warning(
                    "Node '{}' has self-loop".format(source), edge.sourceline
                )
            if target not in self.witness.node_ids:
                self.check_existence_later.add(target)
        if self.options.checkCallstack:
            enter, return_from = (None, None)
            for child in edge:
                if child.tag.rpartition("}")[2] == witness.DATA:
                    self.handle_data(child, edge)
                    key = child.attrib.get(witness.KEY)
                    if key == witness.ENTERFUNCTION:
                        enter = child.text
                    elif key in ["returnFrom", witness.RETURNFROMFUNCTION]:
                        return_from = child.text
                else:
                    logging.warning(
                        "Edge has unexpected child element of type '{}'".format(
                            child.tag
                        ),
                        child.sourceline,
                    )
            if source and target:
                if source in self.witness.transitions:
                    self.witness.transitions[source].append(
                        (target, enter, return_from)
                    )
                else:
                    self.witness.transitions[source] = [(target, enter, return_from)]
        else:
            for child in edge:
                if child.tag.rpartition("}")[2] == witness.DATA:
                    self.handle_data(child, edge)
                else:
                    logging.warning(
                        "Edge has unexpected child element of type '{}'".format(
                            child.tag
                        ),
                        child.sourceline,
                    )

    def handle_graph(self, graph):
        """
        Checks a graph element for validity.

        A graph may have an 'edgedefault' attribute specifying whether edges
        are directed or undirected by default. As edges of witnesses
        should always be directed the value of the 'edgedefault' attribute
        is checked to be 'directed'.

        Other attributes are allowed but no checks are currently performed for them.

        Currently a witness graph is not supposed to have any children of types
        other than 'node', 'edge' or 'data'.
        """
        edge_default = graph.attrib.get("edgedefault")
        if edge_default is None:
            logging.warning(
                "Graph definition is missing attribute 'edgedefault'", graph.sourceline
            )
        elif edge_default != "directed":
            logging.warning("Edgedefault should be 'directed'", graph.sourceline)
        for child in graph:
            if child.tag.rpartition("}")[2] == witness.DATA:
                self.handle_data(child, graph)
            else:
                # All other expected children have already been handled and removed
                logging.warning(
                    "Graph element has unexpected child "
                    "of type '{}'".format(child.tag),
                    child.sourceline,
                )

    def handle_graphml_elem(self, graphml_elem):
        if len(graphml_elem.attrib) > 0:
            logging.warning(
                "Expected graphml element to have no attributes",
                graphml_elem.sourceline,
            )
        if None not in graphml_elem.nsmap:
            logging.warning("Missing default namespace", graphml_elem.sourceline)
        elif graphml_elem.nsmap[None] != "http://graphml.graphdrawing.org/xmlns":
            logging.warning(
                "Unexpected default namespace: {}".format(graphml_elem.nsmap[None]),
                graphml_elem.sourceline,
            )
        if "xsi" not in graphml_elem.nsmap:
            logging.warning(
                "Missing xml schema namespace or namespace prefix is not called 'xsi'",
                graphml_elem.sourceline,
            )
        elif graphml_elem.nsmap["xsi"] != "http://www.w3.org/2001/XMLSchema-instance":
            logging.warning(
                "Expected 'xsi' to be namespace prefix "
                "for 'http://www.w3.org/2001/XMLSchema-instance'",
                graphml_elem.sourceline,
            )
        for child in graphml_elem:
            # All expected children have already been handled and removed
            logging.warning(
                "Graphml element has unexpected child of type '{}'".format(child.tag),
                graphml_elem.sourceline,
            )

    def final_checks(self):
        """
        Performs checks that cannot be done before the whole witness has been traversed
        because elements may appear in almost arbitrary order.
        """
        for key in self.witness.used_keys - set(self.witness.defined_keys):
            if key in witness.COMMON_KEYS:
                # Already handled for other keys
                logging.warning("Key '{}' has been used but not defined".format(key))
        for key in set(self.witness.defined_keys) - self.witness.used_keys:
            logging.info(
                "Unnecessary definition of key '{}', key has never been used".format(
                    key
                )
            )
        if self.witness.witness_type is None:
            logging.warning("Witness-type has not been specified")
        elif self.witness.witness_type == "correctness_witness":
            for key in self.violation_witness_only:
                logging.warning(
                    "Key '{}' is not allowed in correctness witness".format(key)
                )
        elif self.witness.witness_type == "violation_witness":
            for key in self.correctness_witness_only:
                logging.warning(
                    "Key '{}' is not allowed in violation witness".format(key)
                )
        else:
            raise AssertionError("Invalid witness type.")
        if self.witness.sourcecodelang is None:
            logging.warning("Sourcecodelang has not been specified")
        if self.witness.producer is None:
            logging.warning("Producer has not been specified")
        if not self.witness.specifications:
            logging.warning("No specification has been specified")
        if self.witness.programfile is None:
            logging.warning("Programfile has not been specified")
        if self.witness.programhash is None:
            logging.warning("Programhash has not been specified")
        if self.witness.architecture is None:
            logging.warning("Architecture has not been specified")
        if self.witness.creationtime is None:
            logging.warning("Creationtime has not been specified")
        if self.witness.entry_node is None and self.witness.node_ids:
            logging.warning("No entry node has been specified")
        for node_id in self.check_existence_later:
            if node_id not in self.witness.node_ids:
                logging.warning("Node {} has not been declared".format(node_id))
        if self.options.checkCallstack:
            self.check_function_stack(
                collections.OrderedDict(sorted(self.witness.transitions.items())),
                self.witness.entry_node,
            )
        if self.options.checkProgram and self.program_info is not None:
            for check in self.check_later:
                check()

    def lint(self):
        """
        Splits the witness into manageable chunks and triggers or performs
        checks for the resulting elements. Also stores some information to be
        able to trigger checks for the witness as a whole.
        """
        try:
            saw_graph = False
            saw_graphml = False
            element_stack = list()
            for (event, elem) in ET.iterparse(
                self.witness.witness_file, events=("start", "end")
            ):
                if event == "start":
                    element_stack.append(elem)
                else:
                    element_stack.pop()
                    _, _, tag = elem.tag.rpartition("}")
                    if element_stack:
                        parent_elem = element_stack[-1]
                    else:
                        assert tag == witness.GRAPHML
                    if tag == witness.DATA:
                        # Will be handled later
                        pass
                    elif tag == witness.DEFAULT:
                        # Will be handled later
                        pass
                    elif tag == witness.KEY:
                        self.handle_key(elem)
                        parent_elem.remove(elem)
                    elif tag == witness.NODE:
                        self.handle_node(elem)
                        parent_elem.remove(elem)
                    elif tag == witness.EDGE:
                        self.handle_edge(elem)
                        parent_elem.remove(elem)
                    elif tag == witness.GRAPH:
                        if saw_graph:
                            logging.warning(
                                "Found multiple graph definitions", elem.sourceline
                            )
                        else:
                            saw_graph = True
                            self.handle_graph(elem)
                            parent_elem.remove(elem)
                    elif tag == witness.GRAPHML:
                        if saw_graphml:
                            logging.warning(
                                "Found multiple graphml elements", elem.sourceline
                            )
                        else:
                            saw_graphml = True
                            self.handle_graphml_elem(elem)
                    else:
                        logging.warning(
                            "Unknown tag: {}".format(elem.tag), elem.sourceline
                        )
            self.final_checks()
        except ET.XMLSyntaxError as err:
            logging.critical("Malformed witness:\n\t{}".format(err.msg), err.lineno)
        return determine_exit_code()


def main(argv):
    try:
        linter = create_linter(argv[1:])
        start = time.time()
        exit_code = linter.lint()
        end = time.time()
        print("\ntook", end - start, "s")
        print("Exit code:", exit_code)
        sys.exit(exit_code)
    except Exception:
        sys.exit(INTERNAL_ERROR)


if __name__ == "__main__":
    main(sys.argv)
