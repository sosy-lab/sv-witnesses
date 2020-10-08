"""
This module contains a linter that can check witnesses for consistency
with the witness format [1].

[1]: github.com/sosy-lab/sv-witnesses/blob/master/README.md
"""

import argparse
import collections
import gzip
import hashlib
import logging
import re
import sys
import time
from lxml import etree as ET

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

LOGLEVELS = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}

CREATIONTIME_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([+-]\d{2}:\d{2})?$"

WITNESS_VALID = 0

WITNESS_FAULTY = 1


def create_linter(argv):
    arg_parser = create_arg_parser()
    parsed_args = arg_parser.parse_args(argv)
    loglevel = LOGLEVELS[parsed_args.loglevel]
    logger = create_logger(loglevel)
    program = parsed_args.program
    if program is not None:
        program = program.name
    check_program = parsed_args.checkProgram or program is not None
    witness = parsed_args.witness
    if witness is not None:
        witness = witness.name
        with gzip.open(witness) as unzipped_witness:
            try:
                unzipped_witness.read(1)
                zipped = True
            except OSError:
                zipped = False
        if zipped:
            witness = gzip.open(witness)
    return WitnessLint(
        witness,
        logger,
        program,
        check_program,
        parsed_args.checkCallstack,
        parsed_args.ignoreSelfLoops,
    )


def create_arg_parser():
    parser = argparse.ArgumentParser()
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


def create_logger(loglevel):
    """Initializes the logger instances and returns the logger to be used in the linter."""
    pos_logger = logging.getLogger("with_position")
    if not pos_logger.hasHandlers():
        pos_handler = logging.StreamHandler()
        pos_formatter = logging.Formatter("%(levelname)-8s: line %(line)s: %(message)s")
        pos_handler.setFormatter(pos_formatter)
        pos_logger.addHandler(pos_handler)
    pos_logger.setLevel(loglevel)

    no_pos_logger = logging.getLogger("without_position")
    if not no_pos_logger.hasHandlers():
        no_pos_handler = logging.StreamHandler()
        no_pos_formatter = logging.Formatter("%(levelname)-8s: %(message)s")
        no_pos_handler.setFormatter(no_pos_formatter)
        no_pos_logger.addHandler(no_pos_handler)
    no_pos_logger.setLevel(loglevel)

    return LintLogger()


class LintLogger:
    def __init__(self):
        self.logged_inconsistency = False

    def critical(self, msg, lineno=None):
        self.logged_inconsistency = True
        if lineno:
            logging.getLogger("with_position").critical(msg, extra={"line": lineno})
        else:
            logging.getLogger("without_position").critical(msg)

    def error(self, msg, lineno=None):
        self.logged_inconsistency = True
        if lineno:
            logging.getLogger("with_position").error(msg, extra={"line": lineno})
        else:
            logging.getLogger("without_position").error(msg)

    def warning(self, msg, lineno=None):
        self.logged_inconsistency = True
        if lineno:
            logging.getLogger("with_position").warning(msg, extra={"line": lineno})
        else:
            logging.getLogger("without_position").warning(msg)

    def info(self, msg, lineno=None):
        if lineno:
            logging.getLogger("with_position").info(msg, extra={"line": lineno})
        else:
            logging.getLogger("without_position").info(msg)

    def debug(self, msg, lineno=None):
        if lineno:
            logging.getLogger("with_position").debug(msg, extra={"line": lineno})
        else:
            logging.getLogger("without_position").debug(msg)


class WitnessLint:
    """
    Contains methods that check different parts of a witness for consistency
    with the witness format as well as some utility methods for this purpose.
    The lint() method checks the whole witness.
    """

    def __init__(
        self,
        witness,
        logger,
        program,
        check_program,
        check_callstack,
        ignore_self_loops,
    ):
        self.witness = witness
        self.logger = logger
        self.program_info = None
        if program is not None:
            self.collect_program_info(program)
        self.check_program = check_program
        self.check_callstack = check_callstack
        self.ignore_self_loops = ignore_self_loops
        self.witness_type = None
        self.sourcecodelang = None
        self.producer = None
        self.specifications = set()
        self.programfile = None
        self.programhash = None
        self.architecture = None
        self.creationtime = None
        self.entry_node = None
        self.node_ids = set()
        self.sink_nodes = set()
        self.transition_sources = set()
        self.defined_keys = dict()
        self.used_keys = set()
        self.threads = dict()
        self.transitions = dict()
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
        if not self.check_program:
            return
        if self.program_info is None:
            self.check_later.append(lambda: self.check_functionname(name, pos))
        elif name not in self.program_info["function_names"]:
            self.logger.warning(
                "'{}' is not a functionname of the program".format(name), pos
            )

    def check_linenumber(self, line, pos):
        if not self.check_program:
            return
        if self.program_info is None:
            self.check_later.append(lambda: self.check_linenumber(line, pos))
        elif int(line) < 1 or int(line) > self.program_info["num_lines"]:
            self.logger.warning("{} is not a valid linenumber".format(line), pos)

    def check_character_offset(self, offset, pos):
        if not self.check_program:
            return
        if self.program_info is None:
            self.check_later.append(lambda: self.check_character_offset(offset, pos))
        elif int(offset) < 0 or int(offset) >= self.program_info["num_chars"]:
            self.logger.warning(
                "{} is not a valid character offset".format(offset), pos
            )

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
                self.logger.warning(
                    "No leaving transition for node {} but not all "
                    "functions have been left".format(current_node)
                )
            for outgoing in transitions.get(current_node, list()):
                function_stack = current_stack[:]
                if outgoing[2] is not None and outgoing[2] != outgoing[1]:
                    if not function_stack:
                        self.logger.warning(
                            "Trying to return from function '{0}' in transition "
                            "{1} -> {2} but currently not in a function".format(
                                outgoing[2], current_node, outgoing[0]
                            )
                        )
                    elif outgoing[2] == current_stack[-1]:
                        function_stack.pop()
                    else:
                        self.logger.warning(
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

        A data element must have a 'key' attribute specifying the kind of data it holds.

        Data elements in a witness are currently not supposed have any children.
        """
        if len(data) > 0:
            self.logger.warning(
                "Expected data element to not have any children but has {}".format(
                    len(data)
                ),
                data.sourceline,
            )
        if len(data.attrib) > 1:
            self.logger.warning(
                "Expected data element to have exactly one attribute but has {}".format(
                    len(data.attrib)
                ),
                data.sourceline,
            )
        key = data.attrib.get(KEY)
        if key is None:
            self.logger.warning(
                "Expected data element to have attribute 'key'", data.sourceline
            )
        else:
            self.used_keys.add(key)
            _, _, tag = parent.tag.rpartition("}")
            if tag == NODE:
                self.handle_node_data(data, key, parent)
            elif tag == EDGE:
                self.handle_edge_data(data, key, parent)
            elif tag == GRAPH:
                self.handle_graph_data(data, key)
            else:
                raise AssertionError("Invalid parent element of type " + parent.tag)

    def handle_node_data(self, data, key, parent):
        """
        Performs checks for data elements that are direct children of a node element.
        """
        if key == ENTRY:
            if data.text == "true":
                if self.entry_node is None:
                    self.entry_node = parent.attrib.get("id", "")
                else:
                    self.logger.warning("Found multiple entry nodes", data.sourceline)
            elif data.text == "false":
                self.logger.info(
                    "Specifying value 'false' for key 'entry' is unnecessary",
                    data.sourceline,
                )
            else:
                self.logger.warning(
                    "Invalid value for key 'entry': {}".format(data.text),
                    data.sourceline,
                )
        elif key == SINK:
            if data.text == "false":
                self.logger.info(
                    "Specifying value 'false' for key 'sink' is unnecessary",
                    data.sourceline,
                )
            elif data.text == "true":
                node_id = parent.attrib.get("id")
                if node_id is not None:
                    if (
                        node_id in self.transition_sources
                        or node_id in self.transitions
                    ):
                        self.logger.warning(
                            "Sink node should have no leaving edges", data.sourceline
                        )
                    self.sink_nodes.add(node_id)
            else:
                self.logger.warning(
                    "Invalid value for key 'sink': {}".format(data.text),
                    data.sourceline,
                )
            self.violation_witness_only.add(key)
        elif key == VIOLATION:
            if data.text == "false":
                self.logger.info(
                    "Specifying value 'false' for key 'violation' is unnecessary",
                    data.sourceline,
                )
            elif not data.text == "true":
                self.logger.warning(
                    "Invalid value for key 'violation': {}".format(data.text),
                    data.sourceline,
                )
            self.violation_witness_only.add(key)
        elif key == INVARIANT:
            self.correctness_witness_only.add(key)
            # TODO: Check whether data.text is a valid invariant
        elif key == INVARIANT_SCOPE:
            self.correctness_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key in self.defined_keys and self.defined_keys[key] == NODE:
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            self.logger.warning(
                "Unknown key for node data element: {}".format(key), data.sourceline
            )

    def handle_edge_data(self, data, key, parent):
        """
        Performs checks for data elements that are direct children of an edge element.
        """
        if key == ASSUMPTION:
            self.violation_witness_only.add(key)
            # TODO: Check whether all expressions from data.text are valid assumptions
            if "\\result" in data.text:
                resultfunction_present = False
                for child in parent:
                    if (
                        child.tag.rpartition("}")[2] == DATA
                        and child.attrib.get(KEY) == ASSUMPTION_RESULTFUNCTION
                    ):
                        resultfunction_present = True
                        break
                if not resultfunction_present:
                    self.logger.warning(
                        "Found assumption containing '\\result' but "
                        "no resultfunction was specified",
                        data.sourceline,
                    )
        elif key == ASSUMPTION_SCOPE:
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == ASSUMPTION_RESULTFUNCTION:
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == CONTROL:
            if data.text not in ["condition-true", "condition-false"]:
                self.logger.warning(
                    "Invalid value for key 'control': {}".format(data.text),
                    data.sourceline,
                )
            self.violation_witness_only.add(key)
        elif key == STARTLINE:
            self.check_linenumber(data.text, data.sourceline)
        elif key == ENDLINE:
            self.check_linenumber(data.text, data.sourceline)
        elif key == STARTOFFSET:
            self.check_character_offset(data.text, data.sourceline)
        elif key == ENDOFFSET:
            self.check_character_offset(data.text, data.sourceline)
        elif key == ENTERLOOPHEAD:
            if data.text == "false":
                self.logger.info(
                    "Specifying value 'false' for key 'enterLoopHead' is unnecessary",
                    data.sourceline,
                )
            elif not data.text == "true":
                self.logger.warning(
                    "Invalid value for key 'enterLoopHead': {}".format(data.text),
                    data.sourceline,
                )
        elif key == ENTERFUNCTION:
            for child in parent:
                if (
                    child.tag.rpartition("}")[2] == DATA
                    and child.attrib.get(KEY) == THREADID
                    and self.threads[child.text] is None
                ):
                    self.threads[child.text] = data.text
                    break
            self.check_functionname(data.text, data.sourceline)
        elif key in ["returnFrom", RETURNFROMFUNCTION]:
            for child in parent:
                if (
                    child.tag.rpartition("}")[2] == DATA
                    and child.attrib.get(KEY) == THREADID
                    and self.threads[child.text] == data.text
                ):
                    del self.threads[child.text]
                    break
            self.check_functionname(data.text, data.sourceline)
        elif key == THREADID:
            if data.text not in self.threads:
                self.logger.warning(
                    "Thread with id {} doesn't exist".format(data.text), data.sourceline
                )
        elif key == CREATETHREAD:
            if data.text in self.threads:
                self.logger.warning(
                    "Thread with id {} has already been created".format(data.text),
                    data.sourceline,
                )
            else:
                self.threads[data.text] = None
        elif key in self.defined_keys and self.defined_keys[key] == EDGE:
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            self.logger.warning(
                "Unknown key for edge data element: {}".format(key), data.sourceline
            )

    def handle_graph_data(self, data, key):
        """
        Performs checks for data elements that are direct children of a graph element.
        """
        if key == WITNESS_TYPE:
            if data.text not in ["correctness_witness", "violation_witness"]:
                self.logger.warning(
                    "Invalid value for key 'witness-type': {}".format(data.text),
                    data.sourceline,
                )
            elif self.witness_type is None:
                self.witness_type = data.text
            else:
                self.logger.warning(
                    "Found multiple definitions of witness-type", data.sourceline
                )
        elif key == SOURCECODELANG:
            if data.text not in ["C", "Java"]:
                self.logger.warning(
                    "Invalid value for key 'sourcecodelang': {}".format(data.text),
                    data.sourceline,
                )
            elif self.sourcecodelang is None:
                self.sourcecodelang = data.text
            else:
                self.logger.warning(
                    "Found multiple definitions of sourcecodelang", data.sourceline
                )
        elif key == PRODUCER:
            if self.producer is None:
                self.producer = data.text
            else:
                self.logger.warning(
                    "Found multiple definitions of producer", data.sourceline
                )
        elif key == "specification":
            self.specifications.add(data.text)
        elif key == PROGRAMFILE:
            if self.programfile is None:
                self.programfile = data.text
                try:
                    source = open(self.programfile)
                    source.close()
                    if self.program_info is None:
                        self.collect_program_info(self.programfile)
                except FileNotFoundError:
                    self.logger.info(
                        "Programfile specified in witness could not be accessed",
                        data.sourceline,
                    )
            else:
                self.logger.warning(
                    "Found multiple definitions of programfile", data.sourceline
                )
        elif key == PROGRAMHASH:
            if (
                self.program_info is not None
                and data.text.lower() != self.program_info.get("sha256_hash")
                and data.text.lower() != self.program_info.get("sha1_hash")
            ):
                self.logger.warning(
                    "Programhash does not match the hash specified in the witness",
                    data.sourceline,
                )
            if self.programhash is None:
                self.programhash = data.text
            else:
                self.logger.warning(
                    "Found multiple definitions of programhash", data.sourceline
                )
        elif key == ARCHITECTURE:
            if self.architecture is not None:
                self.logger.warning(
                    "Found multiple definitions of architecture", data.sourceline
                )
            elif data.text in ["32bit", "64bit"]:
                self.architecture = data.text
            else:
                self.logger.warning("Invalid architecture identifier", data.sourceline)
        elif key == CREATIONTIME:
            if self.creationtime is not None:
                self.logger.warning(
                    "Found multiple definitions of creationtime", data.sourceline
                )
            elif re.match(CREATIONTIME_PATTERN, data.text.strip()):
                self.creationtime = data.text
            else:
                self.logger.warning("Invalid format for creationtime", data.sourceline)
        elif key in self.defined_keys and self.defined_keys[key] == GRAPH:
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            self.logger.warning(
                "Unknown key for graph data element: {}".format(key), data.sourceline
            )

    def handle_key(self, key):
        """
        Checks a key definition for validity.

        Should the key definition contain the mandatory 'id' and 'for' attributes the defined key
        may be used in the appropriate data elements of any following graph definitions, even if
        the key definition is faulty for other reasons.

        Appropriate are all data elements that are direct children of an element of type
        key_domain, which is the value of the 'for' attribute.

        Key definitions in a witness may have a child element of type 'default' specifying
        the default value for this key, but are currently expected to have no other children.
        """
        key_id = key.attrib.get("id")
        key_domain = key.attrib.get("for")
        if key_id and key_domain:
            if key_id in self.defined_keys:
                self.logger.warning(
                    "Found multiple key definitions with id '{}'".format(key_id),
                    key.sourceline,
                )
            else:
                if key_id in COMMON_KEYS and not COMMON_KEYS[key_id] == key_domain:
                    self.logger.warning(
                        "Key '{0}' should be used for '{1}' elements but "
                        "was defined for '{2}' elements".format(
                            key_id, COMMON_KEYS[key_id], key_domain
                        ),
                        key.sourceline,
                    )
                self.defined_keys[key_id] = key_domain
        else:
            if key_id is None:
                self.logger.warning("Key is missing attribute 'id'", key.sourceline)
            if key_domain is None:
                self.logger.warning("Key is missing attribute 'for'", key.sourceline)
        if len(key) > 1:
            self.logger.warning(
                "Expected key to have at most one child but has {}".format(len(key)),
                key.sourceline,
            )
        for child in key:
            if child.tag.rpartition("}")[2] == DEFAULT:
                if len(child.attrib) != 0:
                    self.logger.warning(
                        "Expected no attributes for 'default' element but found {0} ({1})".format(
                            len(child.attrib), list(child.attrib)
                        ),
                        key.sourceline,
                    )
                if key_id in [ENTRY, SINK, VIOLATION, ENTERLOOPHEAD]:
                    if not child.text == "false":
                        self.logger.warning(
                            "Default value for {} should be 'false'".format(key_id),
                            key.sourceline,
                        )
            else:
                self.logger.warning(
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
            self.logger.warning(
                "Expected node element to have exactly one attribute but has {}".format(
                    len(node.attrib)
                ),
                node.sourceline,
            )
        node_id = node.attrib.get("id")
        if node_id is None:
            self.logger.warning(
                "Expected node element to have attribute 'id'", node.sourceline
            )
        elif node_id in self.node_ids:
            self.logger.warning(
                "Found multiple nodes with id '{}'".format(node_id), node.sourceline
            )
        else:
            self.node_ids.add(node_id)
        for child in node:
            if child.tag.rpartition("}")[2] == DATA:
                self.handle_data(child, node)
            else:
                self.logger.warning(
                    "Node has unexpected child element of type '{}'".format(child.tag),
                    child.sourceline,
                )

    def handle_edge(self, edge):
        """
        Checks an edge element for validity.

        Edges must have attributes 'source' and 'target', each referencing a different existing
        node by its id.

        Other attributes are allowed but no checks are currently performed for them.

        Edges in a witness are currently not supposed to have any non-data children.
        """
        source = edge.attrib.get("source")
        if source is None:
            self.logger.warning("Edge is missing attribute 'source'", edge.sourceline)
        else:
            if source in self.sink_nodes:
                self.logger.warning(
                    "Sink node should have no leaving edges", edge.sourceline
                )
            if not self.check_callstack:
                # Otherwise this information is stored in self.transitions
                self.transition_sources.add(source)
            if source not in self.node_ids:
                self.check_existence_later.add(source)
        target = edge.attrib.get("target")
        if target is None:
            self.logger.warning("Edge is missing attribute 'target'", edge.sourceline)
        else:
            if source == target and not self.ignore_self_loops:
                self.logger.warning(
                    "Node '{}' has self-loop".format(source), edge.sourceline
                )
            if target not in self.node_ids:
                self.check_existence_later.add(target)
        if self.check_callstack:
            enter, return_from = (None, None)
            for child in edge:
                if child.tag.rpartition("}")[2] == DATA:
                    self.handle_data(child, edge)
                    key = child.attrib.get(KEY)
                    if key == ENTERFUNCTION:
                        enter = child.text
                    elif key in ["returnFrom", RETURNFROMFUNCTION]:
                        return_from = child.text
                else:
                    self.logger.warning(
                        "Edge has unexpected child element of type '{}'".format(
                            child.tag
                        ),
                        child.sourceline,
                    )
            if source and target:
                if source in self.transitions:
                    self.transitions[source].append((target, enter, return_from))
                else:
                    self.transitions[source] = [(target, enter, return_from)]
        else:
            for child in edge:
                if child.tag.rpartition("}")[2] == DATA:
                    self.handle_data(child, edge)
                else:
                    self.logger.warning(
                        "Edge has unexpected child element of type '{}'".format(
                            child.tag
                        ),
                        child.sourceline,
                    )

    def handle_graph(self, graph):
        """
        Checks a graph element for validity.

        A graph may have an 'edgedefault' attribute specifying whether edges are directed
        or undirected by default. As edges of witnesses should always be directed the value
        of the 'edgedefault' attribute is checked to be 'directed'.

        Other attributes are allowed but no checks are currently performed for them.

        Currently a witness graph is not supposed to have any children of types other than
        'node', 'edge' or 'data'.
        """
        edge_default = graph.attrib.get("edgedefault")
        if edge_default is None:
            self.logger.warning(
                "Graph definition is missing attribute 'edgedefault'", graph.sourceline
            )
        elif edge_default != "directed":
            self.logger.warning("Edgedefault should be 'directed'", graph.sourceline)
        for child in graph:
            if child.tag.rpartition("}")[2] == DATA:
                self.handle_data(child, graph)
            else:
                # All other expected children have already been handled and removed
                self.logger.warning(
                    "Graph element has unexpected child of type '{}'".format(child.tag),
                    child.sourceline,
                )

    def handle_graphml_elem(self, graphml_elem):
        if len(graphml_elem.attrib) > 0:
            self.logger.warning(
                "Expected graphml element to have no attributes",
                graphml_elem.sourceline,
            )
        if None not in graphml_elem.nsmap:
            self.logger.warning("Missing default namespace", graphml_elem.sourceline)
        elif graphml_elem.nsmap[None] != "http://graphml.graphdrawing.org/xmlns":
            self.logger.warning(
                "Unexpected default namespace: {}".format(graphml_elem.nsmap[None]),
                graphml_elem.sourceline,
            )
        if "xsi" not in graphml_elem.nsmap:
            self.logger.warning(
                "Missing xml schema namespace or namespace prefix is not called 'xsi'",
                graphml_elem.sourceline,
            )
        elif graphml_elem.nsmap["xsi"] != "http://www.w3.org/2001/XMLSchema-instance":
            self.logger.warning(
                "Expected 'xsi' to be namespace prefix "
                "for 'http://www.w3.org/2001/XMLSchema-instance'",
                graphml_elem.sourceline,
            )
        for child in graphml_elem:
            # All expected children have already been handled and removed
            self.logger.warning(
                "Graphml element has unexpected child of type '{}'".format(child.tag),
                graphml_elem.sourceline,
            )

    def final_checks(self):
        """
        Performs checks that cannot be done before the whole witness has been traversed
        because elements may appear in almost arbitrary order.
        """
        for key in self.used_keys - set(self.defined_keys):
            if key in COMMON_KEYS:
                # Already handled for other keys
                self.logger.warning(
                    "Key '{}' has been used but not defined".format(key)
                )
        for key in set(self.defined_keys) - self.used_keys:
            self.logger.info(
                "Unnecessary definition of key '{}', key has never been used".format(
                    key
                )
            )
        if self.witness_type is None:
            self.logger.warning("Witness-type has not been specified")
        if self.sourcecodelang is None:
            self.logger.warning("Sourcecodelang has not been specified")
        if self.producer is None:
            self.logger.warning("Producer has not been specified")
        if not self.specifications:
            self.logger.warning("No specification has been specified")
        if self.programfile is None:
            self.logger.warning("Programfile has not been specified")
        if self.programhash is None:
            self.logger.warning("Programhash has not been specified")
        if self.architecture is None:
            self.logger.warning("Architecture has not been specified")
        if self.creationtime is None:
            self.logger.warning("Creationtime has not been specified")
        if self.entry_node is None and len(self.node_ids) > 0:
            self.logger.warning("No entry node has been specified")
        if self.witness_type == "correctness_witness":
            for key in self.violation_witness_only:
                self.logger.warning(
                    "Key '{}' is not allowed in correctness witness".format(key)
                )
        elif self.witness_type == "violation_witness":
            for key in self.correctness_witness_only:
                self.logger.warning(
                    "Key '{}' is not allowed in violation witness".format(key)
                )
        for node_id in self.check_existence_later:
            if node_id not in self.node_ids:
                self.logger.warning("Node {} has not been declared".format(node_id))
        if self.check_callstack:
            self.check_function_stack(
                collections.OrderedDict(sorted(self.transitions.items())),
                self.entry_node,
            )
        if self.check_program and self.program_info is not None:
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
            for (event, elem) in ET.iterparse(self.witness, events=("start", "end")):
                if event == "start":
                    element_stack.append(elem)
                else:
                    element_stack.pop()
                    _, _, tag = elem.tag.rpartition("}")
                    if element_stack:
                        parent_elem = element_stack[-1]
                    else:
                        assert tag == GRAPHML
                    if tag == DATA:
                        # Will be handled later
                        pass
                    elif tag == DEFAULT:
                        # Will be handled later
                        pass
                    elif tag == KEY:
                        self.handle_key(elem)
                        parent_elem.remove(elem)
                    elif tag == NODE:
                        self.handle_node(elem)
                        parent_elem.remove(elem)
                    elif tag == EDGE:
                        self.handle_edge(elem)
                        parent_elem.remove(elem)
                    elif tag == GRAPH:
                        if saw_graph:
                            self.logger.warning(
                                "Found multiple graph definitions", elem.sourceline
                            )
                        else:
                            saw_graph = True
                            self.handle_graph(elem)
                            parent_elem.remove(elem)
                    elif tag == GRAPHML:
                        if saw_graphml:
                            self.logger.warning(
                                "Found multiple graphml elements", elem.sourceline
                            )
                        else:
                            saw_graphml = True
                            self.handle_graphml_elem(elem)
                    else:
                        self.logger.warning(
                            "Unknown tag: {}".format(elem.tag), elem.sourceline
                        )
            self.final_checks()
        except ET.XMLSyntaxError as err:
            self.logger.critical("Malformed witness:\n\t{}".format(err.msg), err.lineno)
        if self.logger.logged_inconsistency:
            return WITNESS_FAULTY
        return WITNESS_VALID


def main(argv):
    linter = create_linter(argv[1:])
    start = time.time()
    exit_code = linter.lint()
    end = time.time()
    print("\ntook", end - start, "s")
    print("Exit code:", exit_code)
    sys.exit(exit_code)


if __name__ == "__main__":
    main(sys.argv)
