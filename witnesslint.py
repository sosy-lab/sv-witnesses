'''
This module contains a linter that can check witnesses for basic consistency.
'''

import argparse
import collections
import hashlib
import logging
import sys
import time
from lxml import etree as ET

COMMON_KEYS = {'witness-type' : 'graph', 'sourcecodelang' : 'graph', 'producer' : 'graph',
               'specification' : 'graph', 'programfile' : 'graph', 'programhash' : 'graph',
               'architecture' : 'graph', 'creationtime' : 'graph', 'entry' : 'node',
               'sink' : 'node', 'violation' : 'node', 'invariant' : 'node',
               'invariant.scope' : 'node', 'assumption' : 'edge', 'assumption.scope' : 'edge',
               'assumption.resultfunction' : 'edge', 'control' : 'edge', 'startline' : 'edge',
               'endline' : 'edge', 'startoffset' : 'edge', 'endoffset' : 'edge',
               'enterLoopHead' : 'edge', 'enterFunction' : 'edge', 'returnFromFunction' : 'edge',
               'threadId' : 'edge', 'createThread' : 'edge'}

LOGLEVELS = {'critical' : 50, 'error' : 40, 'warning' : 30, 'info' : 20, 'debug' : 10}

def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('witness',
                        help="GraphML file containing a witness.",
                        type=argparse.FileType('r'),
                        metavar='WITNESS')
    parser.add_argument('--loglevel',
                        default='warning',
                        choices=['critical', 'error', 'warning', 'info', 'debug'],
                        help="Desired verbosity of logging output. Only log messages at or above"
                             "the specified level are displayed.",
                        metavar='LOGLEVEL')
    parser.add_argument('--program',
                        help="The program for which the witness was created.",
                        type=argparse.FileType('r'),
                        metavar='PROGRAM')
    parser.add_argument('--checkCallstack',
                        help="Perform checks whether transitions are consistent with callstack. "
                             "Better left disabled for big witnesses.",
                        action='store_true')
    return parser

def create_logger(loglevel):
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

def check_function_stack(transitions, start_node):
    to_visit = [(start_node, [])]
    visited = set()
    while to_visit:
        current_node, current_stack = to_visit.pop()
        if current_node in visited:
            continue
        else:
            visited.add(current_node)
        if current_node not in transitions:
            if current_stack:
                logging.getLogger("without_position") \
                       .warning("No leaving transition for node %s "
                                "but not all functions have been left", current_node)
        else:
            for outgoing in transitions[current_node]:
                function_stack = current_stack[:]
                if outgoing[2] is not None and outgoing[2] != outgoing[1]:
                    if not function_stack:
                        logging.getLogger("without_position") \
                               .warning("Trying to return from function '%s' "
                                        "in transition %s -> %s "
                                        "but currently not in a function",
                                        outgoing[2], current_node, outgoing[0])
                    elif outgoing[2] == current_stack[-1]:
                        function_stack.pop()
                    else:
                        logging.getLogger("without_position") \
                               .warning("Trying to return from function '%s' "
                                        "in transition %s -> %s "
                                        "but currently in function %s",
                                        outgoing[2], current_node, outgoing[0], function_stack[-1])
                if outgoing[1] is not None and outgoing[1] != outgoing[2]:
                    function_stack.append(outgoing[1])
                to_visit.append((outgoing[0], function_stack))

class WitnessLint:
    '''
    Check a GraphML file for basic consistency with the witness format
    by calling lint(path_to_file).
    '''

    def __init__(self, witness, program, check_callstack):
        self.witness = witness
        self.program_info = None
        if program is not None:
            self.collect_program_info(program)
        self.check_callstack = check_callstack
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
        self.function_stack = list()
        self.violation_witness_only = set()
        self.correctness_witness_only = set()
        self.check_existence_later = set()
        self.check_later = list()

    def collect_program_info(self, program):
        with open(program, 'r') as source:
            content = source.read()
            num_chars = len(content)
            num_lines = len(content.split('\n'))
            #TODO: Collect all function names
            function_names = list()
        with open(program, 'rb') as source:
            content = source.read()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
        self.program_info = {'name' : program, 'num_chars' : num_chars, 'num_lines' : num_lines,
                             'sha1_hash' : sha1_hash, 'sha256_hash' : sha256_hash,
                             'function_names' : function_names}

    def check_functionname(self, name, pos):
        if self.program_info is not None:
            if name not in self.program_info['function_names']:
                logging.getLogger("with_position") \
                       .warning("'%s' is not a functionname of the program",
                                name, extra={'line' : pos})
        else:
            self.check_later.append(lambda: self.check_functionname(name, pos))

    def check_linenumber(self, line, pos):
        if self.program_info is not None:
            if int(line) < 1 or int(line) > self.program_info['num_lines']:
                logging.getLogger("with_position") \
                       .warning("%s is not a valid linenumber",
                                line, extra={'line' : pos})
        else:
            self.check_later.append(lambda: self.check_linenumber(line, pos))

    def check_character_offset(self, offset, pos):
        if self.program_info is not None:
            if int(offset) < 0 or int(offset) >= self.program_info['num_chars']:
                logging.getLogger("with_position") \
                       .warning("%s is not a valid character offset",
                                offset, extra={'line' : pos})
        else:
            self.check_later.append(lambda: self.check_character_offset(offset, pos))

    def handle_data(self, data, parent):
        '''
        Performs checks that are common to all data elements and invokes appropriate
        specialized checks.

        A data element must have a 'key' attribute specifying the kind of data it holds.

        Data elements in a witness are currently not supposed have any children.
        '''
        if len(data) > 0:
            logging.getLogger("with_position") \
                   .warning("Expected data element to not have any children but has %d",
                            len(data), extra={'line' : data.sourceline})
        if len(data.attrib) > 1:
            logging.getLogger("with_position") \
                   .warning("Expected data element to have exactly one attribute but has %d",
                            len(data.attrib), extra={'line' : data.sourceline})
        if 'key' in data.attrib:
            key = data.attrib['key']
            self.used_keys.add(key)
            _, _, tag = parent.tag.rpartition('}')
            if tag == 'node':
                self.handle_node_data(data, key, parent)
            elif tag == 'edge':
                self.handle_edge_data(data, key, parent)
            elif tag == 'graph':
                self.handle_graph_data(data, key)
            else:
                raise AssertionError("Invalid parent element of type " + parent.tag)
        else:
            logging.getLogger("with_position") \
                   .warning("Expected data element to have attribute 'key'",
                            extra={'line' : data.sourceline})

    def handle_node_data(self, data, key, parent):
        '''
        Performs checks for data elements that are direct children of a node element.
        '''
        if key == 'entry':
            if data.text == 'true':
                if self.entry_node is None:
                    if 'id' in parent.attrib:
                        self.entry_node = parent.attrib['id']
                    else:
                        self.entry_node = ''
                else:
                    logging.getLogger("with_position") \
                           .warning("Found multiple entry nodes", extra={'line' : data.sourceline})

            elif data.text == 'false':
                logging.getLogger("with_position") \
                       .info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key, extra={'line' : data.sourceline})
            else:
                logging.getLogger("with_position") \
                       .warning("Invalid value for key 'entry': %s",
                                data.text, extra={'line' : data.sourceline})
        elif key == 'sink':
            if data.text == 'false':
                logging.getLogger("with_position") \
                       .info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key, extra={'line' : data.sourceline})
            elif data.text == 'true':
                if 'id' in parent.attrib:
                    node_id = parent.attrib['id']
                    if node_id in self.transition_sources:
                        logging.getLogger("with_position") \
                               .warning("Sink node should have no leaving edges",
                                        extra={'line' : data.sourceline})
                    self.sink_nodes.add(node_id)
            else:
                logging.getLogger("with_position") \
                       .warning("Invalid value for key 'sink': %s",
                                data.text, extra={'line' : data.sourceline})
            self.violation_witness_only.add(key)
        elif key == 'violation':
            if data.text == 'false':
                logging.getLogger("with_position") \
                       .info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key, extra={'line' : data.sourceline})
            elif not data.text == 'true':
                logging.getLogger("with_position") \
                       .warning("Invalid value for key 'violation': %s",
                                data.text, extra={'line' : data.sourceline})
            self.violation_witness_only.add(key)
        elif key == 'invariant':
            self.correctness_witness_only.add(key)
            #TODO: Check whether data.text is a valid invariant
        elif key == 'invariant.scope':
            self.correctness_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key in self.defined_keys and self.defined_keys[key] == 'node':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.getLogger("with_position") \
                   .warning("Unknown key for node data element: %s",
                            key, extra={'line' : data.sourceline})

    def handle_edge_data(self, data, key, parent):
        '''
        Performs checks for data elements that are direct children of an edge element.
        '''
        if key == 'assumption':
            self.violation_witness_only.add(key)
            #TODO: Check whether all expressions from data.text are valid assumptions
            if '\\result' in data.text:
                resultfunction_present = False
                for child in parent:
                    if (child.tag.rpartition('}')[2] == 'data'
                            and 'key' in child.attrib
                            and child.attrib['key'] == 'assumption.resultfunction'):
                        resultfunction_present = True
                        break
                if not resultfunction_present:
                    logging.getLogger("with_position") \
                           .warning("Found assumption containing '\\result' but no resultfunction"
                                    "was specified", extra={'line' : data.sourceline})
        elif key == 'assumption.scope':
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == 'assumption.resultfunction':
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == 'control':
            if data.text not in ['condition-true', 'condition-false']:
                logging.getLogger("with_position") \
                       .warning("Invalid value for key 'control': %s", data.text,
                                extra={'line' : data.sourceline})
            self.violation_witness_only.add(key)
        elif key == 'startline':
            self.check_linenumber(data.text, data.sourceline)
        elif key == 'endline':
            self.check_linenumber(data.text, data.sourceline)
        elif key == 'startoffset':
            self.check_character_offset(data.text, data.sourceline)
        elif key == 'endoffset':
            self.check_character_offset(data.text, data.sourceline)
        elif key == 'enterLoopHead':
            if data.text == 'false':
                logging.getLogger("with_position") \
                       .info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key, extra={'line' : data.sourceline})
            elif not data.text == 'true':
                logging.getLogger("with_position") \
                       .warning("Invalid value for key 'enterLoopHead': %s",
                                data.text, extra={'line' : data.sourceline})
        elif key == 'enterFunction':
            for child in parent:
                if (child.tag.rpartition('}')[2] == 'data'
                        and 'key' in child.attrib
                        and child.attrib['key'] == 'threadId'
                        and self.threads[child.text] is None):
                    self.threads[child.text] = data.text
                    break
            self.check_functionname(data.text, data.sourceline)
        elif key == 'returnFrom' or key == 'returnFromFunction':
            for child in parent:
                if (child.tag.rpartition('}')[2] == 'data'
                        and 'key' in child.attrib
                        and child.attrib['key'] == 'threadId'
                        and self.threads[child.text] == data.text):
                    del self.threads[child.text]
                    break
            self.check_functionname(data.text, data.sourceline)
        elif key == 'threadId':
            if data.text not in self.threads:
                logging.getLogger("with_position") \
                       .warning("Thread with id %s doesn't exist",
                                data.text, extra={'line' : data.sourceline})
        elif key == 'createThread':
            if data.text in self.threads:
                logging.getLogger("with_position") \
                       .warning("Thread with id %s has already been created",
                                data.text, extra={'line' : data.sourceline})
            else:
                self.threads[data.text] = None
        elif key in self.defined_keys and self.defined_keys[key] == 'edge':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.getLogger("with_position") \
                   .warning("Unknown key for edge data element: %s",
                            key, extra={'line' : data.sourceline})

    def handle_graph_data(self, data, key):
        '''
        Performs checks for data elements that are direct children of a graph element.
        '''
        if key == 'witness-type':
            if data.text in ['correctness_witness', 'violation_witness']:
                if self.witness_type is None:
                    self.witness_type = data.text
                else:
                    logging.getLogger("with_position") \
                           .warning("Found multiple definitions of witness-type",
                                    extra={'line' : data.sourceline})
            else:
                logging.getLogger("with_position") \
                       .warning("Invalid value for key 'witness-type': %s",
                                data.text, extra={'line' : data.sourceline})
        elif key == 'sourcecodelang':
            if data.text in ['C', 'Java']:
                if self.sourcecodelang is None:
                    self.sourcecodelang = data.text
                else:
                    logging.getLogger("with_position") \
                           .warning("Found multiple definitions of sourcecodelang",
                                    extra={'line' : data.sourceline})
            else:
                logging.getLogger("with_position") \
                       .warning("Invalid value for key 'sourcecodelang': %s",
                                data.text, extra={'line' : data.sourceline})
        elif key == 'producer':
            if self.producer is None:
                self.producer = data.text
            else:
                logging.getLogger("with_position") \
                       .warning("Found multiple definitions of producer",
                                extra={'line' : data.sourceline})
        elif key == 'specification':
            #TODO: Check specification text
            self.specifications.add(data.text)
        elif key == 'programfile':
            if self.programfile is None:
                self.programfile = data.text
                try:
                    source = open(self.programfile)
                    source.close()
                    if self.program_info is None:
                        self.collect_program_info(self.programfile)
                except FileNotFoundError:
                    logging.getLogger("with_position") \
                           .info("Programfile specified in witness could not be accessed",
                                 extra={'line' : data.sourceline})
            else:
                logging.getLogger("with_position") \
                       .warning("Found multiple definitions of programfile",
                                extra={'line' : data.sourceline})
        elif key == 'programhash':
            if self.program_info is not None:
                if (data.text.lower() != self.program_info['sha256_hash']
                        and data.text.lower() != self.program_info['sha1_hash']):
                    logging.getLogger("with_position") \
                           .warning("Programhash does not match the hash specified"
                                    "in the witness", extra={'line' : data.sourceline})
            if self.programhash is None:
                self.programhash = data.text
            else:
                logging.getLogger("with_position") \
                       .warning("Found multiple definitions of programhash",
                                extra={'line' : data.sourceline})
        elif key == 'architecture':
            if self.architecture is None:
                #TODO: Check architecture identifier
                self.architecture = data.text
            else:
                logging.getLogger("with_position") \
                       .warning("Found multiple definitions of architecture",
                                extra={'line' : data.sourceline})
        elif key == 'creationtime':
            if self.creationtime is None:
                #TODO: Check whether creationtime format conforms to ISO 8601
                self.creationtime = data.text
            else:
                logging.getLogger("with_position") \
                       .warning("Found multiple definitions of creationtime",
                                extra={'line' : data.sourceline})
        elif key in self.defined_keys and self.defined_keys[key] == 'graph':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.getLogger("with_position") \
                   .warning("Unknown key for graph data element: %s",
                            key, extra={'line' : data.sourceline})

    def handle_key(self, key):
        '''
        Checks a key definition for validity.

        Should the key definition contain the mandatory 'id' and 'for' attributes the defined key
        may be used in the appropriate data elements of any following graph definitions, even if
        the key definition is faulty for other reasons.

        Appropriate are all data elements that are direct children of an element of type
        key_domain, which is the value of the 'for' attribute.

        Key definitions in a witness may have a child element of type 'default' specifying
        the default value for this key, but are currently expected to have no other children.
        '''
        if "id" in key.attrib:
            key_id = key.attrib['id']
        else:
            logging.getLogger("with_position") \
                   .warning("Key is missing attribute 'id'", extra={'line' : key.sourceline})
            key_id = None
        if "for" in key.attrib:
            key_domain = key.attrib['for']
        else:
            logging.getLogger("with_position") \
                   .warning("Key is missing attribute 'for'", extra={'line' : key.sourceline})
            key_domain = None
        if key_id and key_domain:
            if key_id in self.defined_keys:
                logging.getLogger("with_position") \
                       .warning("Found multiple key definitions with id '%s'",
                                key_id, extra={'line' : key.sourceline})
            else:
                if key_id in COMMON_KEYS and not COMMON_KEYS[key_id] == key_domain:
                    logging.getLogger("with_position") \
                           .warning("Key '%s' should be used for '%s' elements "
                                    "but was defined for '%s' elements",
                                    key_id, COMMON_KEYS[key_id], key_domain,
                                    extra={'line' : key.sourceline})
                self.defined_keys[key_id] = key_domain
        if len(key) > 1:
            logging.getLogger("with_position") \
                   .warning("Expected key to have at most one child but has %s",
                            len(key), extra={'line' : key.sourceline})
        for child in key:
            if child.tag.rpartition('}')[2] == "default":
                if len(child.attrib) != 0:
                    logging.getLogger("with_position") \
                           .warning("Expected no attributes for 'default' element"
                                    "but found %d (%s)", len(child.attrib),
                                    list(child.attrib), extra={'line' : key.sourceline})
                if key_id in ['entry', 'sink', 'violation', 'enterLoopHead']:
                    if not child.text == 'false':
                        logging.getLogger("with_position") \
                               .warning("Default value for %s should be 'false'",
                                        key_id, extra={'line' : key.sourceline})
            else:
                logging.getLogger("with_position") \
                       .warning("Invalid child for key element: %s",
                                child.tag, extra={'line' : child.sourceline})

    def handle_node(self, node):
        '''
        Checks a node element for validity.

        Nodes must have an unique id but should not have any other attributes.

        Nodes in a witness are currently not supposed have any non-data children.
        '''
        if len(node.attrib) > 1:
            logging.getLogger("with_position") \
                   .warning("Expected node element to have exactly one attribute but has %d",
                            len(node.attrib), extra={'line' : node.sourceline})
        if 'id' in node.attrib:
            node_id = node.attrib['id']
            if node_id in self.node_ids:
                logging.getLogger("with_position") \
                       .warning("Found multiple nodes with id '%s'",
                                node_id, extra={'line' : node.sourceline})
            else:
                self.node_ids.add(node_id)
        else:
            logging.getLogger("with_position") \
                   .warning("Expected node element to have attribute 'id'",
                            extra={'line' : node.sourceline})
        for child in node:
            if child.tag.rpartition('}')[2] == "data":
                self.handle_data(child, node)
            else:
                logging.getLogger("with_position") \
                       .warning("Node has unexpected child element of type '%s'",
                                child.tag, extra={'line' : child.sourceline})

    def handle_edge(self, edge):
        '''
        Checks an edge element for validity.

        Edges must have attributes 'source' and 'target', each referencing a different existing
        node by it's id.

        Other attributes are allowed but no checks are currently performed for them.

        Edges in a witness are currently not supposed to have any non-data children.
        '''
        if 'source' in edge.attrib:
            source = edge.attrib['source']
            if source in self.sink_nodes:
                logging.getLogger("with_position") \
                       .warning("Sink node should have no leaving edges",
                                extra={'line' : edge.sourceline})
            self.transition_sources.add(source)
            if source not in self.node_ids:
                self.check_existence_later.add(source)
        else:
            source = None
            logging.getLogger("with_position") \
                   .warning("Edge is missing attribute 'source'",
                            extra={'line' : edge.sourceline})
        if 'target' in edge.attrib:
            target = edge.attrib['target']
            if source == target:
                logging.getLogger("with_position") \
                       .warning("Node '%s' has self-loop",
                                source, extra={'line' : edge.sourceline})
            if target not in self.node_ids:
                self.check_existence_later.add(target)
        else:
            target = None
            logging.getLogger("with_position") \
                   .warning("Edge is missing attribute 'target'",
                            extra={'line' : edge.sourceline})
        if self.check_callstack:
            enter, return_from = (None, None)
            for child in edge:
                if child.tag.rpartition('}')[2] == "data":
                    self.handle_data(child, edge)
                    if 'key' in child.attrib:
                        if child.attrib['key'] == 'enterFunction':
                            enter = child.text
                        elif (child.attrib['key'] == 'returnFromFunction'
                              or child.attrib['key'] == 'returnFrom'):
                            return_from = child.text
                else:
                    logging.getLogger("with_position") \
                           .warning("Edge has unexpected child element of type '%s'",
                                    child.tag, extra={'line' : child.sourceline})
            if source and target:
                if source in self.transitions:
                    self.transitions[source].append((target, enter, return_from))
                else:
                    self.transitions[source] = [(target, enter, return_from)]
        else:
            for child in edge:
                if child.tag.rpartition('}')[2] == "data":
                    self.handle_data(child, edge)
                else:
                    logging.getLogger("with_position") \
                           .warning("Edge has unexpected child element of type '%s'",
                                    child.tag, extra={'line' : child.sourceline})

    def handle_graph(self, graph):
        '''
        Checks a graph element for validity.

        A graph may have an 'edgedefault' attribute specifying whether edges are directed
        or undirected by default. As edges of witnesses should always be directed the value
        of the 'edgedefault' attribute is checked to be 'directed'.

        Other attributes are allowed but no checks are currently performed for them.

        Currently a witness graph is not supposed to have any children of types other than
        'node', 'edge' or 'data'.
        '''
        if 'edgedefault' in graph.attrib:
            if graph.attrib['edgedefault'] != 'directed':
                logging.getLogger("with_position") \
                       .warning("Edgedefault should be 'directed'",
                                extra={'line' : graph.sourceline})
        else:
            logging.getLogger("with_position") \
                   .warning("Graph definition is missing attribute 'edgedefault'",
                            extra={'line' : graph.sourceline})
        for child in graph:
            if child.tag.rpartition('}')[2] == "data":
                self.handle_data(child, graph)
            else:
                # All other expected children have already been handled and removed
                logging.getLogger("with_position") \
                       .warning("Graph element has unexpected child of type '%s'",
                                child.tag, extra={'line' : child.sourceline})

    def final_checks(self):
        '''
        Performs checks that cannot be done before the whole witness has been traversed
        because elements may appear in almost arbitrary order.
        '''
        for key in self.used_keys.difference(set(self.defined_keys)):
            if key in COMMON_KEYS:
                # Already handled for other keys
                logging.getLogger("without_position") \
                       .warning("Key '%s' has been used but not defined", key)
        for key in set(self.defined_keys).difference(self.used_keys):
            logging.getLogger("without_position") \
                   .info("Unnecessary definition of key '%s', key has never been used", key)
        if self.witness_type is None:
            logging.getLogger("without_position") \
                   .warning("Witness-type has not been specified")
        if self.sourcecodelang is None:
            logging.getLogger("without_position") \
                   .warning("Sourcecodelang has not been specified")
        if self.producer is None:
            logging.getLogger("without_position") \
                   .warning("Producer has not been specified")
        if self.specification is None:
            logging.getLogger("without_position") \
                   .warning("Specification has not been specified")
        if self.programfile is None:
            logging.getLogger("without_position") \
                   .warning("Programfile has not been specified")
        if self.programhash is None:
            logging.getLogger("without_position") \
                   .warning("Programhash has not been specified")
        if self.architecture is None:
            logging.getLogger("without_position") \
                   .warning("Architecture has not been specified")
        if self.creationtime is None:
            logging.getLogger("without_position") \
                   .warning("Creationtime has not been specified")
        if self.entry_node is None and len(self.node_ids) > 0:
            logging.getLogger("without_position") \
                   .warning("No entry node has been specified")
        if self.witness_type == 'correctness_witness':
            for key in self.violation_witness_only:
                logging.getLogger("without_position") \
                       .warning("Key '%s' is not allowed in correctness witness", key)
        elif self.witness_type == 'violation_witness':
            for key in self.correctness_witness_only:
                logging.getLogger("without_position") \
                       .warning("Key '%s' is not allowed in violation witness", key)
        for node_id in self.check_existence_later:
            if node_id not in self.node_ids:
                logging.getLogger("without_position") \
                       .warning("Node %s has not been declared", node_id)
        if self.check_callstack:
            check_function_stack(collections.OrderedDict(sorted(self.transitions.items())),
                                 self.entry_node)
        if self.program_info is not None:
            for check in self.check_later:
                check()

    def lint(self):
        try:
            saw_graph = False
            saw_graphml = False
            element_stack = list()
            for (event, elem) in ET.iterparse(self.witness, events=('start', 'end')):
                if event == 'start':
                    element_stack.append(elem)
                else:
                    element_stack.pop()
                    _, _, tag = elem.tag.rpartition('}')
                    if tag == "data":
                        # Will be handled later
                        pass
                    elif tag == "default":
                        # Will be handled later
                        pass
                    elif tag == "key":
                        self.handle_key(elem)
                        element_stack[-1].remove(elem)
                    elif tag == "node":
                        self.handle_node(elem)
                        element_stack[-1].remove(elem)
                    elif tag == "edge":
                        self.handle_edge(elem)
                        element_stack[-1].remove(elem)
                    elif tag == "graph":
                        if saw_graph:
                            logging.getLogger("with_position") \
                                   .warning("Found multiple graph definitions",
                                            extra={'line' : elem.sourceline})
                            continue
                        saw_graph = True
                        self.handle_graph(elem)
                        element_stack[-1].remove(elem)
                    elif tag == "graphml":
                        if saw_graphml:
                            logging.getLogger("with_position") \
                                   .warning("Found multiple graphml elements",
                                            extra={'line' : elem.sourceline})
                            continue
                        saw_graphml = True
                        if len(elem.attrib) > 0:
                            logging.getLogger("with_position") \
                                   .warning("Expected graphml element to have no attributes",
                                            extra={'line' : elem.sourceline})
                        if None in elem.nsmap:
                            if elem.nsmap[None] != 'http://graphml.graphdrawing.org/xmlns':
                                logging.getLogger("with_position") \
                                       .warning("Unexpected default namespace: %s",
                                                elem.nsmap[None], extra={'line' : elem.sourceline})
                        else:
                            logging.getLogger("with_position") \
                                   .warning("Missing default namespace",
                                            extra={'line' : elem.sourceline})
                        if 'xsi' in elem.nsmap:
                            if elem.nsmap['xsi'] != 'http://www.w3.org/2001/XMLSchema-instance':
                                logging.getLogger("with_position") \
                                       .warning("Expected 'xsi' to be namespace prefix for "
                                                "'http://www.w3.org/2001/XMLSchema-instance'",
                                                extra={'line' : elem.sourceline})
                        else:
                            logging.getLogger("with_position") \
                                   .warning("Missing xml schema namespace "
                                            "or namespace prefix is not called 'xsi'",
                                            extra={'line' : elem.sourceline})
                        for child in elem:
                            # All expected children have already been handled and removed
                            logging.getLogger("with_position") \
                                   .warning("Graphml element has unexpected child of type '%s'",
                                            child.tag, extra={'line' : elem.sourceline})
                    else:
                        logging.getLogger("with_position") \
                               .warning("Unknown tag: %s",
                                        elem.tag, extra={'line' : elem.sourceline})
            self.final_checks()
        except ET.XMLSyntaxError as err:
            logging.getLogger("with_position") \
                   .critical("Malformed witness:\n\t%s", err.msg, extra={'line' : err.lineno})

def main(argv):
    arg_parser = create_arg_parser()
    parsed_args = arg_parser.parse_args(argv[1:])
    loglevel = LOGLEVELS[parsed_args.loglevel]
    create_logger(loglevel)
    program = parsed_args.program
    if program is not None:
        program = program.name
    witness = parsed_args.witness
    if witness is not None:
        witness = witness.name
    linter = WitnessLint(witness, program, parsed_args.checkCallstack)
    start = time.time()
    linter.lint()
    end = time.time()
    print("\ntook", end - start, "s")

if __name__ == '__main__':
    main(sys.argv)
