'''
This module contains a linter that can check witnesses for consistency
with the witness format [1].

[1]: github.com/sosy-lab/sv-witnesses/blob/master/README.md
'''

import argparse
import collections
import gzip
import hashlib
import logging
import re
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

LOGLEVELS = {'critical' : logging.CRITICAL, 'error' : logging.ERROR, 'warning' : logging.WARNING,
             'info' : logging.INFO, 'debug' : logging.DEBUG}

CREATIONTIME_PATTERN = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([+-]\d{2}:\d{2})?$'

def create_linter(argv):
    arg_parser = create_arg_parser()
    parsed_args = arg_parser.parse_args(argv)
    loglevel = LOGLEVELS[parsed_args.loglevel]
    create_logger(loglevel)
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
    return WitnessLint(witness, program, check_program,
                       parsed_args.checkCallstack, parsed_args.ignoreSelfLoops)

def create_arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('witness',
                        help="GraphML file containing a witness.",
                        type=argparse.FileType('r'),
                        metavar='WITNESS')
    parser.add_argument('--loglevel',
                        default='warning',
                        choices=['critical', 'error', 'warning', 'info', 'debug'],
                        help="Desired verbosity of logging output. Only log messages at or above "
                             "the specified level are displayed.",
                        metavar='LOGLEVEL')
    parser.add_argument('--program',
                        help="The program for which the witness was created.",
                        type=argparse.FileType('r'),
                        metavar='PROGRAM')
    parser.add_argument('--checkProgram',
                        help="Perform some additional checks involving the program file. "
                             "Better left disabled for big witnesses. This option is "
                             "implicitly used when a program is given via the --program option.",
                        action='store_true')
    parser.add_argument('--checkCallstack',
                        help="Check whether transitions specified via enterFunction "
                             "and returnFromFunction are consistent. "
                             "Better left disabled for big witnesses.",
                        action='store_true')
    parser.add_argument('--ignoreSelfLoops',
                        help="Produce no warnings when encountering "
                             "edges that represent a self-loop.",
                        action='store_true')
    return parser

def create_logger(loglevel):
    '''Initializes the logger instances used in the linter.'''
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

class WitnessLint:
    '''
    Contains methods that check different parts of a witness for consistency
    with the witness format as well as some utility methods for this purpose.
    The lint() method checks the whole witness.
    '''

    def __init__(self, witness, program, check_program, check_callstack, ignore_self_loops):
        self.witness = witness
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
        self.exit_code = 0

    def log(self, level, msg, *args):
        if level >= LOGLEVELS['warning']:
            self.exit_code = 1
        logging.getLogger("without_position").log(level, msg, *args)

    def log_with_position(self, level, lineno, msg, *args):
        if level >= LOGLEVELS['warning']:
            self.exit_code = 1
        logging.getLogger("with_position").log(level, msg, *args, extra={'line' : lineno})

    def collect_program_info(self, program):
        '''
        Collects and stores some data about the program for later usage.

        This method assumes that the given program can be accessed.
        '''
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
        if not self.check_program:
            return
        if self.program_info is not None:
            if name not in self.program_info['function_names']:
                self.log_with_position(LOGLEVELS['warning'], pos,
                                       "'%s' is not a functionname of the program", name)
        else:
            self.check_later.append(lambda: self.check_functionname(name, pos))

    def check_linenumber(self, line, pos):
        if not self.check_program:
            return
        if self.program_info is not None:
            if int(line) < 1 or int(line) > self.program_info['num_lines']:
                self.log_with_position(LOGLEVELS['warning'], pos,
                                       "%s is not a valid linenumber", line)
        else:
            self.check_later.append(lambda: self.check_linenumber(line, pos))

    def check_character_offset(self, offset, pos):
        if not self.check_program:
            return
        if self.program_info is not None:
            if int(offset) < 0 or int(offset) >= self.program_info['num_chars']:
                self.log_with_position(LOGLEVELS['warning'], pos,
                                       "%s is not a valid character offset", offset)
        else:
            self.check_later.append(lambda: self.check_character_offset(offset, pos))

    def check_function_stack(self, transitions, start_node):
        '''
        Performs DFS on the given transitions to make sure that all
        possible paths have a consistent order of function entries and exits.
        '''
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
                    self.log(LOGLEVELS['warning'],
                             "No leaving transition for node %s "
                             "but not all functions have been left",
                             current_node)
            else:
                for outgoing in transitions[current_node]:
                    function_stack = current_stack[:]
                    if outgoing[2] is not None and outgoing[2] != outgoing[1]:
                        if not function_stack:
                            self.log(LOGLEVELS['warning'],
                                     "Trying to return from function '%s' in transition %s -> %s "
                                     "but currently not in a function",
                                     outgoing[2], current_node, outgoing[0])
                        elif outgoing[2] == current_stack[-1]:
                            function_stack.pop()
                        else:
                            self.log(LOGLEVELS['warning'],
                                     "Trying to return from function '%s' in transition %s -> %s "
                                     "but currently in function %s",
                                     outgoing[2], current_node, outgoing[0], function_stack[-1])
                    if outgoing[1] is not None and outgoing[1] != outgoing[2]:
                        function_stack.append(outgoing[1])
                    to_visit.append((outgoing[0], function_stack))

    def handle_data(self, data, parent):
        '''
        Performs checks that are common to all data elements and invokes appropriate
        specialized checks.

        A data element must have a 'key' attribute specifying the kind of data it holds.

        Data elements in a witness are currently not supposed have any children.
        '''
        if len(data) > 0:
            self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                   "Expected data element to not have any children but has %d",
                                   len(data))
        if len(data.attrib) > 1:
            self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                   "Expected data element to have exactly "
                                   "one attribute but has %d",
                                   len(data.attrib))
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
            self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                   "Expected data element to have attribute 'key'")

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
                    self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                           "Found multiple entry nodes")
            elif data.text == 'false':
                self.log_with_position(LOGLEVELS['info'], data.sourceline,
                                       "Specifying value 'false' for key '%s' is unnecessary",
                                       key)
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Invalid value for key 'entry': %s",
                                       data.text)
        elif key == 'sink':
            if data.text == 'false':
                self.log_with_position(LOGLEVELS['info'], data.sourceline,
                                       "Specifying value 'false' for key '%s' is unnecessary",
                                       key)
            elif data.text == 'true':
                if 'id' in parent.attrib:
                    node_id = parent.attrib['id']
                    if node_id in self.transition_sources or node_id in self.transitions:
                        self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                               "Sink node should have no leaving edges")
                    self.sink_nodes.add(node_id)
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Invalid value for key 'sink': %s",
                                       data.text)
            self.violation_witness_only.add(key)
        elif key == 'violation':
            if data.text == 'false':
                self.log_with_position(LOGLEVELS['info'], data.sourceline,
                                       "Specifying value 'false' for key '%s' is unnecessary",
                                       key)
            elif not data.text == 'true':
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Invalid value for key 'violation': %s", data.text)
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
            self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                   "Unknown key for node data element: %s", key)

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
                    self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                           "Found assumption containing '\\result' "
                                           "but no resultfunction was specified")
        elif key == 'assumption.scope':
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == 'assumption.resultfunction':
            self.violation_witness_only.add(key)
            self.check_functionname(data.text, data.sourceline)
        elif key == 'control':
            if data.text not in ['condition-true', 'condition-false']:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Invalid value for key 'control': %s", data.text)
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
                self.log_with_position(LOGLEVELS['info'], data.sourceline,
                                       "Specifying value 'false' for key '%s' is unnecessary",
                                       key)
            elif not data.text == 'true':
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Invalid value for key 'enterLoopHead': %s", data.text)
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
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Thread with id %s doesn't exist", data.text)
        elif key == 'createThread':
            if data.text in self.threads:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Thread with id %s has already been created", data.text)
            else:
                self.threads[data.text] = None
        elif key in self.defined_keys and self.defined_keys[key] == 'edge':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                   "Unknown key for edge data element: %s", key)

    def handle_graph_data(self, data, key):
        '''
        Performs checks for data elements that are direct children of a graph element.
        '''
        if key == 'witness-type':
            if data.text in ['correctness_witness', 'violation_witness']:
                if self.witness_type is None:
                    self.witness_type = data.text
                else:
                    self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                           "Found multiple definitions of witness-type")
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Invalid value for key 'witness-type': %s", data.text)
        elif key == 'sourcecodelang':
            if data.text in ['C', 'Java']:
                if self.sourcecodelang is None:
                    self.sourcecodelang = data.text
                else:
                    self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                           "Found multiple definitions of sourcecodelang")
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Invalid value for key 'sourcecodelang': %s", data.text)
        elif key == 'producer':
            if self.producer is None:
                self.producer = data.text
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Found multiple definitions of producer")
        elif key == 'specification':
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
                    self.log_with_position(LOGLEVELS['info'], data.sourceline,
                                           "Programfile specified in witness "
                                           "could not be accessed")
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Found multiple definitions of programfile")
        elif key == 'programhash':
            if self.program_info is not None:
                if (data.text.lower() != self.program_info['sha256_hash']
                        and data.text.lower() != self.program_info['sha1_hash']):
                    self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                           "Programhash does not match the hash specified "
                                           "in the witness")
            if self.programhash is None:
                self.programhash = data.text
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Found multiple definitions of programhash")
        elif key == 'architecture':
            if self.architecture is None:
                if data.text in ['32bit', '64bit']:
                    self.architecture = data.text
                else:
                    self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                           "Invalid architecture identifier")
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Found multiple definitions of architecture")
        elif key == 'creationtime':
            if self.creationtime is None:
                if not re.match(CREATIONTIME_PATTERN, data.text.strip()):
                    self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                           "Invalid format for creationtime")
                self.creationtime = data.text
            else:
                self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                       "Found multiple definitions of creationtime")
        elif key in self.defined_keys and self.defined_keys[key] == 'graph':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            self.log_with_position(LOGLEVELS['warning'], data.sourceline,
                                   "Unknown key for graph data element: %s", key)

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
            self.log_with_position(LOGLEVELS['warning'], key.sourceline,
                                   "Key is missing attribute 'id'")
            key_id = None
        if "for" in key.attrib:
            key_domain = key.attrib['for']
        else:
            self.log_with_position(LOGLEVELS['warning'], key.sourceline,
                                   "Key is missing attribute 'for'")
            key_domain = None
        if key_id and key_domain:
            if key_id in self.defined_keys:
                self.log_with_position(LOGLEVELS['warning'], key.sourceline,
                                       "Found multiple key definitions with id '%s'", key_id)
            else:
                if key_id in COMMON_KEYS and not COMMON_KEYS[key_id] == key_domain:
                    self.log_with_position(LOGLEVELS['warning'], key.sourceline,
                                           "Key '%s' should be used for '%s' elements "
                                           "but was defined for '%s' elements",
                                           key_id, COMMON_KEYS[key_id], key_domain)
                self.defined_keys[key_id] = key_domain
        if len(key) > 1:
            self.log_with_position(LOGLEVELS['warning'], key.sourceline,
                                   "Expected key to have at most one child but has %s", len(key))
        for child in key:
            if child.tag.rpartition('}')[2] == "default":
                if len(child.attrib) != 0:
                    self.log_with_position(LOGLEVELS['warning'], key.sourceline,
                                           "Expected no attributes for 'default' element"
                                           "but found %d (%s)",
                                           len(child.attrib), list(child.attrib))
                if key_id in ['entry', 'sink', 'violation', 'enterLoopHead']:
                    if not child.text == 'false':
                        self.log_with_position(LOGLEVELS['warning'], key.sourceline,
                                               "Default value for %s should be 'false'", key_id)
            else:
                self.log_with_position(LOGLEVELS['warning'], child.sourceline,
                                       "Invalid child for key element: %s", child.tag)

    def handle_node(self, node):
        '''
        Checks a node element for validity.

        Nodes must have an unique id but should not have any other attributes.

        Nodes in a witness are currently not supposed have any non-data children.
        '''
        if len(node.attrib) > 1:
            self.log_with_position(LOGLEVELS['warning'], node.sourceline,
                                   "Expected node element to have exactly "
                                   "one attribute but has %d",
                                   len(node.attrib))
        if 'id' in node.attrib:
            node_id = node.attrib['id']
            if node_id in self.node_ids:
                self.log_with_position(LOGLEVELS['warning'], node.sourceline,
                                       "Found multiple nodes with id '%s'", node_id)
            else:
                self.node_ids.add(node_id)
        else:
            self.log_with_position(LOGLEVELS['warning'], node.sourceline,
                                   "Expected node element to have attribute 'id'")
        for child in node:
            if child.tag.rpartition('}')[2] == "data":
                self.handle_data(child, node)
            else:
                self.log_with_position(LOGLEVELS['warning'], child.sourceline,
                                       "Node has unexpected child element of type '%s'",
                                       child.tag)

    def handle_edge(self, edge):
        '''
        Checks an edge element for validity.

        Edges must have attributes 'source' and 'target', each referencing a different existing
        node by its id.

        Other attributes are allowed but no checks are currently performed for them.

        Edges in a witness are currently not supposed to have any non-data children.
        '''
        if 'source' in edge.attrib:
            source = edge.attrib['source']
            if source in self.sink_nodes:
                self.log_with_position(LOGLEVELS['warning'], edge.sourceline,
                                       "Sink node should have no leaving edges")
            if not self.check_callstack:
                # Otherwise this information is stored in self.transitions
                self.transition_sources.add(source)
            if source not in self.node_ids:
                self.check_existence_later.add(source)
        else:
            source = None
            self.log_with_position(LOGLEVELS['warning'], edge.sourceline,
                                   "Edge is missing attribute 'source'")
        if 'target' in edge.attrib:
            target = edge.attrib['target']
            if source == target and not self.ignore_self_loops:
                self.log_with_position(LOGLEVELS['warning'], edge.sourceline,
                                       "Node '%s' has self-loop", source)
            if target not in self.node_ids:
                self.check_existence_later.add(target)
        else:
            target = None
            self.log_with_position(LOGLEVELS['warning'], edge.sourceline,
                                   "Edge is missing attribute 'target'")
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
                    self.log_with_position(LOGLEVELS['warning'], child.sourceline,
                                           "Edge has unexpected child element of type '%s'",
                                           child.tag)
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
                    self.log_with_position(LOGLEVELS['warning'], child.sourceline,
                                           "Edge has unexpected child element of type '%s'",
                                           child.tag)

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
                self.log_with_position(LOGLEVELS['warning'], graph.sourceline,
                                       "Edgedefault should be 'directed'")
        else:
            self.log_with_position(LOGLEVELS['warning'], graph.sourceline,
                                   "Graph definition is missing attribute 'edgedefault'")
        for child in graph:
            if child.tag.rpartition('}')[2] == "data":
                self.handle_data(child, graph)
            else:
                # All other expected children have already been handled and removed
                self.log_with_position(LOGLEVELS['warning'], child.sourceline,
                                       "Graph element has unexpected child of type '%s'",
                                       child.tag)

    def handle_graphml_elem(self, graphml_elem):
        if len(graphml_elem.attrib) > 0:
            self.log_with_position(LOGLEVELS['warning'], graphml_elem.sourceline,
                                   "Expected graphml element "
                                   "to have no attributes")
        if None in graphml_elem.nsmap:
            if graphml_elem.nsmap[None] != 'http://graphml.graphdrawing.org/xmlns':
                self.log_with_position(LOGLEVELS['warning'], graphml_elem.sourceline,
                                       "Unexpected default namespace: %s",
                                       graphml_elem.nsmap[None])
        else:
            self.log_with_position(LOGLEVELS['warning'], graphml_elem.sourceline,
                                   "Missing default namespace")
        if 'xsi' in graphml_elem.nsmap:
            if graphml_elem.nsmap['xsi'] != 'http://www.w3.org/2001/XMLSchema-instance':
                self.log_with_position(LOGLEVELS['warning'], graphml_elem.sourceline,
                                       "Expected 'xsi' to be namespace prefix for "
                                       "'http://www.w3.org/2001/XMLSchema-instance'")
        else:
            self.log_with_position(LOGLEVELS['warning'], graphml_elem.sourceline,
                                   "Missing xml schema namespace "
                                   "or namespace prefix is not called 'xsi'")
        for child in graphml_elem:
            # All expected children have already been handled and removed
            self.log_with_position(LOGLEVELS['warning'], graphml_elem.sourceline,
                                   "Graphml element has unexpected child of type '%s'",
                                   child.tag)

    def final_checks(self):
        '''
        Performs checks that cannot be done before the whole witness has been traversed
        because elements may appear in almost arbitrary order.
        '''
        for key in self.used_keys.difference(set(self.defined_keys)):
            if key in COMMON_KEYS:
                # Already handled for other keys
                self.log(LOGLEVELS['warning'], "Key '%s' has been used but not defined", key)
        for key in set(self.defined_keys).difference(self.used_keys):
            self.log(LOGLEVELS['info'],
                     "Unnecessary definition of key '%s', key has never been used", key)
        if self.witness_type is None:
            self.log(LOGLEVELS['warning'], "Witness-type has not been specified")
        if self.sourcecodelang is None:
            self.log(LOGLEVELS['warning'], "Sourcecodelang has not been specified")
        if self.producer is None:
            self.log(LOGLEVELS['warning'], "Producer has not been specified")
        if not self.specifications:
            self.log(LOGLEVELS['warning'], "No specification has been specified")
        if self.programfile is None:
            self.log(LOGLEVELS['warning'], "Programfile has not been specified")
        if self.programhash is None:
            self.log(LOGLEVELS['warning'], "Programhash has not been specified")
        if self.architecture is None:
            self.log(LOGLEVELS['warning'], "Architecture has not been specified")
        if self.creationtime is None:
            self.log(LOGLEVELS['warning'], "Creationtime has not been specified")
        if self.entry_node is None and len(self.node_ids) > 0:
            self.log(LOGLEVELS['warning'], "No entry node has been specified")
        if self.witness_type == 'correctness_witness':
            for key in self.violation_witness_only:
                self.log(LOGLEVELS['warning'],
                         "Key '%s' is not allowed in correctness witness", key)
        elif self.witness_type == 'violation_witness':
            for key in self.correctness_witness_only:
                self.log(LOGLEVELS['warning'],
                         "Key '%s' is not allowed in violation witness", key)
        for node_id in self.check_existence_later:
            if node_id not in self.node_ids:
                self.log(LOGLEVELS['warning'], "Node %s has not been declared", node_id)
        if self.check_callstack:
            self.check_function_stack(collections.OrderedDict(sorted(self.transitions.items())),
                                      self.entry_node)
        if self.check_program and self.program_info is not None:
            for check in self.check_later:
                check()

    def lint(self):
        '''
        Splits the witness into manageable chunks and triggers or performs
        checks for the resulting elements. Also stores some information to be
        able to trigger checks for the witness as a whole.
        '''
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
                            self.log_with_position(LOGLEVELS['warning'], elem.sourceline,
                                                   "Found multiple graph definitions")
                        else:
                            saw_graph = True
                            self.handle_graph(elem)
                            element_stack[-1].remove(elem)
                    elif tag == "graphml":
                        if saw_graphml:
                            self.log_with_position(LOGLEVELS['warning'], elem.sourceline,
                                                   "Found multiple graphml elements")
                        else:
                            saw_graphml = True
                            self.handle_graphml_elem(elem)
                    else:
                        self.log_with_position(LOGLEVELS['warning'], elem.sourceline,
                                               "Unknown tag: %s", elem.tag)
            self.final_checks()
        except ET.XMLSyntaxError as err:
            self.log_with_position(LOGLEVELS['critical'], err.lineno,
                                   "Malformed witness:\n\t%s", err.msg)
        return self.exit_code

def main(argv):
    linter = create_linter(argv[1:])
    start = time.time()
    exit_code = linter.lint()
    end = time.time()
    print("\ntook", end - start, "s")
    print("Exit code:", exit_code)
    sys.exit(exit_code)

if __name__ == '__main__':
    main(sys.argv)
