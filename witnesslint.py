'''
This module contains a linter that can check witnesses for basic consistency.
'''

import argparse
import hashlib
import logging
import sys
import time
import xml.etree.ElementTree as ET

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
    return parser

class WitnessLint:
    '''
    Check a GraphML file for basic consistency with the witness format
    by calling lint(path_to_file).
    '''

    def __init__(self, witness, program):
        self.witness = witness
        self.program_info = None
        if program is not None:
            self.collect_program_info(program)
        self.witness_type = None
        self.sourcecodelang = None
        self.producer = None
        self.specification = None
        self.programfile = None
        self.programhash = None
        self.architecture = None
        self.creationtime = None
        self.node_ids = set()
        self.num_entry_nodes = 0
        self.defined_keys = dict()
        self.used_keys = set()
        self.threads = dict()
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

    def check_functionname(self, name):
        if self.program_info is not None:
            if name not in self.program_info['function_names']:
                logging.warning("'%s' is not a functionname of the program", name)
        else:
            self.check_later.append(lambda: self.check_functionname(name))

    def check_linenumber(self, line):
        if self.program_info is not None:
            if int(line) < 1 or int(line) > self.program_info['num_lines']:
                logging.warning("%s is not a valid linenumber", line)
        else:
            self.check_later.append(lambda: self.check_linenumber(line))

    def check_character_offset(self, offset):
        if self.program_info is not None:
            if int(offset) < 0 or int(offset) >= self.program_info['num_chars']:
                logging.warning("%s is not a valid character offset", offset)
        else:
            self.check_later.append(lambda: self.check_character_offset(offset))

    def handle_data(self, data, parent):
        '''
        Performs checks that are common to all data elements and invokes appropriate
        specialized checks.

        A data element must have a 'key' attribute specifying the kind of data it holds.

        Data elements in a witness are currently not supposed have any children.
        '''
        if len(data) > 0:
            logging.warning("Expected data element to not have any children but has %d", len(data))
        if len(data.attrib) > 1:
            logging.warning("Expected data element to have exactly one attribute but has %d",
                            len(data.attrib))
        if 'key' in data.attrib:
            key = data.attrib['key']
            self.used_keys.add(key)
            if parent.tag == '{http://graphml.graphdrawing.org/xmlns}node':
                self.handle_node_data(data, key)
            elif parent.tag == '{http://graphml.graphdrawing.org/xmlns}edge':
                self.handle_edge_data(data, key, parent)
            elif parent.tag == '{http://graphml.graphdrawing.org/xmlns}graph':
                self.handle_graph_data(data, key)
            else:
                raise AssertionError("Invalid parent element of type " + parent.tag)
        else:
            logging.warning("Expected data element to have attribute 'key'")

    def handle_node_data(self, data, key):
        '''
        Performs checks for data elements that are direct children of a node element.
        '''
        if key == 'entry':
            if data.text == 'true':
                self.num_entry_nodes += 1
                if self.num_entry_nodes > 1:
                    logging.warning("Found multiple entry nodes")
            elif data.text == 'false':
                logging.info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key)
            else:
                logging.warning("Invalid value for key 'entry': %s", data.text)
        elif key == 'sink':
            if data.text == 'false':
                logging.info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key)
            elif not data.text == 'true':
                logging.warning("Invalid value for key 'sink': %s", data.text)
            self.violation_witness_only.add(key)
            #TODO: Make sure there are no leaving transitions for the wrapping node
        elif key == 'violation':
            if data.text == 'false':
                logging.info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key)
            elif not data.text == 'true':
                logging.warning("Invalid value for key 'violation': %s", data.text)
            self.violation_witness_only.add(key)
        elif key == 'invariant':
            self.correctness_witness_only.add(key)
            #TODO: Check whether data.text is a valid invariant
        elif key == 'invariant.scope':
            self.correctness_witness_only.add(key)
            self.check_functionname(data.text)
        elif key in self.defined_keys and self.defined_keys[key] == 'node':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.warning("Unknown key for node data element: %s", key)

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
                    if (child.tag == '{http://graphml.graphdrawing.org/xmlns}data'
                            and 'key' in child.attrib
                            and child.attrib['key'] == 'assumption.resultfunction'):
                        resultfunction_present = True
                        break
                if not resultfunction_present:
                    logging.warning("Found assumption containing '\\result'"
                                    "but no resultfunction was specified")
        elif key == 'assumption.scope':
            self.violation_witness_only.add(key)
            self.check_functionname(data.text)
        elif key == 'assumption.resultfunction':
            self.violation_witness_only.add(key)
            self.check_functionname(data.text)
        elif key == 'control':
            if data.text not in ['condition-true', 'condition-false']:
                logging.warning("Invalid value for key 'control': %s", data.text)
            self.violation_witness_only.add(key)
        elif key == 'startline':
            self.check_linenumber(data.text)
        elif key == 'endline':
            self.check_linenumber(data.text)
        elif key == 'startoffset':
            self.check_character_offset(data.text)
        elif key == 'endoffset':
            self.check_character_offset(data.text)
        elif key == 'enterLoopHead':
            if data.text == 'false':
                logging.info("Specifying value '%s' for key '%s' is unnecessary",
                             data.text, key)
            elif not data.text == 'true':
                logging.warning("Invalid value for key 'enterLoopHead': %s", data.text)
        elif key == 'enterFunction':
            self.function_stack.append(data.text)
            for child in parent:
                if (child.tag == '{http://graphml.graphdrawing.org/xmlns}data'
                        and 'key' in child.attrib
                        and child.attrib['key'] == 'threadId'
                        and self.threads[child.text] is None):
                    self.threads[child.text] = data.text
                    break
            self.check_functionname(data.text)
        elif key == 'returnFrom' or key == 'returnFromFunction':
            if data.text == self.function_stack[-1]:
                self.function_stack.pop()
            else:
                logging.warning("Trying to return from function %s but currently in function %s",
                                data.text, self.function_stack[-1])
            for child in parent:
                if (child.tag == '{http://graphml.graphdrawing.org/xmlns}data'
                        and 'key' in child.attrib
                        and child.attrib['key'] == 'threadId'
                        and self.threads[child.text] == data.text):
                    del self.threads[child.text]
                    break
            self.check_functionname(data.text)
        elif key == 'threadId':
            if data.text not in self.threads:
                logging.warning("Thread with id %s doesn't exist", data.text)
        elif key == 'createThread':
            if data.text in self.threads:
                logging.warning("Thread with id %s has already been created", data.text)
            else:
                self.threads[data.text] = None
        elif key in self.defined_keys and self.defined_keys[key] == 'edge':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.warning("Unknown key for edge data element: %s", key)

    def handle_graph_data(self, data, key):
        '''
        Performs checks for data elements that are direct children of a graph element.
        '''
        if key == 'witness-type':
            if data.text in ['correctness_witness', 'violation_witness']:
                if self.witness_type is None:
                    self.witness_type = data.text
                else:
                    logging.warning("Found multiple definitions of witness-type")
            else:
                logging.warning("Invalid value for key 'witness-type': %s", data.text)
        elif key == 'sourcecodelang':
            if data.text in ['C', 'Java']:
                if self.sourcecodelang is None:
                    self.sourcecodelang = data.text
                else:
                    logging.warning("Found multiple definitions of sourcecodelang")
            else:
                logging.warning("Invalid value for key 'sourcecodelang': %s", data.text)
        elif key == 'producer':
            if self.producer is None:
                self.producer = data.text
            else:
                logging.warning("Found multiple definitions of producer")
        elif key == 'specification':
            if self.specification is None:
                #TODO: Check specification text
                self.specification = data.text
            else:
                logging.warning("Found multiple definitions of specification")
        elif key == 'programfile':
            if self.programfile is None:
                self.programfile = data.text
                try:
                    source = open(self.programfile)
                    source.close()
                    if self.program_info is None:
                        self.collect_program_info(self.programfile)
                except FileNotFoundError:
                    logging.info("Programfile specified in witness could not be accessed")
            else:
                logging.warning("Found multiple definitions of programfile")
        elif key == 'programhash':
            if self.program_info is not None:
                if (data.text.lower() != self.program_info['sha256_hash']
                        and data.text.lower() != self.program_info['sha1_hash']):
                    logging.warning("Programhash does not match the hash specified in the witness")
            if self.programhash is None:
                self.programhash = data.text
            else:
                logging.warning("Found multiple definitions of programhash")
        elif key == 'architecture':
            if self.architecture is None:
                #TODO: Check architecture identifier
                self.architecture = data.text
            else:
                logging.warning("Found multiple definitions of architecture")
        elif key == 'creationtime':
            if self.creationtime is None:
                #TODO: Check whether creationtime format conforms to ISO 8601
                self.creationtime = data.text
            else:
                logging.warning("Found multiple definitions of creationtime")
        elif key in self.defined_keys and self.defined_keys[key] == 'graph':
            # Other, tool-specific keys are allowed as long as they have been defined
            pass
        else:
            logging.warning("Unknown key for graph data element: %s", key)

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
            logging.warning("Key is missing attribute 'id'")
            key_id = None
        if "for" in key.attrib:
            key_domain = key.attrib['for']
        else:
            logging.warning("Key is missing attribute 'for'")
            key_domain = None
        if key_id and key_domain:
            if key_id in self.defined_keys:
                logging.warning("Found multiple key definitions with id '%s'", key_id)
            else:
                if key_id in COMMON_KEYS and not COMMON_KEYS[key_id] == key_domain:
                    logging.warning("Key '%s' should be used for '%s' elements "
                                    "but was defined for '%s' elements",
                                    key_id, COMMON_KEYS[key_id], key_domain)
                self.defined_keys[key_id] = key_domain
        if len(key) > 1:
            logging.warning("Expected key to have at most one child but has %s", len(key))
        for child in key:
            if child.tag == "{http://graphml.graphdrawing.org/xmlns}default":
                if len(child.attrib) != 0:
                    logging.warning(
                        "Expected no attributes for 'default' element but found %d (%s)",
                        len(child.attrib), list(child.attrib))
                if key_id in ['entry', 'sink', 'violation', 'enterLoopHead']:
                    if not child.text == 'false':
                        logging.warning("Default value for %s should be 'false'", key_id)
            else:
                logging.warning("Invalid child for key element: %s", child.tag)

    def handle_node(self, node):
        '''
        Checks a node element for validity.

        Nodes must have an unique id but should not have any other attributes.

        Nodes in a witness are currently not supposed have any non-data children.
        '''
        if len(node.attrib) > 1:
            logging.warning("Expected node element to have exactly one attribute but has %d",
                            len(node.attrib))
        if 'id' in node.attrib:
            node_id = node.attrib['id']
            if node_id in self.node_ids:
                logging.warning("Found multiple nodes with id '%s'", node_id)
            else:
                self.node_ids.add(node_id)
        else:
            logging.warning("Expected node element to have attribute 'id'")
        for child in node:
            if child.tag == "{http://graphml.graphdrawing.org/xmlns}data":
                self.handle_data(child, node)
            else:
                logging.warning("Node has unexpected child element of type '%s'", child.tag)

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
            if source not in self.node_ids:
                self.check_existence_later.add(source)
        else:
            source = None
            logging.warning("Edge is missing attribute 'source'")
        if 'target' in edge.attrib:
            target = edge.attrib['target']
            if source == target:
                logging.warning("Node '%s' has self-loop", source)
            if target not in self.node_ids:
                self.check_existence_later.add(target)
        else:
            logging.warning("Edge is missing attribute 'target'")
        for child in edge:
            if child.tag == "{http://graphml.graphdrawing.org/xmlns}data":
                self.handle_data(child, edge)
            else:
                logging.warning("Edge has unexpected child element of type '%s'", child.tag)

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
                logging.warning("Edgedefault should be 'directed'")
        else:
            logging.warning("Graph definition is missing attribute 'edgedefault'")
        for child in graph:
            if child.tag == "{http://graphml.graphdrawing.org/xmlns}data":
                self.handle_data(child, graph)
            else:
                # All other expected children have already been handled and removed
                logging.warning("Graph element has unexpected child of type '%s'", child.tag)

    def final_checks(self):
        '''
        Performs checks that cannot be done before the whole witness has been traversed
        because elements may appear in almost arbitrary order.
        '''
        for key in self.used_keys.difference(set(self.defined_keys)):
            if key in COMMON_KEYS:
                # Already handled for other keys
                logging.warning("Key '%s' has been used but not defined", key)
        for key in set(self.defined_keys).difference(self.used_keys):
            logging.info("Unnecessary definition of key '%s', key has never been used", key)
        if self.witness_type is None:
            logging.warning("Witness-type has not been specified")
        if self.sourcecodelang is None:
            logging.warning("Sourcecodelang has not been specified")
        if self.producer is None:
            logging.warning("Producer has not been specified")
        if self.specification is None:
            logging.warning("Specification has not been specified")
        if self.programfile is None:
            logging.warning("Programfile has not been specified")
        if self.programhash is None:
            logging.warning("Programhash has not been specified")
        if self.architecture is None:
            logging.warning("Architecture has not been specified")
        if self.creationtime is None:
            logging.warning("Creationtime has not been specified")
        if self.num_entry_nodes == 0 and len(self.node_ids) > 0:
            logging.warning("No entry node has been specified")
        if self.witness_type == 'correctness_witness':
            for key in self.violation_witness_only:
                logging.warning("Key '%s' is not allowed in correctness witness", key)
        elif self.witness_type == 'violation_witness':
            for key in self.correctness_witness_only:
                logging.warning("Key '%s' is not allowed in violation witness", key)
        for node_id in self.check_existence_later:
            if node_id not in self.node_ids:
                logging.warning("Node %s has not been declared", node_id)
        for functionname in self.function_stack:
            logging.warning("Entered but did not return from function '%s'", functionname)
        if self.program_info is not None:
            for check in self.check_later:
                check()

    def lint(self):
        num_graphs = 0
        element_stack = list()
        for (event, elem) in ET.iterparse(self.witness, events=('start', 'end')):
            if event == 'start':
                element_stack.append(elem)
            else:
                element_stack.pop()
                if elem.tag == "{http://graphml.graphdrawing.org/xmlns}data":
                    # Will be handled later
                    pass
                elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}default":
                    # Will be handled later
                    pass
                elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}key":
                    self.handle_key(elem)
                    element_stack[-1].remove(elem)
                elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}node":
                    self.handle_node(elem)
                    element_stack[-1].remove(elem)
                elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}edge":
                    self.handle_edge(elem)
                    element_stack[-1].remove(elem)
                elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}graph":
                    num_graphs += 1
                    if num_graphs > 1:
                        logging.warning("Found multiple graph definitions")
                    else:
                        self.handle_graph(elem)
                    element_stack[-1].remove(elem)
                elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}graphml":
                    #TODO: Check attributes - perhaps necessary to do outside of iterparse
                    for child in elem:
                        # All expected children have already been handled and removed
                        logging.warning("Graphml element has unexpected child of type '%s'",
                                        child.tag)
                else:
                    logging.warning("Unknown tag: %s", elem.tag)
        self.final_checks()

def main(argv):
    #TODO: Include position information in log messages
    arg_parser = create_arg_parser()
    parsed_args = arg_parser.parse_args(argv[1:])
    loglevel = LOGLEVELS[parsed_args.loglevel]
    program = parsed_args.program
    if program is not None:
        program = program.name
    witness = parsed_args.witness

    logging.basicConfig(level=loglevel, format="%(levelname)-8s %(message)s")
    linter = WitnessLint(witness, program)
    start = time.time()
    linter.lint()
    end = time.time()
    print("\ntook", end - start, "s")

if __name__ == '__main__':
    main(sys.argv)
