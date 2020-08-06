'''
This module contains a linter that can check witnesses for basic consistency.
'''

import logging
import re
import sys
import time
import xml.etree.ElementTree as ET

class WitnessLint:

    def __init__(self, witnessfile):
        self.witness = witnessfile
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
        self.defined_keys = list()
        self.violation_witness_only = set()
        self.correctness_witness_only = set()
        self.check_existence_later = list()

    def handle_node_data(self, data):
        if len(data) > 0:
            logging.warning("Expected data element to not have any children but has %d", len(data))
        if len(data.attrib) > 1:
            logging.warning("Expected data element to have exactly one attribute but has %d",
                            len(data.attrib))
        if 'key' in data.attrib:
            key = data.attrib['key']
            if key == 'entry':
                if data.text == 'true':
                    self.num_entry_nodes += 1
                    if self.num_entry_nodes > 1:
                        logging.warning("Found multiple entry nodes")
                elif data.text == 'false':
                    logging.info("Specifying value '%s' for key '%s' is unnecessary",
                                 data.text, key)
                else:
                    logging.warning("Invalid value for function 'entry': %s", data.text)
            elif key == 'sink':
                if data.text == 'false':
                    logging.info("Specifying value '%s' for key '%s' is unnecessary",
                                 data.text, key)
                elif not data.text == 'true':
                    logging.warning("Invalid value for function 'sink': %s", data.text)
                self.violation_witness_only.add(key)
                #TODO: Make sure there are no leaving transitions for the wrapping node
            elif key == 'violation':
                if data.text == 'false':
                    logging.info("Specifying value '%s' for key '%s' is unnecessary",
                                 data.text, key)
                elif not data.text == 'true':
                    logging.warning("Invalid value for function 'violation': %s", data.text)
                self.violation_witness_only.add(key)
            elif key == 'invariant':
                self.correctness_witness_only.add(key)
                #TODO: Check whether data.text is a valid invariant
            elif key == 'invariant.scope':
                self.correctness_witness_only.add(key)
            else:
                logging.warning("Unknown key for node data element: %s", key)
        else:
            logging.warning("Expected data element to have attribute 'key'")

    def handle_edge_data(self, data):
        if len(data) > 0:
            logging.warning("Expected data element to not have any children but has %d", len(data))
        if len(data.attrib) > 1:
            logging.warning("Expected data element to have exactly one attribute but has %d",
                            len(data.attrib))
        if 'key' in data.attrib:
            key = data.attrib['key']
            if key == 'assumption':
                self.violation_witness_only.add(key)
                #TODO: Check whether all expression from data.text are valid assumptions
            elif key == 'assumption.scope':
                self.violation_witness_only.add(key)
            elif key == 'assumption.resultfunction':
                self.violation_witness_only.add(key)
                #TODO: Necessary if \result is used in an assumption of the current transition
            elif key == 'control':
                if data.text not in ['condition-true', 'condition-false']:
                    logging.warning("Invalid value for function 'control': %s", data.text)
                self.violation_witness_only.add(key)
            elif key == 'startline':
                #TODO: If programfile accessible:
                #      Check whether data.text is a valid line number of the program
                pass
            elif key == 'endline':
                #TODO: If programfile accessible:
                #      Check whether data.text is a valid line number of the program
                pass
            elif key == 'startoffset':
                #TODO
                pass
            elif key == 'endoffset':
                #TODO
                pass
            elif key == 'enterLoopHead':
                if data.text == 'false':
                    logging.info("Specifying value '%s' for key '%s' is unnecessary",
                                 data.text, key)
                elif not data.text == 'true':
                    logging.warning("Invalid value for function 'enterLoopHead': %s", data.text)
            elif key == 'enterFunction':
                #TODO: Must also use returnFromFunction
                pass
            elif key == 'returnFromFunction':
                #TODO: Must also use enterFunction
                pass
            elif key == 'threadId':
                #TODO
                pass
            elif key == 'createThread':
                #TODO
                pass
            else:
                logging.warning("Unknown key for edge data element: %s", key)
        else:
            logging.warning("Expected data element to have attribute 'key'")

    def handle_graph_data(self, data):
        if len(data) > 0:
            logging.warning("Expected data element to not have any children but has %d", len(data))
        if len(data.attrib) > 1:
            logging.warning("Expected data element to have exactly one attribute but has %d",
                            len(data.attrib))
        if 'key' in data.attrib:
            key = data.attrib['key']
            if key == 'witness-type':
                if data.text in ['correctness_witness', 'violation_witness']:
                    if self.witness_type is None:
                        self.witness_type = data.text
                    else:
                        logging.warning("Found multiple definitions of witness-type")
                else:
                    logging.warning("Invalid value for function 'witness-type': %s", data.text)
            elif key == 'sourcecodelang':
                if data.text in ['C', 'Java']:
                    if self.sourcecodelang is None:
                        self.sourcecodelang = data.text
                    else:
                        logging.warning("Found multiple definitions of sourcecodelang")
                else:
                    logging.warning("Invalid value for function 'sourcecodelang': %s", data.text)
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
                else:
                    logging.warning("Found multiple definitions of programfile")
            elif key == 'programhash':
                if re.match(r'[\da-f]{40}|[\da-f]{64}', data.text):
                    #TODO: If programfile accessible:
                    #      Compute hash of programfile and compare with hash from witness
                    if self.programhash is None:
                        self.programhash = data.text
                    else:
                        logging.warning("Found multiple definitions of programhash")
                else:
                    logging.warning("%s is not a valid sha1 or sha256 hashsum", data.text)
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
            else:
                logging.warning("Unknown key for graph data element: %s", key)
        else:
            logging.warning("Expected data element to have attribute 'key'")

    def handle_key(self, key):
        if len(key.attrib) < 2:
            logging.warning("Key must have at least 'id' and 'for' attributes")
        if "id" in key.attrib:
            key_id = key.attrib['id']
            self.defined_keys.append(key_id)
        else:
            logging.warning("Key is missing attribute 'id'")
            key_id = None
        if "for" in key.attrib:
            key_domain = key.attrib['for']
        else:
            logging.warning("Key is missing attribute 'for'")
            key_domain = None
        if key_id and key_domain:
            #TODO: Check whether key_domain is correct for this key_id
            pass
        if len(key) > 1:
            logging.warning("Expected key to have at most one child but has %s", len(key))
        for child in key:
            if child.tag != "{http://graphml.graphdrawing.org/xmlns}default":
                logging.warning("Invalid child for key element: %s", child.tag)
            if len(child.attrib) != 0:
                logging.warning("Expected no attributes for 'default' element but found %d (%s)",
                                len(child.attrib), list(child.attrib))
            #TODO: Check default value

    def handle_node(self, node):
        if len(node.attrib) > 1:
            logging.warning("Expected node element to have exactly one attribute but has %d",
                            len(node.attrib))
        if 'id' in node.attrib:
            node_id = node.attrib['id']
            self.node_ids.add(node_id)
        else:
            logging.warning("Expected node element to have attribute 'id'")
        for child in node:
            self.handle_node_data(child)

    def handle_edge(self, edge):
        if len(edge.attrib) != 2:
            logging.warning("Expected edge element to have exactly two attributes but has %d",
                            len(edge.attrib))
        if 'source' in edge.attrib:
            source = edge.attrib['source']
            if source not in self.node_ids:
                self.check_existence_later.append(source)
        else:
            logging.warning("Edge is missing attribute 'source'")
        if 'target' in edge.attrib:
            target = edge.attrib['target']
            if target not in self.node_ids:
                self.check_existence_later.append(target)
        else:
            logging.warning("Edge is missing attribute 'target'")
        for child in edge:
            self.handle_edge_data(child)

    def handle_graph(self, graph):
        #TODO: Check attributes
        for child in graph:
            if child.tag == "{http://graphml.graphdrawing.org/xmlns}data":
                self.handle_graph_data(child)
            elif child.tag == "{http://graphml.graphdrawing.org/xmlns}node":
                # Already handled
                pass
            elif child.tag == "{http://graphml.graphdrawing.org/xmlns}edge":
                # Already handled
                pass
            else:
                logging.warning("Unexpected child element of type '%s'", child.tag)

    def handle_graphml_element(self, elem):
        #TODO: Check attributes
        for child in elem:
            if (child.tag != "{http://graphml.graphdrawing.org/xmlns}key"
                    and child.tag != "{http://graphml.graphdrawing.org/xmlns}graph"):
                logging.warning("Unexpected child element of type '%s'", child.tag)

    def final_checks(self):
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
                logging.warning("function %s is not allowed in correctness witness", key)
        elif self.witness_type == 'violation_witness':
            for key in self.correctness_witness_only:
                logging.warning("function %s is not allowed in violation witness", key)
        for node_id in self.check_existence_later:
            if node_id not in self.node_ids:
                logging.warning("Node %s has not been declared", node_id)

    def lint(self):
        num_graphs = 0
        for (_, elem) in ET.iterparse(self.witness):
            if elem.tag == "{http://graphml.graphdrawing.org/xmlns}data":
                # Will be handled later
                pass
            elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}default":
                # Will be handled later
                pass
            elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}key":
                self.handle_key(elem)
            elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}node":
                self.handle_node(elem)
            elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}edge":
                self.handle_edge(elem)
            elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}graph":
                num_graphs += 1
                if num_graphs > 1:
                    logging.warning("Found multiple graph definitions")
                else:
                    self.handle_graph(elem)
            elif elem.tag == "{http://graphml.graphdrawing.org/xmlns}graphml":
                self.handle_graphml_element(elem)
            else:
                logging.warning("Unknown tag: %s", elem.tag)
        self.final_checks()

def main(argv):
    #TODO: Add cmdline option for loglevel
    #TODO: Add cmdline option admitting that tool-specific keys are present in the witness
    #      -> set loglevel to info when encountering unknown key
    #TODO: Change format of logging output
    #TODO: Include position information
    logging.basicConfig(level=logging.WARNING)
    linter = WitnessLint(argv[1])
    start = time.time()
    linter.lint()
    print("Success")
    end = time.time()
    print("took ", end - start, "s")

if __name__ == '__main__':
    main(sys.argv)
