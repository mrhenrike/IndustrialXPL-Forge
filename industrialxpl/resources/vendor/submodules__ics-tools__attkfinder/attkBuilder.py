#!/usr/local/bin/python3

# attackBuilder.py
# This program uses a DFG and a CFG stored in a graph database (neo4j), and a 
# PLC program written in ST language to produce a attack verctors mapped to 
# the input space.
# Date: June 2020
__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'


from DBconn import Varnode, Constnode, Block
from neomodel import db

from CPS_toolbox import codeReader, st_lexer
from offensive import attack_repository, attack_target, attack_step
from CPS_graph_explorer import CFG, DFG, data_component


import json
import logging

# this function return a block given a line_id

logging.basicConfig(filename='attkBuilder.log', level=logging.DEBUG)


PLC_CODE_FILE = 'PLCcode.stir'

rd = codeReader()

rd.load_code(PLC_CODE_FILE)
JSON_ATTCK_FILE = 'attackTree.json'

attck_tree = attack_repository()
attck_tree.load_from_json_file(JSON_ATTCK_FILE)

CFG_agent = CFG()
DFG_agent = DFG()

with open(JSON_ATTCK_FILE) as at_file:
    at_data = at_file.read()

attack_tree = json.loads(at_data)

# initial variables
# Cases:
# P1: 
#   ('RIO1:1:O.0', 1, 'B227') 
#   ('P101_FB.Permissive', -1, 'B158') 
#   ('P101_FB.Cmd_Start', 1, 'B158')
# P2:
#   ('HMI_P201.Cmd', 2, 'B193')
target_set = [attack_target('SCADA_Q3_1_Open', 1, 'B146')]

while len(target_set) > 0:
    target = target_set.pop(0)
    lx_agent = st_lexer()
    input_space_map = dict({'sensor': [], 'local': [], 'network': [], 'timer': []})
    banned_blocks = list()

    target_node = data_component(target.name)
    target_node.get_depedencies()
    logging.info(target_node.summary())
    attack_leaf = attack_step(target=target, data_object=target_node, code_reader=rd)
    logging.info(attack_leaf.summary())

    if attack_leaf.check_validity():
        print('Valid attack step: {}\n\n with attack data source: \n{}'.format(
            attack_leaf.summary(), attack_leaf.source))

        for att_src in attack_leaf.source:
            if 'B' in att_src.block_id:
                target_set.append(att_src)
            else:
                print('Input space component: {}'.format(att_src))


exit()

print(attck_tree.get_dictionary())
# with open('attackTree.json', 'w') as f:
#     json.dump(attack_tree, f)
