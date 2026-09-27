#!/usr/local/bin/python3

# clear_db.py
# This script deletes all nodes of a paticular type from the graphDB

import config
from DBconn import Varnode, Msgnode, Block, Constnode, Controller, Program,\
        Routine

node_types = [
        Varnode, Msgnode, Block, Constnode, Controller, Program,\
        Routine
        ]

for ntype in node_types:
    all_nodes = ntype.nodes.all()
    print(f'Clearing {len(all_nodes)} nodes')
    for node in all_nodes:
        node.delete()
    print('! Done')
