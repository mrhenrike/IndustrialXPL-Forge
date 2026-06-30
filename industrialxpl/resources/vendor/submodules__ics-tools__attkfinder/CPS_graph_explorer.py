#!/usr/local/bin/python3

# CPS_graph_explorer.py
# Date: June 2020
__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'

from DBconn import Varnode, Constnode, Block
from neomodel import db, Q

import logging

logger = logging.getLogger(__name__)


class CFG():
    """This class implements all functions to explore the Control-Flow Graph"""
    root_control_flow = []
    start_block = 'B1'
    end_block = ''

    def __init__(self):
        # set start_block as the root block in the CFG
        start_block = Block.nodes.order_by('firstLine').first_or_none()
        self.start_block = start_block.name

        # set end_block as the final block in the CFG
        end_block = Block.nodes.order_by('-firstLine').first_or_none()
        self.end_block = end_block.name

        control_flow = self.get_control_flow(self.start_block, self.end_block)
        self.root_control_flow = control_flow

    def get_block_from_line(self, line_id):
        """ This function returns a Block based on the line id"""
        target_block = Block.nodes.filter(
                firstLine__lte=line_id, 
                lastLine__gte=line_id)\
                .first()
        return target_block

    def get_block_from_block_id(self, block_id):
        block_name = ''
        logger.debug('getting block for {} id'.format(block_id))

        try:
            int(block_id)
            block_name = 'B' + str(block_id)
        except Exception as error:
            if 'B' in block_id:
                block_name = block_id
        target_block = Block.nodes.first_or_none(name=block_name)

        return target_block

    def path_exist(self, block1, block2):
        """ 
        This function uses neo4j's shortestPath algortihm to check if 
        'block1' and 'block2' are connected 
        """
        path_checker = False

        # check if block1 and block2 are the same
        if block1.name == block2.name:
            return [block1]

        query = "match (node1:Block {name:'" + block1.name + "'}),\
                (node2:Block {name:'" + block2.name + "'}),\
                p=shortestPath((node1)-[*]->(node2)) return count(rels(p))"

        results, meta = db.cypher_query(query)

        path_checker = results[0][0] > 0

        return path_checker

    def get_control_dependencies(self, target_node, line_id):
        """ 
        This function gets control dependencies for a particular variables 
        in a line id
        """
        control_depend_nodes = list()
        query = "match (n:Varnode{name:'" + target_node.name + "', \
            entity:'" + target_node.entity + "'})<-[r:weak_link \
                {time:" + str(line_id) + "}]-(m) return m"
        results, meta = db.cypher_query(query)

        for rs in results:
            if 'Varnode' in rs[0].labels:
                parent_node = Varnode.inflate(rs[0])
            elif 'Constnode' in rs[0].labels:
                parent_node = Constnode.inflate(rs[0])
            control_depend_nodes.append(parent_node)

        return control_depend_nodes

    def get_control_flow(self, B1_name, B2_name):

        logger.info('Getting control flow for {} - {} path'\
            .format(B1_name, B2_name))
        B1 = Block.nodes.first_or_none(name=B1_name)
        B2 = Block.nodes.first_or_none(name=B2_name)

        control_flow = list()
        query = "match (node1:Block {name:'" + B1.name + "'}),\
                (node2:Block {name:'" + B2.name + "'}),\
                p=shortestPath((node1)-[*]->(node2)) return nodes(p)"

        results, _ = db.cypher_query(query)

        for rs in results[0][0]:
            b_in_path = Block.inflate(rs)
            control_flow.append(int(b_in_path.name[1:]))

        logger.info('Control flow:{}'.format(control_flow))
        return control_flow

    def get_control_flow_to_root_path(self, B_name):
        target_block_id = int(B_name[1:])
        root_control_flow = self.root_control_flow
        control_chain = list()

        root_flow_slice = sorted(list(filter(
            lambda x: x < target_block_id, root_control_flow)))

        B2 = Block.nodes.first_or_none(name=B_name)

        while len(root_flow_slice) > 0:
            first_block_id = root_flow_slice[-1]
            B1 = self.get_block_from_block_id(first_block_id)
            logger.debug('Validating {} - {} path'.format(B1.name, B2.name))
            if self.path_exist(B1, B2):
                control_chain = sorted(self.get_control_flow(B1.name, B2.name), reverse=True)
                break
            root_flow_slice = root_flow_slice[:-1]

        return control_chain


class DFG():
    """This class implements all methods for Data-Flow Graph objects."""

    CLASS_LOGGING_HEADER = ' [DFG]  '

    def get_parents_and_time(self, node, link_type='strong_link'):
        CLH = self.CLASS_LOGGING_HEADER
        logger.debug('{}Getting parents for {} ({}) with {}'.format(
            CLH, node, type(node), link_type))

        query = "MATCH (n:Varnode{name:'" + node.name + "', entity:'" + \
            node.entity + "'})<-[r:" + link_type + "]-(m) RETURN m, r.time"
        results, _ = db.cypher_query(query)
        data_parents = list()
        for rs in results:
            # store line_id from strong_link edge in DFG
            target_line = int(rs[1])        
            if target_line == 99999:
                # Checks for connection to a network node (unique id: 99999)
                logging.warning('[DD]   [!!!]  Network message found')
            if 'Varnode' in rs[0].labels:
                parent_node = Varnode.inflate(rs[0])
            elif 'Constnode' in rs[0].labels:
                parent_node = Constnode.inflate(rs[0])
            data_parents.append((parent_node, target_line))

        logger.debug(CLH + '{} parent(s) found'.format(len(data_parents)))

        return data_parents


class data_component():
    """docstring for data_component."""
    name = ''
    node_repr = ''
    data_parents = []
    control_parents = dict()
    data_members = []

    def __init__(self, var_name, entity='Controller_P2'):
        target_node = Varnode.nodes.first_or_none(name=var_name, entity=entity)
        self.name = var_name
        self.node_repr = target_node

    def summary(self):
        """Present a easy to read summary of the data component"""
        description = 'Data Component: {}\n\t * Data parents: \n'\
            .format(self.name)

        for dp in self.data_parents:
            description = description + '\t\t- {} (l:{})\n'\
                .format(dp[0].name, dp[1])

        description = description + '\n\t * Control parents: \n'

        control_parents = self.control_parents
        for cp in control_parents:
            description = description + \
                '\t\t- (l:{}) {} \n'\
                    .format(cp, [nd.name for nd in control_parents[cp]])

        description = description + '\n\t * Members: \n'

        for dm in self.data_members:
            description = description + '\t\t- {}\n'\
                    .format(dm.name)

        return description

    def get_depedencies(self):
        self.get_data_parents()
        self.get_control_parents()
        self.get_members()

    def get_data_parents(self):
        node = self.node_repr
        dg = DFG()
        data_parents = dg.get_parents_and_time(node=node, link_type='strong_link')
        self.data_parents = data_parents

    def get_control_parents(self):
        node = self.node_repr
        dg = DFG()
        cp_dict = dict()
        control_parents = dg.get_parents_and_time(node=node, link_type='weak_link')
        for cp in control_parents:
            cp_node = cp[0]
            line_id = cp[1]
            if line_id in cp_dict:
                cp_dict[line_id].append(cp_node)
            else:
                cp_dict[line_id] = [cp_node]

        self.control_parents = cp_dict

    def get_members(self):
        node = self.node_repr
        children_nodes = Varnode.nodes.filter(
            name__contains=node.name + '.', name__ne=node.name).all()
        if children_nodes is None:
            children_nodes = []
        self.data_members = children_nodes
