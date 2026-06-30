#!/usr/local/bin/python3

# DBconn.py
# Date: June 2020

__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'

import os

from py2neo import Graph, Node, Relationship
from py2neo.ogm import GraphObject, Property, RelatedFrom, RelatedTo
from neomodel import StructuredNode, StructuredRel, StringProperty, \
        IntegerProperty, UniqueIdProperty, FloatProperty, AliasProperty, \
        RelationshipTo, RelationshipFrom, db, Q
from neomodel import config as neo_config
from config import logger, local_entity
import config


# Graph DB configuration
neo_config.DATABASE_URL = os.environ["NEO4J_BOLT_URL"]


def connect_sensors():
    """
        Create nodes for interaction with sensors
        Query example: MATCH (a) WHERE a.name =~ ".+:I.+" RETURN a
    """
    InputNodes = Varnode.nodes.filter(Q(name__contains=':I.'), Q(entity=local_entity))
    for sensor_node in InputNodes:
        logger.debug("Creating sensor connection {}"
            .format(sensor_node.name))

        physical_sensor = SensorNode.get_or_create({
            'name': sensor_node.name})[0]

        physical_sensor.from_sensor.connect(sensor_node)


def connect_actuators():
    """
        Create nodes for interaction with actuators
        query example: "MATCH (a) WHERE a.name =~ '.+:O.+' AND a.entity 
        CONTAINS '{}' RETURN a".format(local_entity)
    """
    OutputNodes = Varnode.nodes.filter(Q(name__contains=':O.'), entity=local_entity)

    for actuator_node in OutputNodes:
        logger.debug("Creating actuator connection {}"
            .format(actuator_node.name))
        physical_actuator = ActuatorNode.get_or_create({
            'name': actuator_node.name})[0]
        actuator_node.to_actuator.connect(physical_actuator)


def clean_network_connections():
    """
        Connect components between Controllers through network connections. 
        We assign config.GT to 99999 to easily identify edges created by 
        cleaning of network connections
    """
    config.GT = 99999
    msg_actions = ['rdf', 'wrt']
    # clean connections network --read_from/write_to-->> variable
    for act in msg_actions:
        if act == 'rdf':
            msg_nodes = Msgnode.nodes.has(read_from=True)
            local_vars = msg_nodes.read_from.all()
        else:
            msg_nodes = Msgnode.nodes.has(write_to=True)
            local_vars = msg_nodes.write_to.all()

        for lv in local_vars:
            internal_vars = Varnode.nodes.filter(
                Q(name__contains=lv.name), entity=lv.entity)
            logger.debug(
                "Connecting r/w messages to variables for {}"
                .format(lv.name))
            create_strong_link([lv], internal_vars)

            logger.debug(
                "After cleaning messages. Message nodes: {} to Local variables: \
                {}".format(lv, internal_vars))

    # clean connections variable --read_from/write_to-->> network
    for act in msg_actions:
        if act == 'rdf':
            local_vars = Varnode.nodes.has(read_from=True)
        else:
            local_vars = Varnode.nodes.has(write_to=True)

        for lv in local_vars:
            internal_vars = Varnode.nodes.filter(
                Q(name__contains=lv.name), entity=lv.entity)
            logger.debug(
                "Connecting rd/wt messages from variables for {}"
                .format(lv.name))
            if len(internal_vars) == 0:
                logger.debug(
                    "Variable '{}' does not have components to connect on '{}'"
                    .format(lv.name, lv.entity))
            else:
                create_strong_link(internal_vars, [lv])


def create_weak_link(input_nodes, output_nodes):
    """
        Create a weak link connection between two node sets
    """
    if len(input_nodes) > 0 and len(output_nodes) > 0:
        for ipn in input_nodes:
            for opn in output_nodes:
                ipn.weak_link.connect(opn, {'time': config.GT})


def create_strong_link(input_nodes, output_nodes):
    """
        Create a strong link connection between two node sets
    """
    if len(input_nodes) > 0 and len(output_nodes) > 0:
        for ipn in input_nodes:
            for opn in output_nodes:
                ipn.strong_link.connect(opn, {'time': config.GT})


def merge_graph_node(name, entity, node_type):
    """
        This function combine get_create function for all node types in the 
        graph db
    """
    if node_type == 'var':
        new_node = Varnode.get_or_create({
            'name': name,
            'entity': entity,
            'cod': name + '-' + entity})[0]
    return new_node


def merge_nodes_from_list(name_set, entity, node_type):
    """
        This function create nodes from a list of names in the graph db
    """
    node_list = list()
    for n_name in name_set:
        node_list.append(merge_graph_node(n_name, entity, node_type))
    return node_list


class LinkRel(StructuredRel):
    time = IntegerProperty(default=0)


class Varnode(StructuredNode):

    name = StringProperty(index=True)
    entity = StringProperty(index=True)
    cod = StringProperty(unique_index=True)
    weight = IntegerProperty(default=1)

    weak_link = RelationshipTo('Varnode', 'weak_link', model=LinkRel)
    strong_link = RelationshipTo('Varnode', 'strong_link', model=LinkRel)
    read_from = RelationshipTo('Msgnode', 'read_from')
    write_to = RelationshipTo('Msgnode', 'write_to')
    to_actuator = RelationshipTo('ActuatorNode', 'to_actuator')


class Constnode(StructuredNode):
    name = StringProperty(unique_index=True)
    entity = StringProperty(index=True)
    weight = IntegerProperty()

    weak_link = RelationshipTo('Varnode', 'weak_link', model=LinkRel)
    strong_link = RelationshipTo('Varnode', 'strong_link', model=LinkRel)


class Msgnode(StructuredNode):

    name = StringProperty(unique_index=True)
    entity = StringProperty(index=True)
    weight = IntegerProperty()

    read_from = RelationshipTo('Varnode', 'read_from')
    write_to = RelationshipTo('Varnode', 'write_to')


class SensorNode(StructuredNode):
    name = StringProperty(unique_index=True)
    entity = StringProperty(index=True, default='Physical_domain')

    from_sensor = RelationshipTo('Varnode', 'from_sensor')


class ActuatorNode(StructuredNode):
    name = StringProperty(unique_index=True)
    entity = StringProperty(index=True, default='Physical_domain')

    to_actuator = RelationshipFrom('Varnode', 'to_actuator')


class Block(StructuredNode):
    name = StringProperty(unique_index=True)
    entity = StringProperty(index=True)
    firstLine = IntegerProperty()
    lastLine = IntegerProperty()
    lastBlk = RelationshipFrom('Block', 'nextBlk')
    nextBlk = RelationshipTo('Block', 'nextBlk')


class Controller(StructuredNode):
    name = StringProperty(unique_index=True)
    has_program = RelationshipTo('Program', 'has_program')


class Program(StructuredNode):
    name = StringProperty(unique_index=True)
    has_routine = RelationshipTo('Routine', 'has_program')


class Routine(StructuredNode):
    name = StringProperty(unique_index=True)
    lang = StringProperty()
    has_program = RelationshipFrom('Program', 'has_program')
