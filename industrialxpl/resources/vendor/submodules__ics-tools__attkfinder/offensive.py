#!/usr/local/bin/python3

# offensive.py
# Date: June 2020
__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'

import json
import logging

from CPS_toolbox import st_lexer
from CPS_graph_explorer import data_component, CFG

logger = logging.getLogger(__name__)


class attack_target():
    """docstring for attack_target."""
    name = ''
    value = 0
    block_id = ''

    def __init__(self, name, value, block_id):
        self.name = name
        self.value = value
        self.block_id = block_id

    def __repr__(self):
        return '{}<-{}({})'.format(self.name, self.value, self.block_id)


class attack_step(data_component):
    """docstring for attack_step."""
    source = list()

    def __init__(self, target, data_object, code_reader,  line_id=0):

        if target.name != data_object.name:
            logger.warning(' Data object does not match target')
            return -1

        # store list of data dapendency lines
        dd_lines = list()
        for dd in data_object.data_parents:
            dd_lines.append(dd[1])

        dd_lines = sorted(dd_lines)
        if line_id == 0:
            if len(data_object.data_parents) > 0:
                line_id = dd_lines[0]
                logger.info('Unknown line id, get new line id ({}) from \
                    data_component'.format(line_id))

        self.target = target
        self.plc_code = code_reader
        self.data_object = data_object
        self.dd_lines = dd_lines
        if len(dd_lines) > 0:
            self.update_target_line(dd_lines[0])
        else:
            self.target_line = 0

    def update_target_line(self, line_id):
        '''Update attack_step object based on line_id number'''
        data_object = self.data_object
        self.target_line = line_id

        data_parents = list()
        control_parents = list()

        for dp in data_object.data_parents:
            parent_node = dp[0]
            dp_line = dp[1]
            if dp_line == line_id:
                data_parents.append(parent_node)

        self.data_parents = data_parents

        if line_id in data_object.control_parents:
            self.control_parents = data_object.control_parents[line_id]

        self.data_members = data_object.data_members

    def summary(self):
        """Print a easy to read version of the data component"""
        description = 'Attack step: Target: {}\n\t * Data parents: \n'\
            .format(self.target)

        for dp in self.data_parents:
            description = description + '\t\t- {} (l:{})\n'\
                .format(dp.name, self.target_line)

        description = description + '\n\t * Control parents: \n'

        control_parents = self.control_parents
        description = description \
                + '\t\t- (l:{}) {} \n'\
                    .format(self.target_line, [
                        nod.name for nod in control_parents
                        ])

        description = description + '\n\t * Members: \n'

        for dm in self.data_members:
            description = description + '\t\t- {}\n'.format(dm.name)

        return description

    def check_validity(self):
        target = self.target
        plc_code = self.plc_code
        satisfied_status = False
        DD_valid = False
        CD_valid = False
        cg_agent = CFG()
        src_attack = list()

        for target_line in self.dd_lines:
            lx_agent = st_lexer()
            self.update_target_line(target_line)
            target_block = cg_agent.get_block_from_block_id(target.block_id)

            logger.info(' Checking validity of Data dependencies for {}'\
                .format(target))
            print(target, target.block_id)

            if target_line != 0:
                logger.debug('Getting statement for line {}'\
                    .format(target_line))

                if target_line == 99999:
                    # Check connection to network message
                    logger.info('Network message dependency')

                    src_attack.append(attack_target(
                            target.name, 
                            target.value, 
                            'Net'
                            ))
                    satisfied_status = True
                    self.checked = True
                    self.valid = satisfied_status
                    self.source = src_attack
                    return satisfied_status

                statement = plc_code.get_line(target_line)
                print('[DD]  [*] Statement: {}'.format(statement[:-1]))
                if target.value in [0, 1]:
                    lx_agent.definition_value = True if target.value == 1 else False
                else:
                    lx_agent.definition_value = target.value
                solver_status, extracted_symbolic_variables = lx_agent.eval(statement)
                print('[DD]    [**] Statement analysis: {}, {}'\
                    .format(solver_status, extracted_symbolic_variables))

                logger.info('SMT results: Status: {}, Symbolic values: {}'\
                    .format(lx_agent.status, lx_agent.results))

                if lx_agent.valid:
                    logger.info('DD Satisfied')
                    logger.info(' Checking path between {} and Data dependencies\
                        for {}'\
                            .format(self.data_parents, target))

                    DD_block = cg_agent.get_block_from_line(line_id=target_line)
                    path_check = False
                    if cg_agent.end_block[1:] in DD_block.name:
                        path_check = True
                    elif cg_agent.path_exist(DD_block, target_block):
                        path_check = True
                    if path_check:
                        logger.info('{}->{} path: OK'\
                            .format(DD_block.name, target_block.name))
                        DD_valid = True
                        for lxrs in lx_agent.results:
                            src_attack.append(attack_target(
                                        lxrs[0], 
                                        lxrs[1], 
                                        DD_block.name))
                        break

                else:
                    logger.info('DD Unsat')
                    satisfied_status = False

        if DD_valid:
            if len(self.control_parents) > 0:
                logger.info('Checking validity of Control dependencies for {}'\
                    .format(target))
                control_chain = cg_agent.get_control_flow_to_root_path(
                                    DD_block.name)

                for b_id in control_chain:
                    this_block = cg_agent.get_block_from_block_id(b_id)
                    stmt = plc_code.get_line(this_block.firstLine)
                    logger.info('[LXR] Processing({}): {}'\
                        .format(this_block.name, stmt))
                    if lx_agent.status == 2:
                        # Else statement was processed previously
                        lx_agent.status = 0
                        continue
                    elif lx_agent.status == 3:
                        # 3 = Case detected, the value is returned to be 
                        # asigned to variables in the parent block (2:)
                        lx_agent.definition_value = lx_agent.results[0]
                        solver_status, symbolic_variable = lx_agent.eval(stmt)
                        logger.info(
                            'Solver result (status=3): {} - {}'\
                                .format(lx_agent.status, lx_agent.results))
                        src_attack.append(attack_target(
                            lx_agent.results[0][0], 
                            lx_agent.results[0][1], 
                            this_block.name))
                    else:
                        lx_agent.definition_value = True
                        solver_status, extracted_symbolic_variables = \
                            lx_agent.eval(stmt)

                    print('Msg: {}'.format(solver_status))
                    if solver_status == 2:
                        # 2 = requires check diverge paths and negate their 
                        # symbolic values (ELSE, ELSIF)
                        parent_block = this_block.lastBlk.get()
                        siblings = parent_block.nextBlk.filter(
                                    firstLine__lt=this_block.firstLine)
                        logger.info('Previous block: {}'.format(parent_block))
                        stmt = 'IF ('
                        for sib in siblings:
                            logger.info('Sibling: {}'.format(sib.name))
                            raw_stmt = plc_code.get_line(sib.firstLine)
                            if 'CASE' in raw_stmt:
                                continue
                            raw_stmt = raw_stmt.replace('IF ', "")
                            raw_stmt = raw_stmt.replace(' THEN', "")
                            stmt += raw_stmt + ' AND '
                        stmt = stmt[:-4] + ') THEN'
                        logger.info('In solver_status = 2. statement: {} '\
                            .format(stmt))
                        lx_agent.definition_value = False
                        solver_status, extracted_symbolic_variables = \
                            lx_agent.eval(stmt)
                        logger.info(
                            'Solver result (status=2): {} - {}'\
                                .format(solver_status, extracted_symbolic_variables))
                        for lxrs in lx_agent.results:
                            src_attack.append(attack_target(
                                        lxrs[0], 
                                        lxrs[1], 
                                        this_block.name))

                    elif lx_agent.status == 3:
                        continue
                    else:
                        print('Solver result (status=0,1,4..): {} - {}'\
                            .format(solver_status, extracted_symbolic_variables))
                        for lxrs in lx_agent.results:
                            src_attack.append(attack_target(
                                        lxrs[0], 
                                        lxrs[1], 
                                        this_block.name))

                    logger.info('Attack data source: {}'.format(src_attack))

                satisfied_status = True

            else:
                satisfied_status = True

        else:
            logger.info('Checking validity of Data members {}'.format(target))
            if len(self.data_members) == 0:
                satisfied_status = False
            else:
                satisfied_status = True
                member_value = 0
                if target.value == -1:
                    member_value = 1
                for d_member in self.data_members:
                    src_attack.append(attack_target(
                            d_member.name, 
                            member_value, 
                            target.block_id))

        # check data parent validity (satisfied)
        # check control path from data_parents to target
        # get cotrol parent statements
        # check control parent validity (satisfied)
        self.checked = True
        self.valid = satisfied_status
        self.source = src_attack
        return satisfied_status


class attack_repository():
    attck_dict = dict()

    def load_from_json_file(self, file_name):
        '''Load a json file and store into attck_dict'''
        if '.json' in file_name:
            with open(file_name) as at_file:
                at_data = at_file.read()
        try:
            self.attck_dict = json.loads(at_data)
        except Exception as e:
            print('[!!!]: Error loading JSON file ({})\n{}'\
                .format(file_name, e))

    def update_definitions(self, target, data_definitions, definitions_in_line=[]):
        attack_tree = self.attck_dict
        var_name = target.name
        var_value = target.value
        block_id = target.block_id

        print('UPDATING ATTACK TREE: {}'.format(attack_tree))
        print('WITH PARAMETERS: T:{}, DD:{}, in_line:{}'\
            .format(target, data_definitions, definitions_in_line))

        # format valid and banned definitions
        valid_definitions = ''
        banned_definitons = ''
        if 'valid' in data_definitions:
            valid_definitions = data_definitions['valid']
        if 'banned' in data_definitions:
            banned_definitons = data_definitions['banned']
        if len(definitions_in_line) > 0:
            valid_definitions = {
                str(k[0]) + '-' + str(k[1]): \
                    definitions_in_line for k in data_definitions['valid']}

        if var_name in attack_tree:
            if var_value in attack_tree[var_name]:
                if block_id in attack_tree[var_name][var_value]:
                    if type(banned_definitons) is list:
                        # update banned definitions
                        old_banned_defs = \
                            attack_tree[var_name][var_value][block_id][
                                'definitions']['banned']
                        new_banned_defs = list(set(old_banned_defs \
                                + banned_definitons))
                        attack_tree[var_name][var_value][block_id][
                                'definitions']['banned'] = new_banned_defs

                    if type(valid_definitions) is dict:
                        # update valid definitions
                        new_valid_defs = attack_tree[var_name][var_value][
                                block_id]['definitions']['valid']
                        for k in valid_definitions:
                            if k in new_valid_defs:
                                new_valid_defs[k] = list(
                                        set(new_valid_defs[k] \
                                            + valid_definitions[k]))
                            else:
                                new_valid_defs.update({k: valid_definitions[k]})

                        attack_tree[var_name][var_value][block_id][
                                'definitions']['valid'] = new_valid_defs
                else:
                    attack_tree[var_name][var_value][block_id] = {
                        'definitions': {
                            'valid': valid_definitions,
                            'banned': banned_definitons}}

            else:
                attack_tree[var_name][var_value] = {
                    block_id: {
                        'definitions': {
                            'valid': valid_definitions,
                            'banned': banned_definitons}}}
        else:
            attack_tree[var_name] = {
                var_value: {
                    block_id: {
                        'definitions': {
                            'valid': valid_definitions,
                            'banned': banned_definitons}}}}

        self.attck_dict = attack_tree

        print('UPDATED ATTACK TREE: {}'.format(attack_tree))

    def get_dictionary(self):
        return self.attck_dict
