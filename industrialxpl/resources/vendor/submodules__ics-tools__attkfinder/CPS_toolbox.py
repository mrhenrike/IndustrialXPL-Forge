#!/usr/local/bin/python3

# CPS_toolbox.py
# Date: June 2020
__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'


import re
import string
import logging

from neomodel import db, Q
from z3 import *

from DBconn import Varnode, Constnode, Block

logger = logging.getLogger(__name__)


class codeReader():
    """docstring for codeReader."""
    code_dict = dict()

    def load_code(self, file_name):
        # read a plc code and store in a dict
        with open(file_name, 'r') as rd:
            for line in rd:
                try:
                    line_id = int(line.split(':')[0].split(' ')[-1])
                    line_stmt = line[line.find(':') + 1:]
                    self.code_dict[line_id] = line_stmt
                except Exception as e:
                    continue

    def get_line(self, line_id):
        try:
            stmt = self.code_dict[line_id]
        except Exception as e:
            stmt = None
        return stmt


class st_lexer():
    """docstring for st_lexer."""
    LEXER_REGX = r"""
        # 1. close condition
        (END_IF|END_CASE)        
        # 2. open clause
        |(IF\s|CASE\s|ELSIF\s|ELSE)
        # 3. close clause        
        |(\s*THEN|\sOF\s?) 
        # 4. open group       
        |(\s?\(\s?)        
        # 5. close group
        |(\s?\)\s?)        
        # 6. function
        |(\w+\()                                  
        # 7. case object 
        |(\d+:)                                   
        # 8. definition
        |(\s?:=)                                    
        # 9. logical operator
        |([<>=]\s?|\s?NOT\s?|\s?AND\s?|\s?OR\s?|[<>]=\s?)
        # 10. number
        |(\d+)                                   
        # 11. variables
        |(\w+:?\w+:?\w+\.?\w+\.?\w*|\w+\.?\w*\.?\w*\.?\w*)
        # 12. whitespace
        |(\s+)                                    
        # 13. arithmetic operations
        |([\+\*\/\-])                            
        # 14. special character        
        |(.+)                                    
        """
    original_stmt = ''
    SMT_solver = False
    definition_value = 0
    status = 0
    results = []
    valid = False
    checked = False

    # solver status:
    # 0:
    # 1:
    # 2: requires check diverge paths and negate their symbolic values 
    #       (ELSE, ELSIF)
    # 3: Case detected, the value is returned to be asigned to variables 
    #       in the parent block (2:)
    # 4: Check if constant value satisfies
    # 5: Definition with multiple variables in the predicate
    # 6: Statement diverges

    def eval(self, statement):

        if statement is None:
            logger.debug('Empty statement')
            self.status = 0
            self.results = []
            return 0, []

        # List of all variables analysed in the statement
        var_list = list()                   
        # List of variables used in the Statement, in case of a definiton, 
        # it does not include the defined variable
        variables_in_stmt = list()
        clean_stmt = list()
        fnc = ''
        ptr = re.compile(self.LEXER_REGX, re.VERBOSE)
        scan = ptr.scanner(statement)
        self.original_stmt = statement
        self.var_type = type(self.definition_value)
        ascii_set = string.ascii_letters
        l_operation = ''
        arith_operation = ''
        pending_stmt = []
        pre_process_stmt = []
        s = Solver()                        # SMT solver
        solver_status = 0
        definition_inline = False
        open_group = False
        # Logical and to encapsulate predicate in a definition statement
        land_open = False                   
        lor_open = False
        previous_sym_var = ''

        while True:
            m = scan.search()
            if not m:
                break

            if m.lastindex == 1:                
                # Detect a condition end i.e. 'END_IF' or 'END_CASE'
                logger.debug('END caught')
                self.status = 0
                self.results = []
                return 0, []

            elif m.lastindex == 2:
                # Detect 'ELSE' clause
                self.var_type = bool
                if 'ELSE' in repr(m.group(m.lastindex)):
                    # Increase Basic block node_counter
                    logger.debug('ELSE caught')
                    self.status = 2
                    self.results = []
                    return 2, []

                if 'ELSIF' in repr(m.group(m.lastindex)):
                    logger.debug('ELSIF caught')
                    self.SMT_solver = True
                    solver_status = 2

                elif 'IF' in repr(m.group(m.lastindex)):
                    logger.debug('IF caught')
                    self.SMT_solver = True
                    solver_status = 1

            elif m.lastindex == 3:                
                # Detect a close of a conditional clause i.e. 'THEN'
                logger.debug('close of conditional')

                # For 'CASE' it creates a new open_blocks element
                if 'OF' in repr(m.group(m.lastindex)):
                    logger.debug('got a CASE')
                    self.status = 0
                    self.results = variables_in_stmt
                    pre_process_stmt = [[pre_process_stmt[0], '==',
                                         self.definition_value]]

                    # change boolean variable to integer type
                    sym_var_to_change = previous_sym_var
                    type_changer = "{} = Int('{}')"\
                        .format(sym_var_to_change, sym_var_to_change)
                    exec(type_changer)
                    # return 0, variables_in_stmt
                    self.SMT_solver = True
                    solver_status = 0

                else:   
                    # For 'IF ... THEN' creates an additional path with each 'THEN'
                    logger.debug('got an IF')

            elif m.lastindex == 4:                  
                # Detect open group (
                open_group = True
            elif m.lastindex == 5:                  
                # Detect ')'
                if open_group:
                    stmt_to_process = ''
                    open_group = False

                else:
                    logger.debug('got functions')

                    if fnc == 'timer':
                        # timer function
                        t_var = variables_in_stmt[-1]
                        fnc = ''
                    elif fnc == 'setd':
                        # set function
                        t_var = variables_in_stmt[-1]
                        fnc = ''
                    elif fnc == 'scale':
                        # scale function
                        t_var = variables_in_stmt[-1]
                        fnc = ''
                    elif fnc == 'alarm':
                        # alarm function
                        t_var = variables_in_stmt[-1]
                        fnc = ''
                    elif fnc == 'osri':
                        # osri function
                        t_var = variables_in_stmt[-1]
                        fnc = ''
            elif m.lastindex == 6:                
                # Detect a functions
                c_fnc = repr(m.group(m.lastindex)).replace("'", "")
                if 'TONR' in c_fnc:             # Time On Delay
                    fnc = 'timer'
                elif 'SETD' in c_fnc:           # Set dominant
                    fnc = 'setd'
                elif 'SCL' in c_fnc:            # SCALE
                    fnc = 'scale'
                elif 'ALM' in c_fnc:            # Alarm
                    fnc = 'alarm'
                elif 'OSRI' in c_fnc:            # One-shot rising with input
                    fnc = 'osri'
                elif 'ABS' in c_fnc:            # Absolute value
                    pass
                else:
                    logger.debug("    [!]Function {} pending to process".format(c_fnc))
            elif m.lastindex == 7:                
                # Detect a new case object (new state)
                # Increase Basic block node_counter
                case_value = int(m.group(m.lastindex)[:-1])
                self.status = 3
                self.results = [case_value]
                return 3, [case_value]

            elif m.lastindex == 8:                  
                # Detect a definition
                definition_inline = True
                defined_vars = set(variables_in_stmt)
                # clear vars in line
                variables_in_stmt = []               
                if len(pre_process_stmt) == 1:
                    pre_process_stmt = [
                                pre_process_stmt[0], 
                                '==',
                                self.definition_value, 
                                ',',
                                pre_process_stmt[0], 
                                ' == ( '
                                ]
                else:
                    logger.debug('pre_process: {}'.format(pre_process_stmt))
                    pre_process_stmt[:-1].append([
                                    pre_process_stmt[-1],
                                    ' == ', 
                                    self.definition_value], 
                                    [pre_process_stmt[-1], 
                                    ' == '
                                    ])
                logger.debug('pre_process: {}'.format(pre_process_stmt))
            elif m.lastindex == 9:                  
                # Detect a logical operator
                l_operator = m.group(m.lastindex)
                logger.debug('logical operator {} caught'.format(l_operator))
                logger.debug('[SMT]   pre_process: {}'.format(pre_process_stmt))
                if 'AND' in l_operator:
                    if lor_open:
                        pre_process_stmt.append(')')
                        lor_open = False
                    l_operation = 'land'
                    # if definition_inline:
                    if land_open:
                        pre_process_stmt.append(', ')
                    else:
                        land_open = True
                        stmt_ix = -1
                        while type(previous_sym_var) != type(pre_process_stmt[stmt_ix]):
                            stmt_ix -= 1
                        pre_stmt1 = pre_process_stmt[:stmt_ix]
                        pre_stmt2 = pre_process_stmt[stmt_ix:]
                        pre_process_stmt = pre_stmt1 + ['And('] + pre_stmt2
                        pre_process_stmt.append(', ')
                    logger.debug('pre_process (after land): {}'\
                        .format(pre_process_stmt))
                if 'OR' in l_operator:
                    l_operation = 'lor'
                    lor_open = True
                    pre_process_stmt = pre_process_stmt[:-1] + \
                        ['Or( '] + [pre_process_stmt[-1]]
                    pre_process_stmt.append(', ')
                    logger.debug('pre_process (after lor): {}'\
                        .format(pre_process_stmt))
                if 'NOT' in l_operator:
                    l_operation = 'lnot'
                if '<' in l_operator:
                    l_operation = 'less'
                    pre_process_stmt.append(' < ')
                    self.var_type = int
                    # change boolean variable to integer type
                    sym_var_to_change = previous_sym_var
                    logger.debug('Constant detected')
                    type_changer = "{} = Int('{}')"\
                        .format(sym_var_to_change, sym_var_to_change)
                    logger.debug(
                        '< operator detected, updating symbolic variable type: {}'\
                            .format(type_changer))
                    exec(type_changer)
                if '>' in l_operator:
                    if 'less' in l_operation:
                        l_operation = 'neq'
                        pre_process_stmt = pre_process_stmt[:-1] + [' != ']
                    else:
                        l_operation = 'greater'
                        pre_process_stmt.append(' > ')
                        self.var_type = int

                        # change boolean variable to integer type
                        sym_var_to_change = previous_sym_var
                        logger.debug('Constant detected')
                        type_changer = "{} = Int('{}')"\
                            .format(sym_var_to_change, sym_var_to_change)
                        logger.debug(
                            '> operator detected, updating symbolic variable \
                            type: {}'\
                                .format(type_changer))
                        exec(type_changer)
                if '=' in l_operator:
                    l_operation = 'eq'
                    pre_process_stmt.append(' == ')
                    self.var_type = type(self.definition_value)

            elif m.lastindex == 10:                 
                # Detect a constant value
                this_constant = int(repr(m.group(m.lastindex)).replace("'", ""))
                if 'negative' in arith_operation:
                    this_constant = this_constant * (-1)
                    arith_operation = ''

                pre_process_stmt = pre_process_stmt + [this_constant, ',']
                #sym_var_to_change = pre_process_stmt[0]
                sym_var_to_change = previous_sym_var

                # change boolean variable to integer type
                logger.debug('Constant detected')
                type_changer = "{} = Int('{}')"\
                    .format(sym_var_to_change, sym_var_to_change)
                logger.debug(
                    'Constant detected, updating symbolic variable type: {}'\
                        .format(type_changer))
                exec(type_changer)

            elif m.lastindex == 11:                 
                # Detect a variable
                catched_var = repr(m.group(m.lastindex)).replace("'", "")

                # clean statement rename variables to simpler version to make 
                # the SMT solver job much easier
                if catched_var in var_list:
                    var_list_ix = var_list.index(catched_var)
                    logger.debug('{} in {} with index {}'.format(
                        catched_var, clean_stmt, var_list_ix))
                    clean_stmt_ix = var_list_ix
                else:
                    var_list.append(catched_var)
                    variables_in_stmt.append(catched_var)
                    sym_var = ascii_set[var_list.index(catched_var)]
                    if self.var_type is int:
                        clean_stmt.append(Int(sym_var))
                        sym_var_init = "{}=Int('{}')".format(sym_var, sym_var)
                    else:
                        clean_stmt.append(Bool(sym_var))
                        sym_var_init = "{}=Bool('{}')".format(sym_var, sym_var)

                    logger.debug('Initializing variable {}: {}'\
                        .format(sym_var, sym_var_init))
                    exec(sym_var_init)
                    clean_stmt_ix = -1

                if 'lnot' in l_operation:
                    pre_process_stmt.append(Not(clean_stmt[clean_stmt_ix]))
                    l_operation = ''
                    pre_process_stmt.append(',')
                else:
                    pre_process_stmt.append(clean_stmt[clean_stmt_ix])

                if 'lor' in l_operation:
                    logger.warning('Disjuntion !!!')

                logger.debug("    [*][*] [Variable in line]: {}"\
                    .format(variables_in_stmt))
                #logger.debug(clean_stmt, s)
                previous_sym_var = clean_stmt[clean_stmt_ix]

            elif m.lastindex == 13:                 
                # Detect an arithmetic operations
                ari_operator = m.group(m.lastindex)
                logger.debug('arithmetical operator {} caught'\
                    .format(ari_operator))
                if '-' in ari_operator and 'eq' in l_operation:
                    arith_operation = 'negative'
                else:
                    pre_process_stmt.append(ari_operator)

        if lor_open or land_open:
            l_operation = ''
            if type(pre_process_stmt[-1]) is str:
                if ',' in pre_process_stmt[-1]:
                    pre_process_stmt = pre_process_stmt[:-1] + [')']
            else:
                pre_process_stmt.append(')')

        logger.debug('Prepocessing statement: {}'.format(pre_process_stmt))
        if definition_inline:
            if len(variables_in_stmt) > 0:
                sym_values = variables_in_stmt
                solver_status = 0
            else:
                sym_values = [this_constant]
                solver_status = 4

            stmt_to_process = 's.add('
            for ps in pre_process_stmt:
                if type(ps) is list:
                    for sub_stmt in ps:
                        stmt_to_process = stmt_to_process + str(sub_stmt)
                else:
                    stmt_to_process = stmt_to_process + str(ps)

            stmt_to_process = stmt_to_process.replace(',,', ',')
            if stmt_to_process[-1] == ',':
                stmt_to_process = stmt_to_process[:-1]
            open_braces = stmt_to_process.count('(')
            close_braces = stmt_to_process.count(')')
            stmt_to_process += ')' * (open_braces - close_braces)

            logger.debug('SMT statement (in definition): {}'\
                .format(stmt_to_process))
            exec(stmt_to_process)
            sat_result = s.check()
            self.checked = True
            if repr(sat_result) == 'sat':
                self.valid = True
                logger.info('Satisfied')
                model_values = s.model()
                logger.info('Solver result: {}'.format(model_values))
                for mv in model_values.decls():
                    try:
                        value = model_values[mv].__bool__()
                    except Exception as error:
                        value = model_values[mv].as_long()

                    s_ix = ascii_set.index(str(mv.name()))
                    sym_values.append((var_list[s_ix], value))

                if len(sym_values) > 1:
                    # multiple variables in definition predicate
                    sym_values = list()
                    solver_status = 5
                    for mv in model_values.decls():
                        try:
                            value = model_values[mv].__bool__()
                        except Exception as error:
                            value = model_values[mv].as_long()

                        s_ix = ascii_set.index(str(mv.name()))
                        if s_ix > 0:
                            sym_values.append((var_list[s_ix], value))
            else:
                logger.info('Unsatisfied')
                self.valid = False
                sym_values = list()
                solver_status = 5

            self.status = solver_status
            self.results = sym_values

            return solver_status, sym_values

        if self.SMT_solver:
            stmt_to_process = 's.add('
            if not definition_inline and type(self.definition_value) is bool:
                stmt_to_process += str(self.definition_value) + '==('
            for ps in pre_process_stmt:
                if type(ps) is list:
                    for sub_stmt in ps:
                        stmt_to_process = stmt_to_process + str(sub_stmt)
                else:
                    stmt_to_process = stmt_to_process + str(ps)

            stmt_to_process = stmt_to_process.replace(',,', ',')
            if stmt_to_process[-1] == ',':
                stmt_to_process = stmt_to_process[:-1]
            open_braces = stmt_to_process.count('(')
            close_braces = stmt_to_process.count(')')
            stmt_to_process += ')' * (open_braces - close_braces)

            logger.debug('[SMT]   statement: {}'.format(stmt_to_process))
            self.symbolic_statement = stmt_to_process
            exec(stmt_to_process)

            sym_values = list()
            s.check()
            model_values = s.model()
            logger.info('[SMT]   Solver result: {}'.format(model_values))
            for mv in model_values.decls():
                try:
                    value = model_values[mv].__bool__()
                except Exception as error:
                    value = model_values[mv].as_long()

                s_ix = ascii_set.index(str(mv.name()))
                sym_values.append((var_list[s_ix], value))

            self.status = solver_status
            self.results = sym_values

            return solver_status, sym_values
