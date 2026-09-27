#!/usr/local/bin/python3

# plc_abstractions.py
# Date: June 2020

__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'

import config
import os
import re
import sys
import xml.etree.ElementTree as ET
from DBconn import Varnode, Msgnode, Block, Constnode, Controller, Program, \
        Routine, create_weak_link, create_strong_link, merge_graph_node, \
        merge_nodes_from_list, connect_sensors, connect_actuators, \
        clean_network_connections
from plc_graph_builder import CFG_Builder


def extract_model(routine, code_explorer):
    routine_name = routine.attrib['Name']
    routine_model = Routine(
            name=routine_name, 
            routine=routine, 
            code_explorer=code_explorer,
            language=routine.attrib['Type'])
    config.logger.info('Extract_model from {} ({})'.format(
        routine_name, routine.attrib['Type']))
    config.logger.debug('Routine to model: {}, Type: {}'.format(
        routine[0].tag, routine.attrib['Type']))
    if routine[0].tag == routine.attrib['Type'] + 'Content':
        config.logger.debug('Checking Routine content')
        routine_model.model()

def printProgressBar(iteration, total, prefix='', suffix='', decimals=1, \
    length=50, fill='█'):
    """This function shows the progress of the analysis"""
    percent = ("{0:." + str(decimals) + "f}")\
        .format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s %s%%' % (prefix, percent), end='')
    # Print New Line on Complete
    if iteration == total:
        print(' Done')


class PLCcode():
    """This class contains the methods to process PLC code in XML format"""
    root_tree = None
    routines = dict()
    GT = 1
    NODE_TEMPLATE = {
        'type': 'Variable',
        'entity': None
    }
    instruction_definitions = dict()

    def update_routines(self, routines_in_xml):
        for elm in routines_in_xml:
            self.routines[elm.attrib['Name']] = {'name': elm.attrib['Name'],
                                                 'language': elm.attrib['Type'],
                                                 'routine': elm}

    def get_routine_by_name(self, routine_name):
        routine = None
        if routine_name in self.routines:
            routine = self.routines[routine_name]
        return routine

    def extract_msg_tags(self):
        """ 
        ++++++++++++ MESSAGE Tag +++++++++++++++++++
        <Tag Name="P5_MV503_MSG" 
            Taconfig.GType="Base" 
            DataType="MESSAGE" 
            ExternalAccess="Read/Write">
        <Data Format="Message">
        <MessageParameters 
            MessageType="CIP Data Table Read" 
            RemoteElement="HMI_MV503" 
            RequestedLenconfig.GTh="1" 
            ConnectedFlag="1" 
            ConnectionPath="P5_CONTROLLER" 
            CommTypeCode="0" 
            LocalIndex="0" 
            LocalElement="HMI_MV503" 
            CacheConnections="TRUE"/>
        </Data>
        </Tag>
        """
        root_tree = self.root_tree
        msg_tags = {}
        for tag in root_tree.findall('.//Tag'):
            # process MESSAGE tags
            if tag.attrib['DataType'] == 'MESSAGE':
                if 'CIP Data Table' in tag[0][0].attrib['MessageType']:
                    if 'Read' in tag[0][0].attrib['MessageType']:
                        msg_action = 'read_from'
                    else:
                        msg_action = 'write_to'
                    msg_name = "'" + tag.attrib['Name'] + "'"
                    remote_variable = tag[0][0].attrib['RemoteElement']
                    remote_path = tag[0][0].attrib['ConnectionPath']
                    local_variable = tag[0][0].attrib['LocalElement']

                    config.logger.info(
                        "Message tag Found: {} \n [{}]: {} --->> {}"
                        .format(msg_name, remote_path, remote_variable, \
                            local_variable))

                    msg_tags[msg_name] = {
                        'remote_variable': remote_variable,
                        'remote_entity': remote_path,
                        'local_variable': local_variable,
                        'msg_action': msg_action
                    }
            self.message_tags = msg_tags

    def get_message_tags(self):
        return self.message_tags

    def extract_FBD_definitions(self):
        root_tree = self.root_tree
        msg_tags = {}
        local_entity = config.local_entity
        for tag in root_tree.findall('.//Tag'):
            if tag.attrib['DataType'] in FBD_tags:
                this_FBD = tag.attrib['Name']
                config.logger.info("FBD tag Found: {} ({})"
                    .format(tag.attrib['Name'], tag.attrib['DataType']))

                # Create block for FBD definition
                local_entity = config.local_entity
                cfg_agent = CFG_Builder(entity=local_entity)
                cfg_agent.new_block(line_id=config.GT)
                this_block = cfg_agent.prev_block 
                config.rewrite_code.info(
                    ' [+] Basic block: {}, starts on {}'
                    .format(this_block, config.GT))
                config.logger.debug(
                        "    [!] [FBD_defs] Pushing into DB: {} - Parameters: \
                        {}, {}, {}"
                        .format(
                            this_block, this_block.firstLine, \
                            this_block.lastLine, this_block.entity))

                # write a new line for each DataValueMember definition
                for DVMember in tag[1][0]:
                    # increases a unit of time per DataValueMember definition
                    config.GT += 1     
                    defined_variable = DVMember.attrib['Name']
                    used_value = DVMember.attrib['Value']
                    config.logger.debug(' FBD Definition:  {}.{} := {}'.format(
                        this_FBD, defined_variable, used_value))
                    config.rewrite_code.info(
                        "     [+] {}: {}.{} := {}"
                        .format(config.GT, this_FBD, defined_variable, \
                            used_value))
                # close block node and delete reference from chain of nodes
                prev_block = tblock
                prev_block.lastLine = config.GT - 1
                # config.cBlk = tblock

    def extract_instruction_definitions(self):
        """
        ++++++++++++ Instruction Definition +++++++++++++++++++
        <AddOnInstructionDefinition 
            Name="AIN_FBD" 
            Revision="1.0" 
            ExecutePrescan="false" 
            ExecutePostscan="false" 
            ExecuteEnableInFalse="false" 
            CreatedDate="2014-04-09T07:08:15.740Z" 
            CreatedBy="Water-PC\Water" 
            EditedDate="2015-02-27T07:40:19.254Z" 
            EditedBy="Water-PC\Water" 
            SoftwareRevision="v20.01">
        """

        root_tree = self.root_tree
        inst_def = dict()
        for instDef in root_tree.findall('.//AddOnInstructionDefinition'):
            config.logger.info(instDef.attrib['Name'])
            inst_def[instDef.attrib['Name']] = {
                'parameters': {},
                'local_tags': [],
                'routines': {}
            }
            # Stores parameters (variables which interact with other components)
            for p in instDef[0]:
                config.logger.info("Parameter: {}; Usage: {}".format(
                    p.attrib['Name'], p.attrib['Usage']))
                inst_def[instDef.attrib['Name']]['parameters'] = {
                    'name': p.attrib['Name'],
                    'usage': p.attrib['Usage']
                }
            # Stores local tags (internal variables)
            for lt in instDef[1]:
                config.logger.info("LocalTag: {}".format(lt.attrib['Name']))
                inst_def[instDef.attrib['Name']]['local_tags']\
                    .append(lt.attrib['Name'])
            # Store routines
            for rt in instDef[2]:
                config.logger.info("Routine: {}".format(rt.attrib['Name']))
                inst_def[instDef.attrib['Name']]['routines'] = {
                    'name': rt.attrib['Name'],
                    'language': rt.attrib['Type'],
                    'routine': rt
                }

        self.instruction_definitions = inst_def

    def load_xml_file(self, xml_file):
        """ Load xml file with PLC program """
        if os.path.isfile(xml_file):
            parsed_file = ET.ElementTree(file=xml_file)
            config.logger.info('File {} parsed'.format(xml_file))
        else:
            config.logger.error('File {} unknown'.format(xml_file))
            return -1

        root_tree = parsed_file.getroot()
        local_entity = root_tree[0].tag + '_' + root_tree[0].attrib['Name']

        t_type = 'Program'
        t_name = 'MainProgram'
        '''Search main routine in PLC code'''
        for element in root_tree.findall('.//' + t_type):
            if element.attrib['Name'] == t_name:
                main_routine = element.attrib['MainRoutineName']
                config.logger.info(
                    "We found a main Routine: {} - {}"
                    .format(main_routine, element.tag))
                prg_routines = element[1]
                self.main_routine = main_routine

        self.update_routines(prg_routines)
        self.root_tree = root_tree
        self.local_entity = local_entity
        config.local_entity = local_entity
        self.NODE_TEMPLATE = {
            'type': 'Variable',
            'entity': local_entity
        }
        self.extract_msg_tags()

    def rename_variable(self, catched_var, name_reference):
        """
        Check if variable requires to be renamed, i.e. in 
        the case of FBD where multiple objects use the same 
        routine but they are not related
        """
        if not name_reference:
            return catched_var

        config.logger.debug("    [*][*] Processing {} catched var"
            .format(catched_var))
        if catched_var in name_reference:
            config.logger.debug(
                "    [*][*][*] Found {} in {}"
                .format(catched_var, name_reference))
            return name_reference[catched_var]

        elif '.' in catched_var:
            var2check = catched_var.split('.')[0]
            if var2check in name_reference:
                config.logger.debug(
                    "    [*][*][*][*] Found {} from {} in {}"
                    .format(var2check, catched_var, name_reference))
                dot_pos = catched_var.find('.')
                return name_reference[var2check] + catched_var[dot_pos:]

            else:
                config.logger.debug(
                    "    [*][*][*][*] Could not find {} in {}"
                    .format(catched_var, name_reference))
                return str(name_reference['default'] + '.' + catched_var)

        else:
            config.logger.debug(
                "    [*][*][*] Could not find {} in {}"
                .format(catched_var, name_reference))
            return str(name_reference['default'] + '.' + catched_var)

class Routine():
    name = ''
    routine = ''
    language = ''
    code_explorer = ''

    def __init__(self, name='', routine='', code_explorer='', language=''):
        self.name = name
        # language = routine.attrib['Type']
        self.language = language
        self.code_explorer = code_explorer
        if language == 'FBD':
            self.routine = routine[0][0]
        else:
            self.routine = routine[0]

    def model(self):
        """ 
        This function model the target routine
        """
        language = self.language
        code_explorer = self.code_explorer
        routine = self.routine
        name = self.name
        if language == 'RLL':
            config.logger.debug('Routine Type: Ladder Logic')
            self.model_ladderLogic()
        elif language == 'ST':
            config.logger.debug('Routine Type: Structured Text')
            self.model_structuredText()
        elif language == 'FBD':
            config.logger.debug('Routine Type: Function Block Diagram')
            self.model_FBD()

    
    def model_structuredText(self):
        """ 
        This method model structured text routines.
        
        Structured Text Routine example:
            <Routine Name="Main_Seq" Type="ST">
            <STContent>
            <Line Number="0">
            <![CDATA[(*IF HMI_PLANT.STOP THEN]]>
            </Line>
            <Line Number="1">
            <![CDATA[	HMI_P4_STATE:=1;]]>
            </Line>
            <Line Number="2">
            <![CDATA[END_IF;]]>
            </Line>
            <Line Number="3">
            <![CDATA[*)]]>
            </Line>
            <Line Number="4">
            <![CDATA[]]>
            </Line>
            <Line Number="5">
            <![CDATA[(*]]>
            </Line>
            <Line Number="6">
            <![CDATA[if S:FS then]]>
            </Line>
            <Line Number="7">
            <![CDATA[	HMI_P4_STATE := 1;]]>
        """

        r = self.routine
        r_name = self.name

        config.logger.debug('Modelling Structured text routine')
        functions = []
        parameters = []
        config.logger.info('Analysing {} lines'.format(len(r)))
        status_label = '   [*][*] Processing {}: ST ({} lines)'\
            .format(r_name, len(r))
        i = 0
        lines_c = len(r)
        # it evaluates every line by separate
        state = ''
        program = {}            # it stores all valid program lines
        for line in r:
            i += 1
            # assign line text to 'expression' variable for xml format and 
            # st format
            try:
                expression = line.text[1:-1]
            except:
                expression = line[:-1]

            config.logger.debug(' Line[{}/{}]: {}'\
                .format(i, lines_c, expression))
            # evaluates each function in every line
            pending_expression = ''
            while len(expression) > 0:
                if state == 'comment':
                    if expression.find('*)') != -1:
                        # Check for comment end symbol
                        state = 'end comment'
                        loc = expression.find('*)')
                        pending_expression = expression[loc + 2:]
                        config.logger.debug('Comment ends at {}/{}'\
                            .format(loc, len(expression)))
                        config.logger.debug('Evaluating(1) {}, ACTION: {}, \
                            Pending:  {}'\
                            .format(expression, state, pending_expression))
                        
                        if loc != len(expression) - 3:
                            # There is a statement to evaluates after the 
                            # comment closes
                            expression = expression[loc + 2:]
                            pending_expression = ''
                            state = 'to check'
                        else:
                            # The comment closes at the end of the line
                            expression = pending_expression
                            pending_expression = ''
                    else:  
                        # The comment does not close in this line, 
                        # so we should ignore the statement
                        config.logger.debug('Evaluating(2) {}, ACTION: {}, \
                            Pending:  {}'\
                            .format(expression, state, pending_expression))
                        expression = pending_expression
                        pending_expression = ''
                        continue
                elif expression.find('(*') != -1:
                    # It checks if a comment begins in this line, it checks 
                    # only if there was not part of a comment before
                    state = 'comment'
                    loc = expression.find('(*')
                    pending_expression = expression[loc + 2:]
                    config.logger.debug('Comment starts at {}/{}'\
                        .format(loc, len(expression)))
                    config.logger.debug('Evaluating(3) {}, ACTION: {}, \
                        Pending:  {}'\
                        .format(expression, state, pending_expression))
                    if loc != 0:
                        # there is an statement to evaluate before the comment 
                        # begins
                        pending_expression = expression[loc:]
                        expression = expression[:loc]
                        state = 'to check'
                    else:
                        # comment starts at the beginning of the line
                        expression = pending_expression
                        pending_expression = ''
                else:  
                    # It process lines or line sections that are not inside 
                    # a comment
                    if i in program:
                        program[i] = program[i] + expression
                    else:
                        program[i] = expression

                    config.logger.debug('Evaluating(4) {}, ACTION: {}, \
                        Pending:  {}'\
                        .format(expression, state, pending_expression))
                    state = 'to check'
                    expression = pending_expression
                    pending_expression = ''

        ST_code = ST_program(program=program, status_label=status_label)
        ST_code.run_lexical_analysis()


    def model_FBD(self):
        """
        FBD Routine example:
        <Routine Name="Dosing" Type="FBD">
        <FBDContent SheetSize="A0 - 841 x 1189 mm" 
            SheetOrientation="Landscape">
        <Sheet Number="1">
        <IRef ID="0" X="1120" Y="180" Operand="3" HideDesc="false"/>
        <IRef ID="1" X="1120" Y="200" Operand="3" HideDesc="false"/>
        <ORef ID="24" X="1550" Y="80" Operand="DO_P_403_START" 
            HideDesc="false"/>
        <ORef ID="25" X="1550" Y="520" Operand="DO_P_404_START" 
            HideDesc="false"/>
        <AddOnInstruction Name="Duty2_FBD" ID="42" X="360" Y="60" 
            Operand="P_NAHSO3_ORP_DUTY_FB" 
            VisiblePins="AutoInp Selection Start_Pmp1 Start_Pmp2 PMP1 PMP2 HMI">
        <InOutParameter Name="HMI" Argument="HMI_P_NAHSO3_ORP_DUTY"/>
        <InOutParameter Name="PMP1" Argument="HMI_P403"/>
        <InOutParameter Name="PMP2" Argument="HMI_P404"/>
        </AddOnInstruction>
        <Wire FromID="0" ToID="43" ToParam="Start_TM"/>
        <Wire FromID="1" ToID="43" ToParam="Stop_TM"/>
        <Wire FromID="42" FromParam="Start_Pmp1" ToID="40"/>
        <Wire FromID="42" FromParam="Start_Pmp2" ToID="41"/>
        """
        # Stores instruction definitons
        r = self.routine
        r_name = self.name
        code_explorer = self.code_explorer
        inst_def =code_explorer.instruction_definitions
        local_entity = config.local_entity
        cfg_agent = CFG_Builder(entity=local_entity)
        config.logger.info('Modelling FBD routine')
        print('   [*][*] Processing {}: FBD ({} lines)'\
            .format(r_name, len(r)))
        status_label = '   [*][*] Processing {}: FBD ({} lines)'\
            .format(r_name, len(r))
        ref = {}
        lines_in_code = len(r)
        cfg_agent.new_block(line_id=config.GT)

        # Control variable to create a Basic Block for wire definitions
        CREATE_WIRE_BLOCK = True

        for i, ln in enumerate(r, 1):
            printProgressBar(i, len(r), prefix=status_label)
            config.logger.info(
                'FBD Line[{}/{}]: {} -->> {}'\
                .format(i, lines_in_code, ln.tag, ln.attrib))
            config.rename_vars = False
            config.renamed_vars = {}
            if 'Ref' in ln.tag:
                ref[ln.attrib['ID']] = ln.attrib['Operand']
            if 'AddOnInstruction' in ln.tag:
                config.rename_vars = True
                ref[ln.attrib['ID']] = ln.attrib['Operand']
                routine = inst_def[ln.attrib['Name']]['routines']['routine']
                config.renamed_vars = {'default': ln.attrib['Operand']}
                for iop in ln:
                    if 'InOutParameter' in iop.tag:
                        config.renamed_vars[iop.attrib['Name']] = \
                            iop.attrib['Argument']
                config.logger.debug(
                    "Calling routine renaming the following variables: {}"\
                    .format(config.renamed_vars))
                extract_model(routine, code_explorer)
            if 'Wire' in ln.tag:
                """
                Wire function example:
                <Wire FromID="1" ToID="43" ToParam="Stop_TM"/>
                <Wire FromID="42" FromParam="Start_Pmp1" ToID="40"/>
                Define a Constant node type
                """

                if CREATE_WIRE_BLOCK:
                    cfg_agent = CFG_Builder(entity=local_entity)
                    cfg_agent.new_block(line_id=config.GT)
                    CREATE_WIRE_BLOCK = False

                if 'FromParam' in ln.attrib:
                    parent_node = ref[ln.attrib['FromID']] + '.' \
                        + ln.attrib['FromParam']
                    pnode = merge_graph_node(
                        name=ref[ln.attrib['FromID']] + '.' \
                            + ln.attrib['FromParam'], 
                        entity=local_entity, node_type='var')
                    if ref[ln.attrib['ToID']].isdigit():
                        constant_params = {
                            'type': "Constant",
                            'entity': local_entity
                        }
                        Knode = Constnode.get_or_create(
                            {'name': '{}'\
                            .format(ln.attrib['ToID']), \
                                'entity': local_entity})[0]
                        create_strong_link([pnode], [Knode])
                        # Log into new source code
                        config.rewrite_code.info(
                            "     [+] {}: {}"\
                            .format(config.GT, cnode.name + ' := ' \
                                + Knode.name))
                    else:
                        child_node = ref[ln.attrib['ToID']]
                        cnode = merge_graph_node(
                            name=ref[ln.attrib['ToID']], entity=local_entity, 
                            node_type='var')
                        create_strong_link([pnode], [cnode])

                        # Log into new source code
                        config.rewrite_code.info(
                            "     [+] {}: {}"\
                            .format(config.GT, cnode.name + ' := ' \
                                + pnode.name))

                if 'ToParam' in ln.attrib:
                    child_node = ref[ln.attrib['ToID']] + '.' \
                        + ln.attrib['ToParam']
                    cnode = merge_graph_node(
                        name=ref[ln.attrib['ToID']] + '.' \
                            + ln.attrib['ToParam'], 
                        entity=local_entity, node_type='var')
                    if ref[ln.attrib['FromID']].isdigit():
                        constant_params = {
                            'type': "Constant",
                            'entity': local_entity
                        }
                        Knode = Constnode.get_or_create(
                            {'name': '{}'\
                            .format(ln.attrib['FromID']), \
                                'entity': local_entity})[0]
                        create_strong_link([Knode], [cnode])

                        # Log into new source code
                        config.rewrite_code.info(
                            "     [+] {}: {}"\
                            .format(config.GT, cnode.name + ' := ' + \
                                Knode.name))

                    else:
                        parent_node = ref[ln.attrib['FromID']]
                        pnode = merge_graph_node(
                            name=ref[ln.attrib['FromID']], 
                            entity=local_entity, node_type='var')
                        create_strong_link([pnode], [cnode])
                        # Log into new source code
                        config.rewrite_code.info(
                            "     [+] {}: {}"\
                            .format(config.GT, cnode.name + ' := ' \
                                + pnode.name))
                config.GT += 1

        cfg_agent.prev_block.lastLine = config.GT
        cfg_agent.prev_block.save()
        

    def model_ladderLogic(self):
        """
        +++++++++++++++++ LADDER LOGIC SAMPLE +++++++++++++++++
        <Routine Name="MainRoutine" Type="RLL">
        <RLLContent>                                # Routine[0]
        <Rung Number="0" Type="N">
        <Text>                                      # Routine[0].text
        <![CDATA[NOP();]]>
        </Text>
        </Rung>
        <Rung Number="1" Type="N">
        <Text>
        <![CDATA[JSR(IO,0);]]>
        </Text>
        </Rung>
        <Rung Number="2" Type="N">
        <Text>
        <![CDATA[JSR(Pre_Condition,0);]]>
        </Text>
        ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        """
        r = self.routine
        r_name = self.name
        code_explorer = self.code_explorer
        msg_tags = code_explorer.get_message_tags()
        local_entity = config.local_entity
        config.logger.info('****** Modelling Ladder logic routine ******')
        config.rewrite_code\
            .info('****** Modelling Ladder logic routine ******')
        print('   [*][*] Processing {}: LL ({} lines)'\
            .format(r_name, len(r)), end='\r')
        functions = []  # It stores unknown functions to be added in the future
        parameters = []
        conditional_vars = []  # It stores all conditional variables in a rung
        # It stores the variables where actions take place, always at the 
        # end of the rung
        action_vars = []        
        KNOWN_FUNCTIONS = ['MSG', 'JSR', 'XIO']

        config.logger.info('Analysing {} rungs'.format(len(r)))
        i = 0
        rungs_c = len(r)
        # it evaluates every line by separate
        for rung in r:
            i += 1
            # increases a unit of time per rung in ladder logic
            config.GT += 1
            config.logger.debug(' Rung[{}/{}]: {}'\
            .format(i, rungs_c, rung[0].text[1:-1]))
            # evaluates each function in every line
            for fnc in rung[0].text[1:-1].split(')'):
                config.logger.debug("Parsing: {} .... last character: {}"\
                    .format(fnc, fnc[-1]))
                if fnc[-1:] == ';':
                    # If there is more than one variable in the rung
                    if conditional_vars:
                        for av in action_vars:
                            av_node = Varnode.nodes\
                                .filter(Q(name__contains=av), 
                                        entity=local_entity)
                            for cv in conditional_vars:
                                cv_node = Varnode.nodes.filter(
                                    Q(name__contains=cv), 
                                    entity=local_entity)
                                create_weak_link(cv_node, av_node)
                        conditional_vars = []
                    # break if it reaches the end of the line
                    break               
                prm = 'empty'
                if fnc[-1:] == '(':
                    fn = fnc[:-1]
                else:
                    fn, prm = fnc.split('(')
                config.logger.debug("Function: {}    Parameters: {}"\
                    .format(fn, prm))
                if fn not in KNOWN_FUNCTIONS:
                    functions.append(fn)
                if fn == 'JSR':
                    routine_name = prm.split(',')[0]
                    if True:  # routine_name == 'Main_Seq':
                        config.logger.info("Extracting model from {} routine"\
                            .format(routine_name))
                        print("[+] Extracting model from {} routine"\
                            .format(routine_name))
                        try:
                            if not 'Logix_Status' in routine_name:
                                extract_model(
                                    code_explorer
                                        .routines[routine_name]['routine'], 
                                    code_explorer)
                        except Exception as e:
                            config.logger\
                                .error("++++++ Error: ++++++ Extracting model \
                                    of routine {} in  {} ---->>>> {}. \n\
                                    Trace: {}"\
                                    .format(routine_name, 
                                        code_explorer.routines.keys(), 
                                        e, sys.exc_info()))
                            exit()
                elif fn == 'MSG':
                    config.logger.info("Message Found: {}".format(prm))
                    prm = "'" + prm + "'"
                    msg_params = {
                        'type': "Message",
                        'entity': "Network"
                    }
                    remote_params = {
                        'type': "Variable",
                        'entity': "Controller_" + msg_tags[prm]['remote_entity']\
                            .split('_')[0]
                    }
                    rvar_params = {
                        'type': "Variable",
                        'entity': "Controller_" + msg_tags[prm]['remote_entity']\
                            .split('_')[0]
                    }

                    # Create nodes for reading type messages
                    '''MATCH (a) WHERE a.name STARTS WITH "'HMI_MV504." 
                    RETURN a LIMIT 100'''
                    rel_query = "MATCH (n) WHERE n.name CONTAINS {} AND n.entity \
                        CONTAINS '{}' RETURN n.name"\
                        .format("'" + msg_tags[prm]['local_variable'][1:-1] \
                            + ".'", local_entity)
                    local_vars = []
                    rel_query = "MATCH (n) WHERE n.name CONTAINS {} AND n.entity \
                        CONTAINS '{}' RETURN n.name"\
                        .format("'" + msg_tags[prm]['local_variable'][1:-1] \
                            + ".'", msg_tags[prm]['remote_entity']\
                                .split('_')[0])
                    remote_vars = []

                    # Create nodes for messaging
                    msg_node = Msgnode.get_or_create({'name': prm})[0]
                    local_node = merge_graph_node(
                        name=msg_tags[prm]['local_variable'], 
                        entity=local_entity,
                        node_type='var')
                    remote_node = merge_graph_node(
                        name=msg_tags[prm]['remote_variable'],
                        entity="Controller_" + msg_tags[prm]['remote_entity']\
                            .split('_')[0], node_type='var')
                    rel = msg_tags[prm]['msg_action']

                    if 'read_from' in rel:
                        # creates connection 'Message' -->> 'Local Variable'
                        msg_node.read_from.connect(local_node)

                        # creates connection 'Remote Variable' -->> 'Message'
                        remote_node.read_from.connect(msg_node)

                    # Create nodes for writing type messages
                    else:
                        # creates connection 'Local Variable' -->> 'Message'
                        local_node.write_to.connect(msg_node)

                        # creates connection 'Message' -->> 'Remote Variable'
                        msg_node.write_to.connect(remote_node)

                elif fn == 'XIO':
                    conditional_vars.append(prm)
                elif fn == 'NOP':
                    pass
                else:
                    print("    [!]Function {} pending to process"\
                        .format(fn))
                    functions.append(fn)

        # Print unknown functions
        print("   [*][*][*] Results: Unknown functions[{}]: {}"\
            .format(len(functions), functions))

class ST_program():
    program = ''
    label = ''

    def __init__(self, program='', status_label=''):
        self.program = program
        self.label = status_label

    def run_lexical_analysis(self):
        """
        This function performs lexical analysis in a structured text program.
        """
        p = self.program
        st_text = self.label

        local_entity = config.local_entity
        var_list = []                   # List variables used in the Program
        # store active conditional variables, being '0' the root and the 
        # biggest number the current conditional set
        conditional_clause = {}
        cond_nodes_dict = {}
        fnc = ''
        i = 0

        config.logger.debug("Call lexer with new variables: {}"\
            .format(config.renamed_vars))
        config.logger.debug(" Running lexer in Program with {} lines"\
            .format(len(p)))

        config.rewrite_code.info(' [*]  Lexer on a new program')

        # create a new block node object
        block_chain = []
        # Dict that store all block nodes that are pending to close and 
        # assign next block
        open_blocks = {}            
        code_agent = PLCcode()
        cfg_agent = CFG_Builder(entity=local_entity)
        cfg_agent.new_block(line_id=config.GT)
        config.logger.debug(
            "    [!] Reference block: {}". format(cfg_agent.this_block))

        ptr = re.compile(config.LEXER_REGX, re.VERBOSE)

        for l in p:
            config.GT += 1  # increases time every line
            i += 1
            printProgressBar(i, len(p), prefix=st_text)
            # Log variables in the current line
            vars_in_line = []               
            current_nodes = []
            statement = p[l]
            config.logger.debug(" [+] Running lexer in line {}: {}"\
                .format(l, statement))
            scan = ptr.scanner(statement)
            this_constant = 'K'
            definition_inline = False
            rw_code_line = statement        # it stores the line after renaming variables
            new_statement = ''
            statement_caught = ''
            while True:
                m = scan.search()
                new_statement += statement_caught
                if not m:
                    new_statement = new_statement.replace("\\t", " ")
                    rw_code_line = new_statement.replace("'", "")
                    config.rewrite_code.info("     [+] {}: {}"\
                        .format(config.GT, rw_code_line))
                    break
                # Record in log file output of lexer
                statement_caught = repr(m.group(m.lastindex))
                config.logger.debug(
                    "    [*] Lexer output: [{}]: {}"\
                        .format(m.lastindex, repr(m.group(m.lastindex))))
                if m.lastindex == 1:                
                    # Detect a condition end i.e. 'END_IF' or 'END_CASE'
                    # Delete actual conditional clause
                    del conditional_clause[len(conditional_clause) - 1]
                    del cond_nodes_dict[len(cond_nodes_dict) - 1]
                    cfg_agent.new_block(line_id=config.GT)
                    cfg_agent.close_layer()

                
                elif m.lastindex == 2:
                    # Detect 'ELSE' clause
                    if 'ELSE' in repr(m.group(m.lastindex)):
                        # Increase Basic block node_counter
                        config.rewrite_code.info(
                            ' [+] Basic block: {}, starts on {}'\
                            .format(cfg_agent.prev_block, config.GT))
                        root_block = cfg_agent.get_root_block_in_layer()
                        cfg_agent.delete_root_block_in_layer()
                        cfg_agent.prev_block = root_block
                        cfg_agent.new_block(line_id=config.GT)
                        cfg_agent.add_current_block_to_layer()

                    if 'ELSIF' in repr(m.group(m.lastindex)):
                        # Remove initial if conditional clauses
                        del conditional_clause[len(conditional_clause) - 1]
                        del cond_nodes_dict[len(cond_nodes_dict) - 1]

                    elif 'IF' in repr(m.group(m.lastindex)):
                        # With each IF we should store the reference for later 
                        # connections with blocks
                        cfg_agent.new_layer()

                elif m.lastindex == 3:                
                    # Detect a close of a conditional clause i.e. 'THEN'
                    actual_vars = set(vars_in_line)
                    # create a node with an indirect edge to its conditional 
                    # variables
                    # Store conditional clause and clear 'vars_in_line'

                    # After checking DFG we found an issue in the 'weak_link' 
                    # between 'HMI_P1_STATE' and 'HMI_PLANT.START' in 
                    # 'Controller_P1', this link creates a lot of false 
                    # connections. We comment out the following section to fix 
                    # the issue
                    if len(conditional_clause) > 0:
                        conditional_clause[len(conditional_clause)] \
                            = conditional_clause[len(conditional_clause) - 1] \
                                + list(set(vars_in_line))

                        cond_nodes_dict[len(cond_nodes_dict)] \
                            = cond_nodes_dict[len(cond_nodes_dict) - 1] \
                                + list(current_nodes)

                    else:
                        conditional_clause[len(conditional_clause)] \
                            = list(set(vars_in_line))
                        cond_nodes_dict[len(cond_nodes_dict)] \
                            = list(current_nodes)

                    vars_in_line = []
                    current_nodes = []
                    root_block = cfg_agent.get_root_block_in_layer()
                    cfg_agent.prev_block.lastLine = config.GT - 1
                    cfg_agent.prev_block.save()
                    if not 'OF' in repr(m.group(m.lastindex)):
                        cfg_agent.prev_block = root_block
                    cfg_agent.new_block(line_id=config.GT)
                    if 'OF' in repr(m.group(m.lastindex)):
                        cfg_agent.new_layer(empty=True)

                    cfg_agent.add_current_block_to_layer()

                elif m.lastindex == 5:                  
                    # Detect ')'
                    t_input_nodes = []
                    t_output_nodes = []
                    if fnc == 'timer':
                        t_var = vars_in_line[-1]
                        config.logger.debug("    [*][*] Adding timer {} \
                            function"\
                            .format(t_var))
                        t_input = [t_var + '.TimerEnable', \
                            t_var + '.PRE', t_var + '.Reset']
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output = [t_var + '.DN']
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')
                        fnc = ''
                    elif fnc == 'setd':
                        t_var = vars_in_line[-1]
                        config.logger.debug("    [*][*] Adding set dominant {} \
                            function".format(t_var))
                        t_input = [t_var + '.EnableIn', t_var + '.Set', \
                            t_var + '.Reset']
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output = [t_var + '.Out']
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')

                        fnc = ''
                    elif fnc == 'scale':
                        t_var = vars_in_line[-1]
                        config.logger.debug("    [*][*] Adding scale {} \
                            function".format(t_var))
                        t_input = [t_var + '.InRawMax', t_var + '.InRawMin', \
                                t_var + '.InEUMax', t_var + '.InEUMin', \
                                t_var + '.In']
                        t_output = [t_var + '.Out']
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')

                        fnc = ''
                    elif fnc == 'alarm':
                        t_var = vars_in_line[-1]
                        config.logger.debug("    [*][*] Adding alarm {} \
                            function".format(t_var))
                        t_input = [t_var + '.In', t_var + '.HHLimit']
                        t_output = [t_var + '.HHAlarm']
                        rel = 'weak_link'
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')

                        create_weak_link(t_input_nodes, t_output_nodes)

                        t_input = [t_var + '.In', t_var + '.HLimit']
                        t_output = [t_var + '.HAlarm']
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')

                        create_weak_link(t_input_nodes, t_output_nodes)

                        t_input = [t_var + '.In', t_var + '.LLimit']
                        t_output = [t_var + '.LAlarm']
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')

                        create_weak_link(t_input_nodes, t_output_nodes)

                        t_input = [t_var + '.In', t_var + '.LLLimit']
                        t_output = [t_var + '.LLAlarm']
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')

                        fnc = ''
                    elif fnc == 'osri':
                        t_var = vars_in_line[-1]
                        config.logger.debug("    [*][*] Adding OSRI {} \
                            function".format(t_var))
                        t_input = [t_var + '.InputBit']
                        t_output = [t_var + '.OutputBit']
                        t_input_nodes = merge_nodes_from_list(
                            t_input, entity=local_entity, node_type='var')
                        t_output_nodes = merge_nodes_from_list(
                            t_output, entity=local_entity, node_type='var')

                        fnc = ''
                    create_weak_link(t_input_nodes, t_output_nodes)
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
                        print("    [!]Function {} pending to process"\
                        .format(c_fnc))
                elif m.lastindex == 7:                
                    # Detect a new case object (new state)
                    root_block = cfg_agent.get_root_block_in_layer()
                    cfg_agent.prev_block = root_block
                    cfg_agent.new_block(line_id=config.GT)
                    cfg_agent.add_current_block_to_layer()

                elif m.lastindex == 8:                  
                    # Detect a definition
                    definition_inline = True
                    defined_vars = set(vars_in_line)
                    defined_nodes = current_nodes
                    config.logger.debug("    [*][*] [Definition] of {} \
                        variables".format(defined_vars))
                    # create a node with an indirect edge to its 
                    # conditional variables
                    if len(conditional_clause) > 0:
                        create_weak_link(cond_nodes_dict[len(cond_nodes_dict) \
                            - 1], defined_nodes)

                    vars_in_line = []               # clear vars in line
                    current_nodes = []
                elif m.lastindex == 10:                 
                    # Detect a constant value
                    this_constant = repr(m.group(m.lastindex))
                elif m.lastindex == 11:                 
                    # Detect a variable
                    catched_var = repr(m.group(m.lastindex)).replace("'", "")
                    new_var_name = code_agent.rename_variable(
                        catched_var, name_reference=config.renamed_vars)
                    # replace original variable name by new one to be written 
                    # in the clean code.
                    statement_caught = new_var_name

                    rw_code_line = rw_code_line.replace(catched_var, new_var_name)
                    var_list.append(new_var_name)
                    vars_in_line.append(new_var_name)
                    node1 = merge_graph_node(name=new_var_name, \
                        entity=local_entity, node_type='var')
                    current_nodes.append(node1)
                    config.logger.debug("    [*][*] [Variable in line]: {}"\
                        .format(vars_in_line))
                    config.logger.debug("    [*][*] [Variable in line]: {}"\
                        .format(vars_in_line))

            if definition_inline:
                config.logger.debug(
                    "    [*][*] Processing a definition: {} --->> {}"\
                    .format(vars_in_line, defined_vars))
                if vars_in_line:
                    actual_vars = set(vars_in_line)
                    create_strong_link(current_nodes, defined_nodes)

                    vars_in_line = []
                    current_nodes = []
                else:
                    constant_params = {
                        'type': "Constant",
                        'entity': local_entity
                    }
                    Knode = Constnode.get_or_create({
                        'name': this_constant,
                        'entity': local_entity
                    })[0]
                    create_strong_link([Knode], defined_nodes)

                definition_inline = False           # reset the indicator
            var_list_size = len(set(var_list))
            config.logger.debug(
                "    [*] Variable list[{}]: {}"\
                .format(len(set(var_list)), set(var_list)))
