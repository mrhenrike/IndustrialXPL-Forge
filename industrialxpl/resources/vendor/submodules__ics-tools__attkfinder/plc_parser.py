#!/usr/local/bin/python3

# xml_parser.py
# Date: June 2020

__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'

import getopt
import os
import sys
import re
import xml.etree.ElementTree as ET
import config
from neomodel import Q
from DBconn import connect_sensors, connect_actuators, clean_network_connections
        
from plc_graph_builder import CFG_Builder
from plc_abstractions import PLCcode, extract_model, Routine

def main(argv):
    
    # Validate input arguments and check if xml file exists
    source_file = ''
    usage_text = 'Usage: xml_parser.py -i <inputfile> -f <xml/st>'
    try:
      opts, args = getopt.getopt(argv,"hi:f:",["help", "ifile=", "format="])
    except getopt.GetoptError:
        print(usage_text)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(usage_text)
            sys.exit()
        elif opt in ("-i", "--ifile"):
            source_file = arg
        elif opt in ('-f', '--format'):
            format_file = arg
        else:
            print(usage_text)
            sys.exit()
    

    if os.path.exists(source_file):
        config.logger.info('Processing {}'.format(source_file))
    else:
        print(f' !!! filename {source_file} unknown')
        print(usage_text)
        exit()

    if format_file == 'st':
        # Processing Structured Text program
        print('Processing independent ST program')
        # Create a list of files to process, if a dir is passed as argument
        # the list contains all files in the dir
        if os.path.isfile(source_file):
            files_to_parse = [source_file]
        elif os.path.isdir(source_file):
            files_to_parse = [source_file + '/' + f for f in os.listdir(source_file)]
        for stfile in files_to_parse:
            config.logger.info('Parsing {} file'.format(stfile))
            f = open(stfile, 'r')
            st_program = f.readlines()
            plc_routine = Routine(
                    name=stfile.split('.')[0],
                    routine=[st_program],
                    language='ST')
            plc_routine.model()
        # else:
        #     config.logger.error('File {} unknown'.format(source_file))
        #     return -1
    else:
        # Processing XML format
        print('Processing XML format')
        code_explorer = PLCcode()
        code_explorer.load_xml_file(source_file)

        # Extract all message tags
        code_explorer.get_message_tags()
        code_explorer.extract_instruction_definitions()

        # It checks for the main routine and start extracting the models
        main_routine = code_explorer.routines[code_explorer.main_routine]['routine']
        extract_model(main_routine, code_explorer)
        connect_sensors()
        connect_actuators()
        clean_network_connections()
        cfg_agent = CFG_Builder(entity=config.local_entity)


if __name__ == '__main__':
    main(sys.argv[1:])
