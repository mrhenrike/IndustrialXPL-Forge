#!/usr/local/bin/python3

# config.py
# Date: June 2020

__version__ = '1.0.0'
__author__ = 'cpsSecResearcher'

import logging
#from DBconn import Block

# Logger configuration
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s:%(name)s:%(message)s')
file_handler = logging.FileHandler('PLCParser.log', mode='w')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Include a logger to rewrite the PLC code including new variabes (rename)
rewrite_code = logging.getLogger('Code')
rewrite_code.setLevel(logging.INFO)
rwc_file_handler = logging.FileHandler('NewCode.stir', mode='w')
rewrite_code.addHandler(rwc_file_handler)

# Global discrete time of the system
GT = 0
local_entity = ''

# Basic block counter for CFG on static analysis
basicBlock = 0

# CFG current block
# cBlk = Block()
# cBlk.name = ''


# Global variable to process ST code renaming variables in the case of FBD
rename_vars = False
renamed_vars = {}


# Configuration of regular expression for lexer
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
        # 10. number and constants
        |(\d+\#\w+|\d+|\s*TRUE|\s*FALSE)                                   
        # 11. variables
        |(\w+:?\w+:?\w+\.?\w+\.?\w*|\w+\.?\w*\.?\w*\.?\w*)
        # 12. whitespace
        |(\s+)                                    
        # 13. arithmetic operations
        |([\+\*\/\-])                            
        # 14. special character
        |(.+)
        """
